from __future__ import annotations
import json
import logging
import re
from dataclasses import dataclass, field
from urllib.parse import urljoin, urlparse, parse_qsl

from discovery.params import parse_fragment_params

log = logging.getLogger('SentinelX')

URL_RE = re.compile(r'''["'`]((?:https?://|/)[^"'`\s<>]+)["'`]''')
API_MARKERS = ('/api', '/graphql', '/swagger', '/openapi')


def looks_like_api(url: str) -> bool:
    return any(marker in url.lower() for marker in API_MARKERS)


def extract_api_endpoints(script: str, base_url: str) -> list[str]:
    """API-shaped absolute/relative endpoints that appear as literal quoted
    strings. Unchanged, deliberately conservative behavior: only URLs that
    contain an API marker and are written out in full as a single string
    literal. See analyze_script() for the endpoints this misses."""
    out = set()
    for raw in URL_RE.findall(script):
        if '${' in raw:
            # A template literal like `/api/v2/orders/${id}` is not a
            # concrete URL -- it's handled (with ${...} -> {}) by
            # analyze_script().template_endpoints, not emitted here as a
            # bogus literal containing '${id}'.
            continue
        u = urljoin(base_url, raw)
        if looks_like_api(u):
            out.add(u)
    return sorted(out)


# --- Beyond regex-over-literals ------------------------------------------
#
# extract_api_endpoints() only catches endpoints written as one complete
# quoted string. Real bundled/minified JS routinely builds URLs a way that
# leaves nothing for that regex to match:
#
#   base + '/users/' + id                 -> concatenation; only '/users/'
#                                            is a literal, and it isn't
#                                            API-marker-shaped on its own
#   `${API}/api/v1/orders/${orderId}`     -> template literal; the path only
#                                            exists once ${...} is stripped
#   //# sourceMappingURL=app.js.map       -> the real source (with readable
#                                            paths) lives in the .map file
#
# analyze_script() recovers all three statically: it strips ${...}
# interpolations to reconstruct template paths, harvests path-shaped string
# fragments (which is what concatenation leaves behind), and surfaces any
# sourceMappingURL so the caller can fetch and mine the map. It cannot
# evaluate arbitrary runtime expressions (no engine can, statically), so a
# value pulled purely from a non-literal variable is reported as the literal
# fragments that build it, which is what is actually recoverable.

# A path-shaped literal: begins with '/' (not '//', which is a protocol-
# relative URL/comment) or is an absolute http(s) URL. Captured from single,
# double, or back-tick quotes.
_PATH_LITERAL_RE = re.compile(r'''["'`]((?:https?://|/(?!/))[^"'`\s<>]*)["'`]''')
# Back-tick template literals, captured whole so ${...} can be normalized.
_TEMPLATE_RE = re.compile(r'`([^`\\]*(?:\\.[^`\\]*)*)`', re.DOTALL)
_INTERP_RE = re.compile(r'\$\{[^}]*\}')
# sourceMappingURL, from either the // or /* comment form.
_SOURCEMAP_RE = re.compile(r'sourceMappingURL\s*=\s*([^\s*"\'<>]+)')
# A bare path fragment inside a string, for the concatenation case:
# '/users/' in `base + '/users/' + id`. Two or more path-ish chars.
_FRAGMENT_RE = re.compile(r'''["'`](/[A-Za-z0-9._~\-/]{1,}?)["'`]''')


@dataclass
class ScriptAnalysis:
    base_url: str
    api_endpoints: list[str] = field(default_factory=list)       # api-shaped, any construction
    template_endpoints: list[str] = field(default_factory=list)  # from `...${x}...`, ${} -> {}
    path_candidates: list[str] = field(default_factory=list)     # non-api path literals/fragments
    source_map_url: str | None = None

    @property
    def all_api(self) -> list[str]:
        """Every api-shaped endpoint, literal or template-derived, absolute."""
        return sorted(set(self.api_endpoints) | {t for t in self.template_endpoints if looks_like_api(t)})


def _normalize_template(raw: str) -> str:
    """Turn a template-literal body into a stable path shape by replacing
    each ${...} interpolation with a {} placeholder."""
    return _INTERP_RE.sub('{}', raw)


def analyze_script(script: str, base_url: str) -> ScriptAnalysis:
    script = script or ''
    result = ScriptAnalysis(base_url=base_url)

    # 1. Literal API endpoints (same as extract_api_endpoints).
    result.api_endpoints = extract_api_endpoints(script, base_url)

    # 2. Template literals. Strip ${...}, then keep any body that still
    #    contains a path -- absolute, rooted, or api-shaped after stripping.
    templates = set()
    for raw in _TEMPLATE_RE.findall(script):
        if '${' not in raw:
            continue  # a plain back-tick string; already handled as a literal
        norm = _normalize_template(raw).strip()
        if not norm:
            continue
        if norm.startswith(('http://', 'https://', '/')) or looks_like_api(norm):
            # Resolve relative shapes against base_url; leave {}-leading ones
            # (e.g. "{}/api/users") as-is since the host is a runtime value.
            resolved = urljoin(base_url, norm) if norm.startswith('/') else norm
            templates.add(resolved)
    result.template_endpoints = sorted(templates)

    # 3. Path candidates: rooted/absolute path literals that are NOT
    #    api-shaped (the concatenation case leaves these behind, e.g.
    #    '/users/' from base + '/users/' + id). api-shaped literals already
    #    live in api_endpoints, so exclude them here to avoid duplication.
    candidates = set()
    for raw in _PATH_LITERAL_RE.findall(script):
        resolved = urljoin(base_url, raw)
        if not looks_like_api(resolved):
            candidates.add(resolved)
    for raw in _FRAGMENT_RE.findall(script):
        resolved = urljoin(base_url, raw)
        if not looks_like_api(resolved):
            candidates.add(resolved)
    result.path_candidates = sorted(candidates)

    # 4. Source map pointer (fetched/parsed by the caller if present).
    m = _SOURCEMAP_RE.search(script)
    if m:
        ref = m.group(1).strip()
        if not ref.startswith('data:'):  # inline data-URI maps are parsed separately
            result.source_map_url = urljoin(base_url, ref)

    return result


# --- JavaScript -> parameter-name integration ----------------------------
#
# The parameter prober is only as good as its candidate list. JavaScript is a
# rich source of real, application-specific parameter names the generic
# wordlist would never contain: names read from the query string
# (`searchParams.get('ref')`), names appended to request bodies
# (`fd.append('user_id', ...)`), and the query keys baked into URL literals.
# extract_param_names_from_js() harvests those so they can be fed straight
# into discovery.params -- turning "endpoints found in JS" into "parameter
# names to test on those endpoints". Heuristic and deliberately conservative.
_NAME = r'[A-Za-z0-9_.\-]{1,64}'
# `.get/getAll/has('x')` on a known params-ish accessor. The accessor set is
# the fixed conventional names plus any variable bound to URLSearchParams
# (resolved below), so `const p = new URLSearchParams(...); p.get('x')` works.
_FIXED_ACCESSORS = ('searchParams', 'params', 'query', 'qs', 'args')
_JS_GETPARAM_RE = re.compile(rf'get(?:Query|Url)?Param(?:eter)?\s*\(\s*[\'"]({_NAME})[\'"]', re.IGNORECASE)
_JS_APPEND_RE = re.compile(rf'\.(?:append|set)\s*\(\s*[\'"]({_NAME})[\'"]\s*,')
# Inline: new URLSearchParams(...).get('x')
_JS_INLINE_USP_RE = re.compile(
    rf'URLSearchParams\s*\([^)]*\)\s*\.\s*(?:get|getAll|has)\s*\(\s*[\'"]({_NAME})[\'"]')
# Variables bound to a URLSearchParams instance (or something's .searchParams).
_JS_USP_BIND_RE = re.compile(
    r'(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*(?:new\s+URLSearchParams|[^;\n]*\.searchParams)')

# A quoted hash/fragment literal: SPA hash-routes and hash query strings
# written directly into JS -- a router table entry ('#/search?q=admin'),
# a navigation call (navigate('#/profile?tab=settings')), or an assignment
# (location.hash = '#tab=info'). These never match _PATH_LITERAL_RE /
# _FRAGMENT_RE above (both require a leading '/' or 'http'), so without this
# they were invisible to parameter discovery even though the parameter names
# are sitting right there as literal text. Deliberately permissive: anything
# that isn't actually query-like (a route-only hash, a bare anchor, a CSS
# hex color such as '#fff') is filtered out downstream by
# parse_fragment_params(), which only returns pairs when the fragment
# contains '?' or '='.
_HASH_LITERAL_RE = re.compile(r'''["'`](#[A-Za-z0-9._~\-/?&=%]{1,})["'`]''')


def extract_param_names_from_js(script: str) -> set[str]:
    """Harvest likely parameter names from a script: `.get/getAll/has('x')`
    on URLSearchParams (inline, bound to a variable, or a conventionally-named
    accessor), `getParam('x')`-style helpers, FormData/params
    `.append/.set(name, ...)`, and the query keys inside any URL/template
    literal. Returns a set of bare names (never values). Heuristic by nature."""
    script = script or ''
    names: set[str] = set()
    for rx in (_JS_GETPARAM_RE, _JS_APPEND_RE, _JS_INLINE_USP_RE):
        names.update(rx.findall(script))
    accessors = set(_FIXED_ACCESSORS) | set(_JS_USP_BIND_RE.findall(script))
    access_re = re.compile(
        r'\b(?:' + '|'.join(re.escape(a) for a in accessors) +
        rf')\s*\.\s*(?:get|getAll|has)\s*\(\s*[\'"]({_NAME})[\'"]')
    names.update(access_re.findall(script))
    # Query keys embedded in string / template literals (strip ${...} first).
    for raw in _PATH_LITERAL_RE.findall(script) + _TEMPLATE_RE.findall(script):
        query = urlparse(_INTERP_RE.sub('', raw)).query
        if query:
            names.update(k for k, _ in parse_qsl(query, keep_blank_values=True))
    # Fragment (hash) literals, quoted directly or as a template literal
    # (`#/search?q=${term}`, interpolation stripped). Reuses
    # discovery.params.parse_fragment_params so hash-query parsing stays in
    # one place and shares its exact SPA-route/query rules with the passive
    # collect_parameters() path.
    hash_literals = _HASH_LITERAL_RE.findall(script)
    for raw in _TEMPLATE_RE.findall(script):
        stripped = _INTERP_RE.sub('', raw)
        if stripped.startswith('#'):
            hash_literals.append(stripped)
    for raw in hash_literals:
        names.update(k for k, _ in parse_fragment_params('https://_' + raw))
    return {n for n in names if n and len(n) <= 64}


def endpoints_from_source_map(map_text: str, base_url: str) -> dict:
    """Mine a JavaScript source map for endpoints. A .map file's `sources`
    lists the original module paths, and `sourcesContent` (when present)
    embeds the *unbundled, unminified* original source -- where endpoints
    are far more likely to appear as readable literals than in the shipped
    bundle. Returns {'sources': [...], 'api_endpoints': [...],
    'path_candidates': [...]}.
    """
    empty = {'sources': [], 'api_endpoints': [], 'path_candidates': []}
    try:
        data = json.loads(map_text)
    except (ValueError, TypeError) as e:
        log.debug('could not parse source map from %s: %s', base_url, e)
        return empty
    sources = [s for s in (data.get('sources') or []) if isinstance(s, str)]
    api, paths = set(), set()
    for content in (data.get('sourcesContent') or []):
        if not isinstance(content, str):
            continue
        sub = analyze_script(content, base_url)
        api.update(sub.all_api)
        paths.update(sub.path_candidates)
    return {
        'sources': sources,
        'api_endpoints': sorted(api),
        'path_candidates': sorted(paths),
    }
