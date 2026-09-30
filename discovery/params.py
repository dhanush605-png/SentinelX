from __future__ import annotations

"""Parameter discovery for SentinelX.

Before this module, SentinelX only ever "saw" the exact query strings that
happened to appear in crawled links -- it had no dedicated notion of a
*parameter* at all. That under-reports attack surface badly: the query and
form parameters an application accepts are where most input-handling bugs
live (injection, IDOR, mass-assignment, open-redirect), and many of the
interesting ones are never present in a link the crawler can follow.

This module adds two layers, both scoped to authorized targets:

1. Passive enumeration (no extra requests). Every parameter is harvested
   from material the crawl already fetched -- the query strings of the
   target, every crawled page's final URL, every discovered link, and the
   fields of every HTML <form> (which the plain-link crawler ignored
   entirely). This alone turns "the query strings that appeared in links"
   into "every query and form parameter the site exposed to the crawl".

2. Fragment-aware enumeration. Client-side routes commonly store query
   parameters after the `#` (for example `/#/search?q=admin`). Browsers do not
   send that fragment to the server, so normal URL query parsing misses it.
   SentinelX parses query-like parameters from hash fragments and records them
   separately as `fragment` / `CLIENT` parameters. This is passive and uses
   URLs the crawler already encountered. discovery.js also feeds this: a hash
   route or hash query string written directly into JavaScript as a string
   literal or template literal (a router table entry, `location.hash = '#tab=x'`,
   `navigate('#/search?q=admin')`) is parsed with the same
   parse_fragment_params() used here, so fragment parameters that only ever
   appear inside a script -- never in a rendered `<a href>` -- are still
   discovered.

3. Active hidden-parameter discovery (opt-in). Some parameters are accepted
   by an endpoint but never appear in any HTML or link -- "hidden" or
   "secret" parameters (debug flags, feature toggles, legacy inputs). This
   is the same mapping technique tools like Arjun/ParamMiner use: send a
   set of candidate parameter *names* carrying a unique benign marker value,
   and see which names the server acknowledges. It sends marker values,
   never attack payloads -- the goal is to learn which parameters exist, not
   to exploit them -- and it is rate-limitable and off unless the tester
   explicitly enables it for their own target.

   The ParamProber engine that does this supports:
     * Differential response analysis -- a two-sample baseline establishes
       how much the endpoint's response naturally varies (status, byte
       length, word and line counts), and a probe only counts as an effect
       when it moves the response beyond that observed jitter, so dynamic
       pages (CSRF tokens, timestamps) don't produce false positives.
     * Individual attribution by binary splitting -- a reflected marker is
       attributed to its name directly; a non-reflected group effect is
       isolated by recursively halving the group and re-testing, so a real
       but non-reflecting parameter is pinned to one name instead of being
       reported as an anonymous "something in this batch" signal.
     * Multiple injection locations -- query string (GET), form body
       (POST application/x-www-form-urlencoded), and JSON body
       (POST application/json), so parameters an endpoint only reads from a
       request body are discoverable too.
     * Confidence/evidence scoring -- every finding carries the concrete
       evidence that produced it (reflection, status change, body-size
       change) and a high/medium/low confidence derived from it.
"""

import logging
import re
import time
from dataclasses import dataclass, field
from urllib.parse import urljoin, urlparse, parse_qsl, urlencode, urlunparse

from bs4 import BeautifulSoup

log = logging.getLogger('SentinelX')

# Fields that carry no server-side parameter meaning worth reporting.
_IGNORED_INPUT_TYPES = frozenset({'submit', 'button', 'image', 'reset'})


@dataclass
class FormField:
    name: str
    type: str
    value: str = ''


@dataclass
class Form:
    action: str          # absolute URL the form submits to
    method: str          # 'GET' or 'POST'
    fields: list[FormField] = field(default_factory=list)
    source_url: str = ''  # page the form was found on


@dataclass
class ParamObservation:
    """Everything SentinelX learned about one parameter name, aggregated
    across every place it was seen during the crawl."""
    name: str
    locations: set = field(default_factory=set)      # {'query', 'form'}
    methods: set = field(default_factory=set)         # {'GET', 'POST'}
    endpoints: set = field(default_factory=set)       # URLs it was seen on
    field_types: set = field(default_factory=set)     # form input types
    example_values: set = field(default_factory=set)

    def add_value(self, value: str) -> None:
        if value:
            # Keep the inventory small and non-sensitive: a couple of short
            # samples is enough to show shape without hoarding real data.
            if len(self.example_values) < 3:
                self.example_values.add(value[:64])


@dataclass
class ParamFinding:
    """One discovered (or candidate) hidden parameter, with the evidence
    that identified it and a confidence derived from that evidence."""
    name: str
    location: str                                   # 'query' | 'post-form' | 'post-json'
    reflected: bool = False
    status: int | str | None = None
    evidence: list = field(default_factory=list)    # human-readable evidence strings
    confidence: str = 'low'                          # 'high' | 'medium' | 'low'
    score: float = 0.0

    @property
    def note(self) -> str:
        return '; '.join(self.evidence) if self.evidence else '(no evidence)'


def parse_query_params(url: str) -> list[tuple[str, str]]:
    """Return the (name, value) pairs in a URL's query string, keeping
    repeats and blank values (``?a=&b`` -> [('a',''), ('b','')])."""
    query = urlparse(url).query
    return parse_qsl(query, keep_blank_values=True) if query else []




def parse_fragment_params(url: str) -> list[tuple[str, str]]:
    """Return query-like parameter pairs embedded in a URL fragment.

    This handles the common SPA forms::

        /#/search?q=admin
        #?q=admin
        #q=admin&sort=name

    The fragment is client-side data and is deliberately *not* sent to the
    server. We therefore keep these parameters separate from normal ``query``
    parameters instead of pretending they were HTTP GET parameters.

    Route-only fragments such as ``#/search`` and ``#dashboard`` produce no
    parameters. A fragment only becomes parameter data when it contains a
    query marker (``?``) or a query-style ``name=value`` pair.
    """
    fragment = urlparse(url).fragment
    if not fragment:
        return []

    # SPA hash routes: "#/route?x=1". Also accept "#?x=1".
    if '?' in fragment:
        _, query = fragment.split('?', 1)
        return parse_qsl(query, keep_blank_values=True) if query else []

    # Query-like hash fragments: "#x=1&y=2".
    if '=' in fragment:
        return parse_qsl(fragment.lstrip('?'), keep_blank_values=True)

    return []

def extract_forms(html: str, base_url: str) -> list[Form]:
    """Parse every <form> out of a page: its resolved action URL, method,
    and named fields (input/select/textarea/button). This is the parameter
    surface a link-only crawl never sees -- a POST search form or a
    settings form exposes named parameters that appear in no href."""
    soup = BeautifulSoup(html or '', 'lxml')
    forms: list[Form] = []
    for f in soup.find_all('form'):
        action = urljoin(base_url, f.get('action') or '')
        method = (f.get('method') or 'GET').strip().upper()
        if method not in ('GET', 'POST'):
            method = 'GET'
        fields: list[FormField] = []
        seen = set()
        for el in f.find_all(['input', 'select', 'textarea', 'button']):
            name = el.get('name')
            if not name:
                continue
            ftype = (el.get('type') or el.name or '').strip().lower()
            if el.name == 'input' and ftype in _IGNORED_INPUT_TYPES:
                continue
            value = el.get('value') or ''
            key = (name, ftype)
            if key in seen:
                continue
            seen.add(key)
            fields.append(FormField(name=name, type=ftype, value=value))
        forms.append(Form(action=action, method=method, fields=fields, source_url=base_url))
    return forms


def collect_parameters(pages) -> dict[str, ParamObservation]:
    """Aggregate every query and form parameter across the crawl.

    `pages` is an iterable of crawler.spider.PageResult. We read query
    parameters from each page's requested URL, its final URL, and every
    link it discovered, and form parameters from each page's parsed forms.
    """
    inventory: dict[str, ParamObservation] = {}

    def obs(name: str) -> ParamObservation:
        return inventory.setdefault(name, ParamObservation(name=name))

    def add_query(url: str) -> None:
        for name, value in parse_query_params(url):
            o = obs(name)
            o.locations.add('query')
            o.methods.add('GET')
            o.endpoints.add(urlparse(url)._replace(query='', fragment='').geturl())
            o.add_value(value)

    def add_fragment(url: str) -> None:
        for name, value in parse_fragment_params(url):
            o = obs(name)
            o.locations.add('fragment')
            o.methods.add('CLIENT')
            # Keep the client-side route visible in the report. Unlike an
            # HTTP query parameter, a fragment is meaningful only in the
            # browser and is never transmitted to the server.
            o.endpoints.add(url)
            o.add_value(value)

    for p in pages:
        add_query(getattr(p, 'url', '') or '')
        add_query(getattr(p, 'final_url', '') or '')
        add_fragment(getattr(p, 'url', '') or '')
        add_fragment(getattr(p, 'final_url', '') or '')
        for link in getattr(p, 'links', None) or []:
            add_query(link)
            add_fragment(link)
        for form in getattr(p, 'forms', None) or []:
            for fld in form.fields:
                o = obs(fld.name)
                o.locations.add('form')
                o.methods.add(form.method)
                o.endpoints.add(form.action)
                o.field_types.add(fld.type)
                o.add_value(fld.value)

    return inventory


def _with_query(url: str, extra: dict[str, str]) -> str:
    parts = urlparse(url)
    pairs = parse_qsl(parts.query, keep_blank_values=True) + list(extra.items())
    return urlunparse(parts._replace(query=urlencode(pairs)))


def load_param_wordlist(path: str | None) -> list[str]:
    """Load candidate parameter names, one per line (blank lines and
    ``#`` comments ignored)."""
    if not path:
        return []
    names: list[str] = []
    with open(path, encoding='utf8') as fh:
        for line in fh:
            line = line.strip()
            if line and not line.startswith('#'):
                names.append(line)
    return names


# A small built-in list of commonly-accepted-but-rarely-linked parameter
# names, so --discover-params is useful without requiring a wordlist. These
# are parameter *names* to test for existence, not payloads.
DEFAULT_PARAM_CANDIDATES = (
    'id', 'page', 'q', 'query', 'search', 'debug', 'test', 'admin', 'user',
    'user_id', 'account', 'redirect', 'redirect_url', 'url', 'next', 'return',
    'return_url', 'callback', 'file', 'path', 'dir', 'lang', 'format', 'view',
    'sort', 'order', 'limit', 'offset', 'filter', 'token', 'api_key', 'key',
    'preview', 'draft', 'show', 'mode', 'action', 'type', 'ref', 'source',
)


PROBE_LOCATIONS = ('query', 'post-form', 'post-json')
# CLI-facing method names -> internal injection location.
METHOD_TO_LOCATION = {'get': 'query', 'post': 'post-form', 'json': 'post-json'}
_MARKER = 'rrp'  # short marker prefix, unlikely to collide with real content
_WORD_RE = re.compile(r'\S+')


@dataclass
class _Signature:
    """A cheap, content-agnostic fingerprint of one HTTP response, used to
    tell whether injecting a parameter changed anything."""
    status: int | None
    length: int
    words: int
    lines: int


def _signature(resp) -> _Signature:
    body = getattr(resp, 'text', '') or ''
    return _Signature(
        status=getattr(resp, 'status_code', None),
        length=len(body),
        words=len(_WORD_RE.findall(body)),
        lines=body.count('\n') + 1,
    )


class ParamProber:
    """Differential hidden-parameter prober for one endpoint at one injection
    location. See the module docstring for the technique and the safety
    scope: it sends benign marker values to learn which parameter names an
    endpoint acknowledges, never attack payloads.
    """

    def __init__(self, session, url, *, location='query', timeout=10.0, rate_limit=0.0,
                 chunk_size=20, marker=_MARKER, sleep=None, max_requests=300):
        if location not in PROBE_LOCATIONS:
            raise ValueError(f'unknown probe location {location!r}')
        self.session = session
        self.url = url
        self.location = location
        self.timeout = timeout
        self.rate_limit = rate_limit
        self.chunk_size = max(1, chunk_size)
        self.marker = marker
        self._sleep = sleep or time.sleep
        self.max_requests = max_requests
        self._requests_made = 0
        self.baseline: _Signature | None = None
        self.jitter_len = self.jitter_words = self.jitter_lines = 0
        self.baseline_stable = True

    # -- transport ---------------------------------------------------------
    def _send(self, params: dict):
        """Issue one request injecting `params` at this prober's location.
        Returns the response, or None on transport failure / budget exhausted."""
        if self._requests_made >= self.max_requests:
            return None
        self._requests_made += 1
        if self.rate_limit:
            self._sleep(self.rate_limit)
        try:
            if self.location == 'query':
                return self.session.get(_with_query(self.url, params), timeout=self.timeout)
            if self.location == 'post-form':
                return self.session.post(self.url, data=params, timeout=self.timeout)
            return self.session.post(self.url, json=params, timeout=self.timeout)
        except Exception as e:  # noqa: BLE001 -- a probe failure must never abort the scan
            log.debug('parameter probe (%s) failed for %s: %s', self.location, self.url, e)
            return None

    def _markers_for(self, names, start=0) -> dict:
        # A distinctive per-name token so a reflection can be tied to one name.
        return {name: f'{self.marker}{start + i}z' for i, name in enumerate(names)}

    # -- differential baseline --------------------------------------------
    def _establish_baseline(self) -> bool:
        """Sample the endpoint twice with no injected parameters to learn
        both its resting fingerprint and how much it naturally varies."""
        a = self._send({})
        b = self._send({})
        if a is None or b is None:
            return False
        sa, sb = _signature(a), _signature(b)
        self.baseline = sa
        self.jitter_len = abs(sa.length - sb.length)
        self.jitter_words = abs(sa.words - sb.words)
        self.jitter_lines = abs(sa.lines - sb.lines)
        self.baseline_stable = (sa.status == sb.status and self.jitter_len == 0
                                and self.jitter_words == 0 and self.jitter_lines == 0)
        return True

    def _diff(self, resp):
        """Compare `resp` to the baseline, allowing for observed jitter.
        Returns (reasons, status_changed, body_changed)."""
        sig = _signature(resp)
        reasons, status_changed, body_changed = [], False, False
        if sig.status != self.baseline.status:
            reasons.append(f'status {self.baseline.status} -> {sig.status}')
            status_changed = True
        len_delta = sig.length - self.baseline.length
        if abs(len_delta) > self.jitter_len:
            reasons.append(f'body length {len_delta:+d} bytes (baseline jitter +/-{self.jitter_len})')
            body_changed = True
        word_delta = sig.words - self.baseline.words
        if abs(word_delta) > self.jitter_words:
            reasons.append(f'word count {word_delta:+d} (baseline jitter +/-{self.jitter_words})')
            body_changed = True
        return reasons, status_changed, body_changed

    # -- main flow ---------------------------------------------------------
    def discover(self, candidates) -> list[ParamFinding]:
        candidates = [c for c in dict.fromkeys(candidates) if c]  # dedupe, keep order
        if not candidates or not self._establish_baseline():
            return []

        findings: dict[str, ParamFinding] = {}

        # 1. Reflection screen: markers echoed back attribute directly to a name.
        reflected = set()
        for start in range(0, len(candidates), self.chunk_size):
            chunk = candidates[start:start + self.chunk_size]
            markers = self._markers_for(chunk, start)
            resp = self._send(markers)
            if resp is None:
                continue
            body = getattr(resp, 'text', '') or ''
            status = getattr(resp, 'status_code', None)
            for name, token in markers.items():
                if token in body:
                    reflected.add(name)
                    findings[name] = ParamFinding(
                        name=name, location=self.location, reflected=True, status=status,
                        evidence=[f"marker value reflected in response (endpoint reads '{name}')"],
                    )

        # 2. Differential attribution by binary splitting over the non-reflected
        #    names: a real-but-silent parameter is isolated to one name.
        remaining = [n for n in candidates if n not in reflected]
        for f in self._bisect(remaining):
            findings.setdefault(f.name, f)

        return sorted((self._score(f) for f in findings.values()),
                      key=lambda f: (-f.score, f.name))

    def _bisect(self, names) -> list[ParamFinding]:
        if not names:
            return []
        resp = self._send(self._markers_for(names))
        if resp is None:
            return []
        reasons, status_changed, body_changed = self._diff(resp)
        if not reasons:
            return []  # this group moves nothing measurable
        status = getattr(resp, 'status_code', None)
        if len(names) == 1:
            f = ParamFinding(name=names[0], location=self.location, reflected=False,
                             status=status, evidence=list(reasons))
            f._status_changed, f._body_changed = status_changed, body_changed
            return [f]
        mid = len(names) // 2
        halves = self._bisect(names[:mid]) + self._bisect(names[mid:])
        if halves:
            return halves
        # Neither half alone reproduced the effect: it needs the whole group
        # (parameter interaction) or is noise we can't pin down. Report once,
        # low-confidence, rather than silently dropping or over-claiming it.
        f = ParamFinding(name=f'(group of {len(names)})', location=self.location, reflected=False,
                         status=status,
                         evidence=[f'group effect not isolated to one parameter: {"; ".join(reasons)}'])
        f._unattributed = True
        return [f]

    def _score(self, f: ParamFinding) -> ParamFinding:
        """Turn a finding's evidence into a 0..1 confidence score and label.
        Reflection and status change are strong signals; a body-size change
        is moderate, and weak when the baseline was itself unstable."""
        score = 0.0
        if f.reflected:
            score += 0.65
        if getattr(f, '_status_changed', False):
            score += 0.45
        if getattr(f, '_body_changed', False):
            score += 0.30 if self.baseline_stable else 0.12
        if getattr(f, '_unattributed', False):
            score = min(score, 0.2)
        f.score = round(min(score, 1.0), 2)
        f.confidence = 'high' if f.score >= 0.6 else 'medium' if f.score >= 0.3 else 'low'
        return f


def discover_parameters(session, url, candidates, *, locations=('query',), timeout=10.0,
                        rate_limit=0.0, chunk_size=20, max_requests_per_location=300,
                        sleep=None) -> list[ParamFinding]:
    """Run hidden-parameter discovery at each requested injection location
    and return the combined, scored findings."""
    out: list[ParamFinding] = []
    for loc in locations:
        prober = ParamProber(session, url, location=loc, timeout=timeout, rate_limit=rate_limit,
                             chunk_size=chunk_size, max_requests=max_requests_per_location, sleep=sleep)
        out.extend(prober.discover(candidates))
    return out


def probe_hidden_params(session, url, candidates, *, timeout=10.0, rate_limit=0.0,
                        chunk_size=20, marker=_MARKER, sleep=None) -> list[ParamFinding]:
    """Backward-compatible query-string probe: differential + reflection
    discovery at the 'query' location. Returns a list of ParamFinding."""
    return ParamProber(session, url, location='query', timeout=timeout, rate_limit=rate_limit,
                       chunk_size=chunk_size, marker=marker, sleep=sleep).discover(candidates)
