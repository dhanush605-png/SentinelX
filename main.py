from __future__ import annotations
import ipaddress
import logging
import os
from urllib.parse import urlparse

import requests

from cli import build_parser
from crawler.spider import Crawler
from crawler.auth import parse_headers, parse_cookie_string, load_cookie_file, parse_basic_auth
from discovery.js import (analyze_script, endpoints_from_source_map, looks_like_api,
                          extract_param_names_from_js)
from discovery.params import (collect_parameters, discover_parameters, ParamObservation,
                              load_param_wordlist, DEFAULT_PARAM_CANDIDATES, METHOD_TO_LOCATION)
from discovery.passive import discover_passive_subdomains
from analysis.security import analyze_headers, parse_cookies, check_cors, interesting_paths
from reporting.writers import write_reports

log = logging.getLogger('SentinelX')


def _build_login_config(args) -> dict | None:
    """Turn --login-* CLI args into the login kwargs crawler.spider.Crawler
    passes on to crawler.browser.BrowserSession.login(). Returns None when
    no login was requested."""
    login_url = getattr(args, 'login_url', None)
    if not login_url:
        return None
    if not getattr(args, 'render_js', False):
        raise SystemExit('--login-url requires --render-js (filling a login form needs a real browser).')

    password = getattr(args, 'login_pass', None)
    pass_env = getattr(args, 'login_pass_env', None)
    if pass_env:
        password = os.environ.get(pass_env)
        if password is None:
            raise SystemExit(f'--login-pass-env: environment variable {pass_env!r} is not set')

    user = getattr(args, 'login_user', None)
    if not user or not password:
        raise SystemExit('--login-url requires a username (--login-user) and a password '
                          '(--login-pass or --login-pass-env)')

    return {
        'login_url': login_url,
        'user': user,
        'password': password,
        'user_selector': args.login_user_selector,
        'pass_selector': args.login_pass_selector,
        'submit_selector': args.login_submit_selector,
        'wait_selector': args.login_wait,
    }


def _build_auth_kwargs(args) -> dict:
    """Turn every authentication-related CLI flag into the kwargs
    crawler.spider.Crawler expects. Every flag defaults to "off", so a run
    with none of them set behaves exactly as before this feature existed."""
    render_js = getattr(args, 'render_js', False)
    storage_state = getattr(args, 'auth_storage_state', None)
    save_storage_state = getattr(args, 'save_storage_state', None)
    if storage_state and not render_js:
        raise SystemExit('--auth-storage-state requires --render-js.')
    if save_storage_state and not render_js:
        raise SystemExit('--save-storage-state requires --render-js.')

    cookies = {}
    cookies.update(load_cookie_file(getattr(args, 'cookie_file', None)))
    cookies.update(parse_cookie_string(getattr(args, 'cookie', None)))

    kwargs = {
        'headers': parse_headers(getattr(args, 'header', None)),
        'cookies': cookies,
        'basic_auth': parse_basic_auth(getattr(args, 'basic_auth', None)),
        'render_js': render_js,
        'storage_state': storage_state,
        'login': _build_login_config(args),
        'save_storage_state': save_storage_state,
    }
    max_reauths = getattr(args, 'session_max_reauth', 3)
    if max_reauths != 3:
        kwargs['max_reauths'] = max_reauths
    if getattr(args, 'auth_v2', False):
        kwargs.update({
            'auth_v2': True,
            'auth_verify_url': getattr(args, 'auth_verify_url', None),
            'auth_success_text': getattr(args, 'auth_success_text', None),
            'auth_failure_text': getattr(args, 'auth_failure_text', None),
        })
    kwargs.update({
        # CLI flags are "opt out of the fast default", so negate them here.
        'block_resources': not getattr(args, 'render_assets', False),
        'block_stylesheets': not getattr(args, 'render_css', False),
        'block_trackers': not getattr(args, 'allow_trackers', False),
        'neutralize_canvas': getattr(args, 'neutralize_canvas', False),
        'browser_arg': getattr(args, 'browser_arg', None),
    })
    return kwargs


def _is_public_hostname(host: str | None) -> bool:
    """Passive (CT-log) subdomain discovery only makes sense for a real,
    publicly resolvable hostname -- there's no certificate-transparency data
    for an IP address or 'localhost'."""
    if not host or host == 'localhost':
        return False
    try:
        ipaddress.ip_address(host)
        return False
    except ValueError:
        return True


def section(id, title, description, columns, rows, not_applicable_note=None):
    """A single feature's slice of the report. `rows` is a list of dicts
    keyed by `columns`. If rows is empty and not_applicable_note is None,
    the report renders an explicit 'no findings' message for this feature
    rather than just omitting the section."""
    return {
        'id': id,
        'title': title,
        'description': description,
        'columns': columns,
        'rows': rows,
        'count': len(rows),
        'not_applicable': not_applicable_note,
    }


def build_report(target: str, args) -> dict:
    auth_kwargs = _build_auth_kwargs(args)
    crawler = Crawler(target, args.depth, args.timeout, args.rate_limit, args.scope, args.proxy, **auth_kwargs)
    pages = crawler.crawl()

    seen_urls = set()
    unique_pages = []
    for p in pages:
        if p.url in seen_urls:
            continue
        seen_urls.add(p.url)
        unique_pages.append(p)

    # ---- Crawling: every page found -----------------------------------
    crawl_rows = [{'URL': p.url, 'Status': p.status, 'Content-Type': p.content_type} for p in unique_pages]

    # ---- Broken links ----------------------------------------------------
    broken_rows = [
        {'URL': p.url, 'Status': p.status, 'Error': p.error}
        for p in unique_pages if p.error or (p.status is not None and p.status >= 400)
    ]

    # ---- Redirects ---------------------------------------------------------
    redirect_rows = [
        {'URL': p.url, 'Final URL': p.final_url, 'Status': p.status}
        for p in unique_pages
        if not p.error and p.status and p.status < 400 and p.url.rstrip('/') != p.final_url.rstrip('/')
    ]

    # ---- Endpoint discovery: well-known paths -----------------------------
    endpoint_rows = []
    for path in interesting_paths(target):
        try:
            r = crawler.session.get(path, timeout=args.timeout)
            if r.status_code < 400:
                endpoint_rows.append({'URL': path, 'Status': r.status_code})
        except requests.RequestException as e:
            log.debug('endpoint discovery request failed for %s: %s', path, e)

    # ---- JavaScript analysis ------------------------------------------------
    # Static extraction goes well past "quoted literal API URLs": it also
    # recovers template-literal paths (${x} -> {}), path fragments left by
    # string concatenation, and -- when a script advertises a sourceMappingURL
    # -- the readable endpoints inside the original source embedded in the
    # .map file. Only concrete (no-placeholder) API URLs are fed to the live
    # API/CORS probes; template shapes and non-API paths are reported as
    # leads in a separate section rather than fetched.
    unique_scripts = sorted({s for p in unique_pages for s in p.scripts})
    js_rows = []
    js_dynamic_rows = []
    js_endpoints_found = set()  # concrete, fetchable API URLs only
    js_param_names = set()      # parameter names harvested from JS (feature: JS -> params)

    def _add_dynamic(script_url, kind, values):
        for v in values:
            js_dynamic_rows.append({'Script': script_url, 'Kind': kind, 'Endpoint / Source': v})

    for script_url in unique_scripts:
        try:
            r = crawler.session.get(script_url, timeout=args.timeout)
        except requests.RequestException as e:
            js_rows.append({'Script': script_url, 'Endpoints Found': f'(request failed: {e})'})
            continue
        analysis = analyze_script(r.text, script_url)
        js_param_names.update(extract_param_names_from_js(r.text))
        concrete_api = [e for e in analysis.all_api if '{}' not in e]
        js_endpoints_found.update(concrete_api)
        shown = analysis.all_api  # includes template shapes, for the reader
        js_rows.append({
            'Script': script_url,
            'Endpoints Found': ', '.join(shown) if shown else '(none)',
        })
        _add_dynamic(script_url, 'template', analysis.template_endpoints)
        _add_dynamic(script_url, 'path candidate', analysis.path_candidates)

        # Follow a source map if the bundle points to one -- its embedded
        # original source is where minified/concatenated endpoints become
        # readable again.
        if analysis.source_map_url:
            try:
                mr = crawler.session.get(analysis.source_map_url, timeout=args.timeout)
                js_param_names.update(extract_param_names_from_js(mr.text))
                mined = endpoints_from_source_map(mr.text, analysis.source_map_url)
                map_api = [e for e in mined['api_endpoints'] if '{}' not in e]
                js_endpoints_found.update(map_api)
                _add_dynamic(script_url, 'source map', [analysis.source_map_url])
                _add_dynamic(script_url, 'from source map (api)', mined['api_endpoints'])
                _add_dynamic(script_url, 'from source map (source)', mined['sources'])
            except requests.RequestException as e:
                _add_dynamic(script_url, 'source map', [f'{analysis.source_map_url} (fetch failed: {e})'])

    hidden_endpoints = sorted(js_endpoints_found - seen_urls)

    # ---- Parameter discovery ------------------------------------------------
    # Passive: every query/form parameter the crawl already saw (forms
    # included -- a link-only crawl never enumerated form fields). Active
    # (opt-in via --discover-params): probe a bounded set of endpoints for
    # hidden parameter names the server acknowledges. See discovery.params.
    param_inventory = collect_parameters(unique_pages)
    # JS -> parameter integration: names read/appended in JavaScript are real
    # application parameters, so record them in the passive inventory even
    # when the crawl never saw them in a link or form.
    for name in js_param_names:
        param_inventory.setdefault(name, ParamObservation(name=name)).locations.add('js')

    param_rows = []
    for name in sorted(param_inventory):
        o = param_inventory[name]
        endpoints = sorted(o.endpoints)
        seen_on = endpoints[0] if endpoints else ''
        if len(endpoints) > 1:
            seen_on += f' (+{len(endpoints) - 1} more)'
        param_rows.append({
            'Parameter': name,
            'Where': ', '.join(sorted(o.locations)) or '(unknown)',
            'Methods': ', '.join(sorted(o.methods)) or '-',
            'Field Types': ', '.join(sorted(t for t in o.field_types if t)) or '-',
            'Seen On': seen_on,
            'Confidence': 'observed',  # passive params were literally seen in the app
            'Example Values': ', '.join(sorted(o.example_values)) if o.example_values else '(none)',
        })

    if getattr(args, 'discover_params', False):
        wordlist = load_param_wordlist(getattr(args, 'param_wordlist', None))
        # Candidates: wordlist (or built-in) UNION names harvested from JS.
        candidates = list(dict.fromkeys((wordlist or list(DEFAULT_PARAM_CANDIDATES))
                                        + sorted(js_param_names)))
        methods = getattr(args, 'param_methods', None) or 'get'
        locations = [METHOD_TO_LOCATION[m.strip().lower()] for m in methods.split(',')
                     if m.strip().lower() in METHOD_TO_LOCATION] or ['query']
        # Probe the target plus any crawled GET page (dedup by path), bounded.
        probe_targets, seen_probe = [], set()
        for u in [crawler.target] + [p.final_url or p.url for p in unique_pages
                                     if not p.error and (p.status or 0) < 400]:
            base = urlparse(u)._replace(query='', fragment='').geturl()
            if base and base not in seen_probe:
                seen_probe.add(base)
                probe_targets.append(base)
            if len(probe_targets) >= getattr(args, 'param_probe_max_endpoints', 10):
                break
        _loc_method = {'query': 'GET', 'post-form': 'POST (form)', 'post-json': 'POST (JSON)'}
        for target_url in probe_targets:
            for f in discover_parameters(crawler.session, target_url, candidates,
                                         locations=locations, timeout=args.timeout,
                                         rate_limit=args.rate_limit):
                param_rows.append({
                    'Parameter': f.name,
                    'Where': f'hidden ({f.location})',
                    'Methods': _loc_method.get(f.location, f.location),
                    'Field Types': '-',
                    'Seen On': target_url,
                    'Confidence': f.confidence,
                    'Example Values': f.note,
                })

    # ---- API discovery: anything API-shaped, from the crawl or from JS ------
    # A hidden endpoint (referenced in JS but not linked from any crawled
    # page) is still a real, directly-reachable URL -- it's "hidden" only in
    # the sense that a link-only crawl wouldn't find it. We fetch it live so
    # API Discovery and CORS Analysis both see its real status/headers
    # rather than treating "not linked" as "not checked".
    api_urls = sorted({p.url for p in unique_pages if looks_like_api(p.url)} | js_endpoints_found)
    status_by_url = {p.url: p.status for p in unique_pages}
    for u in hidden_endpoints:
        try:
            r = crawler.session.get(u, timeout=args.timeout)
            status_by_url[u] = r.status_code
        except requests.RequestException as e:
            status_by_url[u] = f'(request failed: {e})'
    api_rows = [{
        'URL': u,
        'Status': status_by_url.get(u),
        'Linked': 'no -- found only via JavaScript' if u in hidden_endpoints else 'yes',
    } for u in api_urls]

    # ---- Security headers ---------------------------------------------------
    header_rows = []
    for p in unique_pages:
        if not p.headers:
            continue
        result = analyze_headers(p.url, p.headers)
        header_rows.append({
            'URL': p.url,
            'Missing Headers': ', '.join(result['security_headers_missing']) if result['security_headers_missing'] else '(none missing)',
            'Server': result['server'],
            'X-Powered-By': result['powered_by'],
        })

    # ---- Cookies ---------------------------------------------------------
    cookie_rows = []
    seen_cookie_names = set()
    for p in unique_pages:
        for c in parse_cookies(p.set_cookie_headers, p.url):
            if c['name'] in seen_cookie_names:
                continue
            seen_cookie_names.add(c['name'])
            cookie_rows.append({
                'Cookie': c['name'],
                'Set On': c['url'],
                'Secure': c['secure'],
                'HttpOnly': c['httponly'],
                'SameSite': c['samesite'] or '(not set)',
                'Issues': '; '.join(c['issues']) if c['issues'] else '(none)',
            })

    # ---- CORS analysis --------------------------------------------------
    # Probe every API-shaped endpoint regardless of whether it was linked --
    # a hidden endpoint is just as reachable as a linked one (see note above).
    cors_rows = []
    for u in api_urls:
        result = check_cors(crawler.session, u, args.timeout)
        if result is None:
            continue
        if 'error' in result:
            cors_rows.append({'URL': u, 'Access-Control-Allow-Origin': f"(request failed: {result['error']})",
                               'Access-Control-Allow-Credentials': '', 'High Risk': ''})
        else:
            cors_rows.append({
                'URL': u,
                'Access-Control-Allow-Origin': result['access_control_allow_origin'],
                'Access-Control-Allow-Credentials': result['access_control_allow_credentials'] or '(not set)',
                'High Risk': 'YES -- reflects arbitrary Origin with credentials allowed' if result['high_risk'] else 'no',
            })

    # ---- Passive subdomain discovery --------------------------------------
    host = urlparse(crawler.target).hostname
    passive_rows = []
    passive_note = None
    if not _is_public_hostname(host):
        passive_note = (
            f"Not applicable: '{host}' is not a public, resolvable hostname "
            "(it's an IP address or localhost), so there is no certificate-"
            "transparency history to query."
        )
    else:
        try:
            subs = discover_passive_subdomains(host, timeout=args.timeout)
            passive_rows = [{'Subdomain': s} for s in subs]
            if not subs:
                passive_note = f"Queried crt.sh for '{host}' -- no certificate-transparency records found."
        except requests.RequestException as e:
            passive_note = f"Could not query crt.sh for '{host}': {e}"

    sections = [
        section('crawl', 'Crawling -- Pages Found',
                'Every URL the crawler reached from the target, within scope and depth.',
                ['URL', 'Status', 'Content-Type'], crawl_rows),
        section('broken_links', 'Broken Links',
                'Pages that returned a 4xx/5xx status or failed to load.',
                ['URL', 'Status', 'Error'], broken_rows),
        section('redirects', 'Redirects',
                'Pages whose final URL differed from the requested URL.',
                ['URL', 'Final URL', 'Status'], redirect_rows),
        section('endpoint_discovery', 'Endpoint Discovery',
                'Well-known paths (robots.txt, sitemap.xml, API docs, etc.) checked directly.',
                ['URL', 'Status'], endpoint_rows),
        section('js_analysis', 'JavaScript Analysis',
                'Script files pulled from crawled pages, scanned for API-shaped URLs '
                '(literal, template-built, and recovered from source maps).',
                ['Script', 'Endpoints Found'], js_rows),
        section('js_dynamic', 'JavaScript Analysis -- Dynamic & Hidden Endpoints',
                'Endpoints not written as one literal string: template-literal paths '
                '(${...} shown as {}), path fragments from string concatenation, and '
                'endpoints/sources recovered from source maps.',
                ['Script', 'Kind', 'Endpoint / Source'], js_dynamic_rows),
        section('parameters', 'Parameter Discovery',
                'Query-string, client-side fragment, and form parameters enumerated from the crawl (forms and JS included), '
                'plus any hidden parameters found by --discover-params probing (query, POST-form and '
                'POST-JSON), each scored by the evidence that identified it. Fragment parameters such as /#/search?q=x are passive client-side findings.',
                ['Parameter', 'Where', 'Methods', 'Field Types', 'Seen On', 'Confidence', 'Example Values'],
                param_rows),
        section('api_discovery', 'API Discovery',
                'API/GraphQL-shaped endpoints found either by crawling or inside JavaScript.',
                ['URL', 'Status', 'Linked'], api_rows),
        section('security_headers', 'Security Header Analysis',
                'Recommended security headers checked on every crawled page.',
                ['URL', 'Missing Headers', 'Server', 'X-Powered-By'], header_rows),
        section('cookies', 'Cookie Analysis',
                'Cookies set by the target, checked for Secure/HttpOnly/SameSite flags.',
                ['Cookie', 'Set On', 'Secure', 'HttpOnly', 'SameSite', 'Issues'], cookie_rows),
        section('cors', 'CORS Analysis',
                'API-shaped endpoints probed with a spoofed Origin header to check CORS policy.',
                ['URL', 'Access-Control-Allow-Origin', 'Access-Control-Allow-Credentials', 'High Risk'], cors_rows),
        section('passive_subdomains', 'Passive Subdomain Discovery',
                'Subdomains found via certificate-transparency logs (crt.sh), no active DNS brute-forcing.',
                ['Subdomain'], passive_rows, not_applicable_note=passive_note),
    ]

    session_manager = getattr(crawler, 'session_manager', None)
    session_state = getattr(session_manager, 'state', None)
    auth_v2_controller = getattr(crawler, 'auth_v2_controller', None)
    auth_v2_state = getattr(auth_v2_controller, 'state', None)
    session_info = {
        'reauth_count': getattr(session_state, 'reauth_count', 0),
        'last_reauth_reason': getattr(session_state, 'last_reauth_reason', None),
        'exhausted': getattr(session_state, 'exhausted', False),
        'auth_v2_reauth_count': getattr(auth_v2_state, 'reauth_count', 0),
        'auth_v2_authenticated': getattr(auth_v2_state, 'authenticated', False),
    }

    return {'target': target, 'sections': sections, 'pages_crawled': len(unique_pages), 'session': session_info}


def main():
    args = build_parser().parse_args()
    logging.basicConfig(level=logging.INFO, format='%(levelname)s %(message)s')
    if args.depth < 0 or args.concurrency < 1:
        raise SystemExit('depth must be >=0 and concurrency >=1')

    report = build_report(args.target, args)
    formats = ('html', 'json', 'csv') if args.format == 'all' else (args.format,)
    write_reports(report, args.output, formats)

    summary = ', '.join(f"{s['title']}: {s['count']}" for s in report['sections'])
    print(f"SentinelX complete: {report['pages_crawled']} pages crawled. Reports: {args.output}/")
    print(summary)
    session = report['session']
    if session['reauth_count']:
        status = 'exhausted retries, session may still be invalid' if session['exhausted'] else 'recovered'
        print(f"Session: re-authenticated {session['reauth_count']}x "
              f"(last reason: {session['last_reauth_reason']}) -- {status}")


if __name__ == '__main__':
    main()
