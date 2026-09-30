from __future__ import annotations
import argparse

def build_parser() -> argparse.ArgumentParser:
    p=argparse.ArgumentParser(prog='SentinelX', description='Safe web attack-surface reconnaissance for authorized targets.')
    p.add_argument('target'); p.add_argument('--depth',type=int,default=2); p.add_argument('--concurrency',type=int,default=8)
    p.add_argument('--timeout',type=float,default=10); p.add_argument('--rate-limit',type=float,default=0.0)
    p.add_argument('--scope',choices=['same-origin','same-site'],default='same-origin'); p.add_argument('--proxy')
    p.add_argument('--output',default='reports'); p.add_argument('--format',choices=['html','json','csv','all'],default='all')

    render = p.add_argument_group('JavaScript rendering', 'Fetch pages with a real headless browser so SPA content '
                                   '(client-side-routed links, JS-inserted scripts) is discovered, not just the '
                                   'server-rendered HTML.')
    render.add_argument('--render-js', action='store_true',
                         help='Render every page with headless Chromium (via Playwright) instead of a plain GET.')
    render.add_argument('--render-assets', action='store_true',
                         help='Do not abort image/media/font requests during rendering (they are skipped by '
                              'default -- SentinelX never reads their bytes -- for faster, lower-bandwidth crawls).')
    render.add_argument('--render-css', action='store_true',
                         help='Do not abort stylesheet requests during rendering (skipped by default).')
    render.add_argument('--allow-trackers', action='store_true',
                         help='Do not abort requests to known analytics/tracker hosts during rendering '
                              '(blocked by default).')
    render.add_argument('--neutralize-canvas', action='store_true',
                         help='Stub out WebGL contexts to reduce CPU from background render loops. Off by '
                              'default: it changes what the page renders, which a recon crawl usually wants to '
                              'see exactly as a real browser would.')
    render.add_argument('--browser-arg', action='append', default=[], metavar='FLAG',
                         help='Extra Chromium launch flag, e.g. --browser-arg --no-sandbox (needed in some '
                              'containers with no usable sandbox/user namespace). Repeatable.')

    params = p.add_argument_group('Parameter discovery', 'Query-string and form parameters are always enumerated '
                                   'passively from the crawl. These flags add active discovery of hidden parameter '
                                   'names the server accepts but never links -- it sends benign marker values to '
                                   'learn which parameters exist, never attack payloads, and only against your own '
                                   'authorized target.')
    params.add_argument('--discover-params', action='store_true',
                        help='Actively probe endpoints for hidden/unlinked parameter names (off by default). '
                             'Uses differential response analysis and binary-split attribution, and folds in '
                             'parameter names harvested from JavaScript.')
    params.add_argument('--param-methods', metavar='LIST', default='get',
                        help='Comma-separated injection methods for hidden-parameter probing: get (query '
                             'string), post (form body), json (JSON body). Default: get.')
    params.add_argument('--param-wordlist', metavar='FILE',
                        help='Newline-delimited candidate parameter names to probe (# comments allowed). '
                             'Defaults to a small built-in list when --discover-params is set without this. '
                             'Names found in JavaScript are always added on top.')
    params.add_argument('--param-probe-max-endpoints', type=int, default=10, metavar='N',
                        help='Cap how many distinct endpoints hidden-parameter probing runs against. Default: 10.')

    auth = p.add_argument_group('Authentication', 'Reach functionality that sits behind a login. Every credential '
                                 'here is one you already hold for your own authorized target.')
    auth.add_argument('--header', action='append', default=[], metavar='NAME:VALUE',
                       help='Add a request header, e.g. --header "Authorization: Bearer <token>". Repeatable.')
    auth.add_argument('--cookie', metavar='STRING',
                       help='Raw Cookie header string to seed the session, e.g. "session=abc; csrftoken=xyz".')
    auth.add_argument('--cookie-file', metavar='FILE',
                       help='JSON file of {"name": "value", ...} cookies, or a Playwright storage_state JSON, to '
                            'seed the session.')
    auth.add_argument('--basic-auth', metavar='USER:PASS', help='HTTP Basic authentication credentials.')
    auth.add_argument('--auth-storage-state', metavar='FILE',
                       help='Playwright storage_state JSON (cookies + localStorage) captured from an already-'
                            'authenticated browser session. Requires --render-js.')
    auth.add_argument('--save-storage-state', metavar='FILE',
                       help='After the crawl (and any --login-url flow), save the authenticated session to this '
                            'file for reuse via --auth-storage-state on later runs. Requires --render-js.')

    login = p.add_argument_group('Login automation', 'Fill and submit a login form once, before crawling. Requires '
                                  '--render-js. This performs a single legitimate sign-in with credentials you '
                                  'supply -- it never guesses or brute-forces credentials.')
    login.add_argument('--login-url', help='URL of the login form to submit before crawling.')
    login.add_argument('--login-user', help='Username/email to fill into the login form.')
    login.add_argument('--login-pass', help='Password to fill into the login form.')
    login.add_argument('--login-pass-env', metavar='VAR',
                        help='Name of an environment variable holding the login password '
                             '(safer than --login-pass, which is visible in shell history and the process list).')
    login.add_argument('--login-user-selector', default='input[name="username"], input[name="email"], input[type="email"]',
                        help='CSS selector for the username/email field.')
    login.add_argument('--login-pass-selector', default='input[name="password"], input[type="password"]',
                        help='CSS selector for the password field.')
    login.add_argument('--login-submit-selector', default='button[type="submit"], input[type="submit"]',
                        help='CSS selector for the login form submit control.')
    login.add_argument('--login-wait', metavar='SELECTOR', default=None,
                        help='Optional CSS selector to wait for after submitting, confirming the authenticated '
                             'app has loaded (defaults to waiting for the network to go idle).')
    authv2 = p.add_argument_group('Authentication V2', 'Opt-in authentication lifecycle with explicit verification and automatic re-authentication.')
    authv2.add_argument('--auth-v2', action='store_true',
                        help='Use the second authentication system: login, verify, detect expiry, re-authenticate, and retry. Requires --render-js and --login-url.')
    authv2.add_argument('--auth-verify-url', metavar='URL',
                        help='Authenticated URL used by Authentication V2 to verify the session, e.g. /dashboard.')
    authv2.add_argument('--auth-success-text', metavar='TEXT',
                        help='Text that must appear on --auth-verify-url for the session to be considered authenticated.')
    authv2.add_argument('--auth-failure-text', metavar='TEXT',
                        help='Text indicating a logged-out/login state on --auth-verify-url.')
    login.add_argument('--session-max-reauth', type=int, default=3, metavar='N',
                        help='If the session appears to expire mid-crawl (401/403, or a redirect back to a '
                             'login page), re-run the --login-url flow up to N times to recover. Only takes '
                             'effect together with --login-url. Set to 0 to disable. Default: 3.')
    return p
