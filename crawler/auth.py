from __future__ import annotations

"""Parsing helpers for authenticated scanning.

SentinelX is only useful against a real application if it can reach whatever
sits behind a login -- most of a modern app's interesting attack surface
(account settings, admin panels, internal APIs) is unauthenticated-invisible
by design. These helpers turn CLI-supplied credentials/tokens into the
plain dicts/tuples `crawler.spider.Crawler` needs; they contain no network
code and no guessing/brute-forcing of credentials -- every credential here
is supplied directly by the tester for their own authorized target.
"""

import json
from http.cookies import SimpleCookie


def parse_headers(header_args: list[str] | None) -> dict[str, str]:
    """Parse repeated ``--header "Name: Value"`` CLI arguments into a dict.

    Typically used for ``Authorization: Bearer <token>`` or an API key
    header, so SentinelX's crawl (and every derived request -- JS fetches,
    endpoint probes, CORS probes) is made as an authenticated user.
    """
    headers: dict[str, str] = {}
    for item in header_args or []:
        if ':' not in item:
            raise ValueError(f"invalid --header {item!r}, expected \"Name: Value\"")
        name, _, value = item.partition(':')
        name, value = name.strip(), value.strip()
        if not name:
            raise ValueError(f"invalid --header {item!r}, expected \"Name: Value\"")
        headers[name] = value
    return headers


def parse_cookie_string(cookie_str: str | None) -> dict[str, str]:
    """Parse a raw ``name=value; name2=value2`` Cookie header string, as
    copied straight out of a browser's DevTools, into a name->value dict."""
    if not cookie_str:
        return {}
    jar = SimpleCookie()
    jar.load(cookie_str)
    return {name: morsel.value for name, morsel in jar.items()}


def load_cookie_file(path: str | None) -> dict[str, str]:
    """Load cookies from a JSON file. Two shapes are accepted:

    - a flat ``{"name": "value", ...}`` map, or
    - a Playwright ``storage_state`` document (``{"cookies": [{"name": ..,
      "value": ..}, ...], "origins": [...]}``), so a session already
      exported for ``--auth-storage-state`` can be reused for plain
      (non-JS-rendered) requests too.
    """
    if not path:
        return {}
    with open(path, encoding='utf8') as f:
        data = json.load(f)
    if isinstance(data, dict) and 'cookies' in data:
        return {c['name']: c['value'] for c in data['cookies']}
    if isinstance(data, dict):
        return {k: str(v) for k, v in data.items()}
    raise ValueError(f'unrecognized cookie file format: {path}')


def parse_basic_auth(value: str | None) -> tuple[str, str] | None:
    """Parse a ``USER:PASS`` value for HTTP Basic authentication."""
    if not value:
        return None
    if ':' not in value:
        raise ValueError('--basic-auth must be in the form USER:PASS')
    user, _, password = value.partition(':')
    return (user, password)
