from __future__ import annotations

"""Session lifecycle management for authenticated crawls.

Every authentication method SentinelX supports (--header/--cookie/
--basic-auth, a loaded --auth-storage-state, or a --login-url form
submission) only proves the session was valid *at the start* of the run.
A long, depth-limited crawl can easily outlive that: a server-side
session timeout, a CSRF/session-cookie rotation the crawler doesn't pick
up, or a reverse proxy dropping the auth header partway through -- and
every request after that point would silently be crawled as an
unauthenticated user, with no error, just a report full of login pages.

SessionManager watches for that. It flags a response as a likely
session-expiry (401/403, or a redirect to something that looks like a
login page) and, when a re-authentication method is available, re-runs
it once and tells the caller to retry the request that triggered it.

This performs no credential guessing or brute-forcing: the only thing a
reauth callback is allowed to do is replay the exact single login the
tester already configured with --login-*, the same as before -- it is
just no longer limited to running that login once at the very start.
"""

import logging
import re
import time
from dataclasses import dataclass

log = logging.getLogger('SentinelX')

LOGIN_URL_HINT = re.compile(r'(?:^|/)(login|signin|sign-in|log-in|auth|sso)(?:[/?]|$)', re.IGNORECASE)


@dataclass
class SessionState:
    reauth_count: int = 0
    last_reauth_at: float | None = None
    last_reauth_reason: str | None = None
    exhausted: bool = False


class SessionManager:
    """Tracks whether the crawl's authenticated session still looks good,
    and re-authenticates (at most `max_reauths` times) when it doesn't.

    `reauth_callback`, if given, is called with no arguments whenever
    re-authentication is needed. It must perform the actual re-login (for
    example, re-running BrowserSession.login()) and return True on
    success. Without a callback, SessionManager still detects and reports
    expiry, it just can't recover from it -- exactly like SentinelX's
    behavior before this feature existed.
    """

    def __init__(self, reauth_callback=None, max_reauths: int = 3, login_url_hint: str | None = None):
        self.reauth_callback = reauth_callback
        self.max_reauths = max_reauths
        self._login_url_hint = login_url_hint
        self.state = SessionState()

    @property
    def can_reauth(self) -> bool:
        return self.reauth_callback is not None and not self.state.exhausted

    def looks_expired(self, status: int | None, final_url: str | None) -> str | None:
        """Return a short human-readable reason if `status`/`final_url`
        look like a rejected or expired session, else None."""
        if status in (401, 403):
            return f'HTTP {status}'
        if final_url:
            if self._login_url_hint and final_url.rstrip('/') == self._login_url_hint.rstrip('/'):
                return 'redirected back to the configured login URL'
            if LOGIN_URL_HINT.search(final_url):
                return 'redirected to what looks like a login page'
        return None

    def maybe_reauth(self, status: int | None, final_url: str | None) -> bool:
        """Check a response for signs of session expiry and, if found and
        re-authentication is available, re-authenticate. Returns True when
        the caller should retry the request that produced this response."""
        reason = self.looks_expired(status, final_url)
        if not reason:
            return False
        if not self.can_reauth:
            log.warning('session looks expired (%s) but no re-authentication '
                         'method is configured (use --login-url to enable it)', reason)
            return False
        if self.state.reauth_count >= self.max_reauths:
            self.state.exhausted = True
            log.warning('session expired again (%s) after %d re-authentication '
                        'attempt(s); giving up on further retries', reason, self.state.reauth_count)
            return False

        log.info('session appears to have expired (%s); re-authenticating '
                  '(attempt %d/%d)', reason, self.state.reauth_count + 1, self.max_reauths)
        ok = self.reauth_callback()
        self.state.reauth_count += 1
        self.state.last_reauth_at = time.time()
        self.state.last_reauth_reason = reason
        if not ok:
            self.state.exhausted = True
            log.warning('re-authentication failed; giving up on further retries')
        return ok
