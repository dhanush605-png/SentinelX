from __future__ import annotations

"""Second-generation authentication controller for SentinelX.

This module is intentionally separate from crawler.session.SessionManager.
It provides an explicit authentication lifecycle:

    login -> verify -> crawl -> detect expiry -> re-authenticate -> verify -> retry

It is opt-in so the existing authentication implementation remains intact.
It is designed for tester-supplied credentials against authorized targets and
never guesses credentials or performs brute-force authentication.
"""

import logging
from dataclasses import dataclass
from typing import Callable

log = logging.getLogger("SentinelX")


@dataclass
class AuthV2State:
    authenticated: bool = False
    reauth_count: int = 0
    last_reason: str | None = None
    exhausted: bool = False


class AuthenticationController:
    """Owns authentication state independently of the legacy SessionManager."""

    def __init__(
        self,
        login_callback: Callable[[], bool],
        verify_callback: Callable[[], bool],
        max_reauths: int = 3,
    ) -> None:
        if max_reauths < 0:
            raise ValueError("max_reauths must be >= 0")
        self.login_callback = login_callback
        self.verify_callback = verify_callback
        self.max_reauths = max_reauths
        self.state = AuthV2State()

    @staticmethod
    def is_expired(
        status: int | None,
        final_url: str | None,
        login_url: str | None = None,
        body: str | None = None,
        failure_text: str | None = None,
    ) -> bool:
        if status in (401, 403):
            return True
        if final_url:
            final = final_url.rstrip("/").lower()
            if login_url and final == login_url.rstrip("/").lower():
                return True
            if any(part in final for part in ("/login", "/signin", "/sign-in", "/log-in")):
                return True
        if failure_text and body and failure_text.lower() in body.lower():
            return True
        return False

    def initial_login(self) -> bool:
        ok = bool(self.login_callback())
        self.state.authenticated = ok
        if not ok:
            self.state.exhausted = True
            self.state.last_reason = "initial authentication failed"
            return False
        if not self.verify_callback():
            self.state.authenticated = False
            self.state.exhausted = True
            self.state.last_reason = "initial authentication verification failed"
            log.warning("Auth V2 login completed but verification failed")
            return False
        return True

    def reauthenticate(self, reason: str) -> bool:
        self.state.last_reason = reason
        if self.state.exhausted or self.state.reauth_count >= self.max_reauths:
            self.state.exhausted = True
            log.warning("Auth V2 re-authentication limit reached (%d)", self.max_reauths)
            return False

        attempt = self.state.reauth_count + 1
        log.info("Auth V2 session expired (%s); re-authenticating (%d/%d)", reason, attempt, self.max_reauths)
        self.state.reauth_count += 1

        try:
            if not self.login_callback():
                self.state.authenticated = False
                self.state.exhausted = True
                return False
            if not self.verify_callback():
                self.state.authenticated = False
                self.state.exhausted = True
                log.warning("Auth V2 re-authentication succeeded but verification failed")
                return False
        except Exception as exc:
            self.state.authenticated = False
            self.state.exhausted = True
            log.warning("Auth V2 re-authentication failed: %s", exc)
            return False

        self.state.authenticated = True
        return True
