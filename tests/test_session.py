from crawler.session import SessionManager


def test_looks_expired_flags_401_and_403():
    sm = SessionManager()
    assert sm.looks_expired(401, 'https://app.example.com/account') == 'HTTP 401'
    assert sm.looks_expired(403, 'https://app.example.com/account') == 'HTTP 403'


def test_looks_expired_flags_login_redirect():
    sm = SessionManager()
    reason = sm.looks_expired(200, 'https://app.example.com/login?next=/account')
    assert reason == 'redirected to what looks like a login page'


def test_looks_expired_returns_none_for_healthy_response():
    sm = SessionManager()
    assert sm.looks_expired(200, 'https://app.example.com/account') is None


def test_maybe_reauth_without_callback_only_detects():
    sm = SessionManager(reauth_callback=None)
    assert sm.maybe_reauth(401, 'https://app.example.com/account') is False
    assert sm.state.reauth_count == 0


def test_maybe_reauth_calls_callback_and_counts_attempts():
    calls = []
    sm = SessionManager(reauth_callback=lambda: (calls.append(1) or True), max_reauths=3)
    assert sm.maybe_reauth(401, 'https://app.example.com/account') is True
    assert len(calls) == 1
    assert sm.state.reauth_count == 1
    assert sm.state.last_reauth_reason == 'HTTP 401'


def test_maybe_reauth_stops_after_max_reauths():
    calls = []
    sm = SessionManager(reauth_callback=lambda: (calls.append(1) or True), max_reauths=2)
    for _ in range(5):
        sm.maybe_reauth(401, 'https://app.example.com/account')
    assert len(calls) == 2
    assert sm.state.exhausted is True


def test_maybe_reauth_gives_up_immediately_on_failed_callback():
    sm = SessionManager(reauth_callback=lambda: False, max_reauths=3)
    assert sm.maybe_reauth(401, 'https://app.example.com/account') is False
    assert sm.state.exhausted is True
    # a second call shouldn't re-invoke the callback once exhausted
    assert sm.can_reauth is False


def test_maybe_reauth_ignores_healthy_response():
    sm = SessionManager(reauth_callback=lambda: True)
    assert sm.maybe_reauth(200, 'https://app.example.com/account') is False
    assert sm.state.reauth_count == 0


def test_auth_v2_initial_login_and_verification():
    from crawler.auth_v2 import AuthenticationController
    calls = []
    controller = AuthenticationController(
        login_callback=lambda: (calls.append('login') or True),
        verify_callback=lambda: (calls.append('verify') or True),
        max_reauths=2,
    )
    assert controller.initial_login() is True
    assert controller.state.authenticated is True
    assert calls == ['login', 'verify']


def test_auth_v2_reauth_requires_verification():
    from crawler.auth_v2 import AuthenticationController
    state = {'verify': 0}
    controller = AuthenticationController(
        login_callback=lambda: True,
        verify_callback=lambda: (state.__setitem__('verify', state['verify'] + 1) or state['verify'] >= 2),
        max_reauths=2,
    )
    assert controller.initial_login() is False
    assert controller.state.exhausted is True


def test_auth_v2_expiry_detection():
    from crawler.auth_v2 import AuthenticationController
    assert AuthenticationController.is_expired(401, 'https://app.test/dashboard')
    assert AuthenticationController.is_expired(302, 'https://app.test/login?next=/dashboard')
    assert not AuthenticationController.is_expired(200, 'https://app.test/dashboard')
