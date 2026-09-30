"""The upgraded active parameter prober: differential response analysis,
binary-split attribution, POST-form and POST-JSON injection, and
confidence/evidence scoring. All faked at the session level."""
from discovery.params import ParamProber, discover_parameters, probe_hidden_params


class _Resp:
    def __init__(self, text='', status=200):
        self.text = text
        self.status_code = status


class _Session:
    """Configurable fake. `on_get`/`on_post` receive the injected params dict
    and return (text, status)."""
    def __init__(self, on_get=None, on_post=None):
        self._on_get = on_get
        self._on_post = on_post
        self.get_calls = []
        self.post_calls = []

    def get(self, url, timeout=None, headers=None):
        from urllib.parse import urlparse, parse_qsl
        params = dict(parse_qsl(urlparse(url).query))
        self.get_calls.append(params)
        text, status = (self._on_get or (lambda p: ('base', 200)))(params)
        return _Resp(text, status)

    def post(self, url, data=None, json=None, timeout=None, headers=None):
        params = data if data is not None else (json or {})
        self.post_calls.append({'data': data, 'json': json})
        text, status = (self._on_post or (lambda p: ('base', 200)))(params)
        return _Resp(text, status)


# --- differential analysis: a non-reflecting param that changes the body ---

def test_bisection_attributes_a_nonreflecting_length_effect_to_one_name():
    # 'secret' changes the response length but is never reflected. A pure
    # reflection probe would miss it; differential + bisection must pin it.
    def on_get(params):
        if 'secret' in params:
            return ('base plus extra content here', 200)
        return ('base', 200)
    prober = ParamProber(_Session(on_get=on_get), 'https://x/app', location='query',
                         rate_limit=0.0, sleep=lambda s: None)
    findings = prober.discover(['alpha', 'secret', 'beta', 'gamma'])
    names = {f.name for f in findings}
    assert 'secret' in names
    f = next(f for f in findings if f.name == 'secret')
    assert not f.reflected
    assert any('length' in e for e in f.evidence)
    assert f.confidence in ('medium', 'high')


def test_stable_baseline_with_no_effect_yields_nothing():
    prober = ParamProber(_Session(), 'https://x/', location='query', sleep=lambda s: None)
    assert prober.discover(['a', 'b', 'c']) == []


def test_unstable_baseline_downgrades_a_length_only_signal():
    # Baseline itself jitters by a few bytes; a same-size effect must not be
    # over-claimed. We make the effect exceed jitter but keep it body-only.
    seq = iter([('baseline--', 200), ('baseline', 200)])  # two different baselines

    def on_get(params):
        if 'x' in params:
            return ('baseline plus a clearly larger body than jitter', 200)
        try:
            return next(seq)
        except StopIteration:
            return ('baseline', 200)
    prober = ParamProber(_Session(on_get=on_get), 'https://x/', location='query',
                         sleep=lambda s: None)
    findings = prober.discover(['x'])
    if findings:  # a body-only effect on an unstable baseline is low confidence
        assert findings[0].confidence in ('low', 'medium')


# --- status-change attribution --------------------------------------------

def test_status_change_is_strong_evidence():
    def on_get(params):
        return ('base', 500) if 'boom' in params else ('base', 200)
    findings = ParamProber(_Session(on_get=on_get), 'https://x/', location='query',
                           sleep=lambda s: None).discover(['boom', 'quiet'])
    boom = next(f for f in findings if f.name == 'boom')
    assert any('status' in e for e in boom.evidence)
    assert boom.confidence in ('medium', 'high')


# --- reflection scoring ----------------------------------------------------

def test_reflected_marker_scores_high_confidence():
    def on_get(params):
        body = 'base'
        for v in params.values():
            body += ' ' + v  # reflect every injected value
        return (body, 200)
    findings = ParamProber(_Session(on_get=on_get), 'https://x/', location='query',
                           sleep=lambda s: None).discover(['ref'])
    ref = next(f for f in findings if f.name == 'ref')
    assert ref.reflected and ref.confidence == 'high' and ref.score >= 0.6


# --- POST-form and POST-JSON injection ------------------------------------

def test_post_form_injection_uses_data_body():
    def on_post(params):
        return ('base echo=' + params['token'], 200) if 'token' in params else ('base', 200)
    session = _Session(on_post=on_post)
    findings = discover_parameters(session, 'https://x/submit', ['token', 'nope'],
                                   locations=['post-form'], sleep=lambda s: None)
    assert any(f.name == 'token' and f.location == 'post-form' for f in findings)
    # It went through POST with a form body, not the query string.
    assert session.post_calls and session.post_calls[0]['data'] is not None
    assert not session.get_calls


def test_post_json_injection_uses_json_body():
    def on_post(params):
        return ('base ' + params.get('flag', ''), 200) if 'flag' in params else ('base', 200)
    session = _Session(on_post=on_post)
    findings = discover_parameters(session, 'https://x/api', ['flag'],
                                   locations=['post-json'], sleep=lambda s: None)
    assert any(f.name == 'flag' and f.location == 'post-json' for f in findings)
    assert session.post_calls and session.post_calls[0]['json'] is not None


def test_discover_parameters_runs_multiple_locations():
    def on_get(p):
        return ('base ' + p.get('g', ''), 200) if 'g' in p else ('base', 200)
    def on_post(p):
        return ('base ' + p.get('g', ''), 200) if 'g' in p else ('base', 200)
    session = _Session(on_get=on_get, on_post=on_post)
    findings = discover_parameters(session, 'https://x/', ['g'],
                                   locations=['query', 'post-form'], sleep=lambda s: None)
    locs = {f.location for f in findings if f.name == 'g'}
    assert locs == {'query', 'post-form'}


def test_probe_respects_request_budget():
    prober = ParamProber(_Session(), 'https://x/', location='query',
                         max_requests=1, sleep=lambda s: None)
    # Budget of 1 is exhausted by the first baseline sample -> no crash, no findings.
    assert prober.discover(['a', 'b']) == []


def test_probe_hidden_params_wrapper_still_returns_findings():
    def on_get(params):
        return ('base ' + ' '.join(params.values()), 200)
    out = probe_hidden_params(_Session(on_get=on_get), 'https://x/', ['a'], sleep=lambda s: None)
    assert out and out[0].name == 'a' and out[0].reflected
