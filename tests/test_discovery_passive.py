import requests

from discovery.passive import discover_passive_subdomains


class _FakeResponse:
    def __init__(self, payload, status_code=200):
        self._payload = payload
        self.status_code = status_code

    def raise_for_status(self):
        if self.status_code >= 400:
            raise requests.HTTPError(f'{self.status_code} error')

    def json(self):
        return self._payload


def test_extracts_and_normalizes_names(monkeypatch):
    payload = [
        {'name_value': 'WWW.example.com\napi.example.com'},
        {'name_value': '*.staging.example.com'},
    ]
    monkeypatch.setattr(requests, 'get', lambda *a, **k: _FakeResponse(payload))

    result = discover_passive_subdomains('example.com')

    assert result == sorted({'www.example.com', 'api.example.com', 'staging.example.com'})


def test_deduplicates_and_sorts_results(monkeypatch):
    payload = [
        {'name_value': 'b.example.com\na.example.com'},
        {'name_value': 'a.example.com'},
    ]
    monkeypatch.setattr(requests, 'get', lambda *a, **k: _FakeResponse(payload))

    result = discover_passive_subdomains('example.com')

    assert result == ['a.example.com', 'b.example.com']


def test_filters_out_unrelated_domains(monkeypatch):
    payload = [{'name_value': 'sub.example.com\nsub.other-domain.com'}]
    monkeypatch.setattr(requests, 'get', lambda *a, **k: _FakeResponse(payload))

    result = discover_passive_subdomains('example.com')

    assert result == ['sub.example.com']


def test_includes_apex_domain_when_present(monkeypatch):
    payload = [{'name_value': 'example.com'}]
    monkeypatch.setattr(requests, 'get', lambda *a, **k: _FakeResponse(payload))

    result = discover_passive_subdomains('example.com')

    assert result == ['example.com']


def test_raises_on_http_error(monkeypatch):
    monkeypatch.setattr(requests, 'get', lambda *a, **k: _FakeResponse([], status_code=500))

    try:
        discover_passive_subdomains('example.com')
        assert False, 'expected HTTPError to be raised'
    except requests.HTTPError:
        pass
