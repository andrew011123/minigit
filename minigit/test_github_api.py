import json
import urllib.request
import pytest

from minigit.github_api import create_github_repo
from minigit.exceptions import AuthenticationError, NetworkError


class _FakeResponse:
    def __init__(self, data: bytes):
        self._data = data

    def read(self):
        return self._data


class _FakeOpener:
    def __init__(self, resp: bytes = None, exc: Exception = None):
        self._resp = resp
        self._exc = exc

    def open(self, req, data=None):
        if self._exc:
            raise self._exc
        return _FakeResponse(self._resp)


def test_create_repo_success(monkeypatch):
    expected_url = 'https://github.com/me/newrepo.git'
    body = json.dumps({'clone_url': expected_url}).encode('utf-8')

    opener = _FakeOpener(resp=body)
    monkeypatch.setattr(urllib.request, 'build_opener', lambda *args, **kwargs: opener)

    clone = create_github_repo('newrepo', username='me', token='tok')
    assert clone == expected_url


def test_create_repo_unauthorized(monkeypatch):
    err = urllib.request.HTTPError('url', 401, 'Unauthorized', hdrs=None, fp=None)
    opener = _FakeOpener(exc=err)
    monkeypatch.setattr(urllib.request, 'build_opener', lambda *args, **kwargs: opener)

    with pytest.raises(AuthenticationError):
        create_github_repo('newrepo', username='me', token='bad')


def test_create_repo_validation_error(monkeypatch):
    err = urllib.request.HTTPError('url', 422, 'Unprocessable Entity', hdrs=None, fp=None)
    opener = _FakeOpener(exc=err)
    monkeypatch.setattr(urllib.request, 'build_opener', lambda *args, **kwargs: opener)

    with pytest.raises(NetworkError):
        create_github_repo('existing-repo', username='me', token='tok')
