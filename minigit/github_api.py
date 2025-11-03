import json
import urllib.request
from typing import Optional

from .exceptions import NetworkError, AuthenticationError


def create_github_repo(repo_name: str, username: Optional[str] = None, token: Optional[str] = None) -> str:
    """
    Create a GitHub repository for the authenticated user.

    Args:
        repo_name: Name of the repository to create
        username: Optional username (used if token is not provided for basic auth)
        token: Personal access token (preferred) or password for basic auth

    Returns:
        Clone URL (https://...git)

    Raises:
        AuthenticationError: If authentication fails (401/403)
        NetworkError: For other HTTP/network errors
    """
    url = 'https://api.github.com/user/repos'
    data = json.dumps({'name': repo_name}).encode('utf-8')

    headers = {
        'Content-Type': 'application/json',
        'Accept': 'application/vnd.github.v3+json',
    }

    if token:
        headers['Authorization'] = f'token {token}'

    req = urllib.request.Request(url, data=data, headers=headers)

    try:
        if token and not username:
            opener = urllib.request.build_opener()
        else:
            password_manager = urllib.request.HTTPPasswordMgrWithDefaultRealm()
            password_manager.add_password(None, url, username or '', token or '')
            auth_handler = urllib.request.HTTPBasicAuthHandler(password_manager)
            opener = urllib.request.build_opener(auth_handler)

        response = opener.open(req)
        body = response.read()
        parsed = json.loads(body.decode())

        clone_url = parsed.get('clone_url')
        if not clone_url:
            raise NetworkError('GitHub response missing clone_url')

        return clone_url

    except urllib.request.HTTPError as e:
        if e.code in (401, 403):
            raise AuthenticationError(f"Authentication failed: {e}")
        elif e.code == 422:
            raise NetworkError(f"GitHub API validation error: {e}")
        else:
            raise NetworkError(f"HTTP error {e.code}: {e}")
    except urllib.request.URLError as e:
        raise NetworkError(f"Network error: {e}")
    except Exception as e:
        raise NetworkError(f"Request failed: {e}")
