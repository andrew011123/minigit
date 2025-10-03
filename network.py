import hashlib
import os
import struct
import urllib.request
import zlib
from typing import Set, Tuple, Optional
from .core import read_object, get_local_ref, ObjectType
from .commit import find_commit_objects
from .exceptions import NetworkError, AuthenticationError


class ObjectTypeNum:
    COMMIT = 1
    TREE = 2
    BLOB = 3


def extract_lines(data: bytes) -> list:
    """
    Args:
        data: Raw response data
    
    Returns:
        List of line contents (bytes)
    """
    lines = []
    i = 0
    
    for _ in range(10000):
        if i >= len(data):
            break
        
        if i + 4 > len(data):
            break
        
        try:
            line_length = int(data[i:i + 4], 16)
        except ValueError:
            break
        
        if line_length == 0:
            i += 4
            lines.append(b'')
        else:
            if i + line_length > len(data):
                break
            
            line = data[i + 4:i + line_length]
            lines.append(line)
            i += line_length
    
    return lines


def build_lines_data(lines: list) -> bytes:
    """
    Args:
        lines: List of line contents (bytes)
    
    Returns:
        Formatted data ready to send
    """
    result = []
    
    for line in lines:
        length = len(line) + 5
        result.append(f'{length:04x}'.encode())
        result.append(line)
        result.append(b'\n')
    
    result.append(b'0000')
    
    return b''.join(result)


def http_request(url: str, username: str, password: str, data: Optional[bytes] = None) -> bytes:
    """
    Args:
        url: Full URL to request
        username: Basic auth username
        password: Basic auth password
        data: POST data (GET request if None)
    
    Returns:
        Response body
    
    Raises:
        AuthenticationError: If authentication fails
        NetworkError: If request fails
    """
    try:
        password_manager = urllib.request.HTTPPasswordMgrWithDefaultRealm()
        password_manager.add_password(None, url, username, password)
        auth_handler = urllib.request.HTTPBasicAuthHandler(password_manager)
        opener = urllib.request.build_opener(auth_handler)
        
        response = opener.open(url, data=data)
        return response.read()
        
    except urllib.request.HTTPError as e:
        if e.code == 401 or e.code == 403:
            raise AuthenticationError(f"Authentication failed: {e}")
        raise NetworkError(f"HTTP error {e.code}: {e}")
    except urllib.request.URLError as e:
        raise NetworkError(f"Network error: {e}")
    except Exception as e:
        raise NetworkError(f"Request failed: {e}")


def get_remote_ref(git_url: str, username: str, password: str,
                   ref: str = 'refs/heads/master') -> Optional[str]:
    """
    Args:
        git_url: Git repository URL (e.g., https://github.com/user/repo.git)
        username: Authentication username
        password: Authentication password
        ref: Reference name (default: refs/heads/master)
    
    Returns:
        Commit SHA-1 or None if ref doesn't exist
    
    Raises:
        NetworkError: If request fails
    """
    url = f'{git_url}/info/refs?service=git-receive-pack'
    response = http_request(url, username, password)
    lines = extract_lines(response)
    
    if not lines or lines[0] != b'# service=git-receive-pack\n':
        raise NetworkError("Invalid server response")
    
    if len(lines) < 2 or lines[1] != b'':
        raise NetworkError("Invalid server response format")
    
    if len(lines) >= 3 and lines[2][:40] == b'0' * 40:
        return None
    
    for line in lines[2:]:
        if not line:
            continue
        
        parts = line.split(b'\x00')[0].split()
        if len(parts) >= 2:
            sha1, ref_name = parts[0], parts[1]
            if ref_name.decode() == ref and len(sha1) == 40:
                return sha1.decode()
    
    return None


def find_missing_objects(local_sha1: str, remote_sha1: Optional[str]) -> Set[str]:
    """
    Args:
        local_sha1: Local commit SHA-1
        remote_sha1: Remote commit SHA-1 (None if remote is empty)
    
    Returns:
        Set of SHA-1 hashes of missing objects
    """
    local_objects = find_commit_objects(local_sha1)
    
    if remote_sha1 is None:
        return local_objects
    
    remote_objects = find_commit_objects(remote_sha1)
    return local_objects - remote_objects


def encode_pack_object(sha1: str) -> bytes:
    """
    Args:
        sha1: Object SHA-1 hash
    
    Returns:
        Encoded object bytes
    """
    obj_type, data = read_object(sha1)
    
    type_map = {
        ObjectType.COMMIT: ObjectTypeNum.COMMIT,
        ObjectType.TREE: ObjectTypeNum.TREE,
        ObjectType.BLOB: ObjectTypeNum.BLOB,
    }
    type_num = type_map.get(obj_type)
    
    if type_num is None:
        raise NetworkError(f"Unknown object type: {obj_type}")
    
    size = len(data)
    
    byte = (type_num << 4) | (size & 0x0f)
    size >>= 4
    
    header = []
    while size:
        header.append(byte | 0x80)
        byte = size & 0x7f
        size >>= 7
    
    header.append(byte)
    
    compressed = zlib.compress(data)
    
    return bytes(header) + compressed


def create_pack(objects: Set[str]) -> bytes:
    """
    Args:
        objects: Set of object SHA-1 hashes
    
    Returns:
        Complete pack file data
    """
    header = struct.pack('!4sLL', b'PACK', 2, len(objects))
    
    body = b''.join(encode_pack_object(obj) for obj in sorted(objects))
    
    contents = header + body
    checksum = hashlib.sha1(contents).digest()
    
    return contents + checksum


def push(git_url: str, username: Optional[str] = None, 
         password: Optional[str] = None, ref: str = 'refs/heads/master') -> Tuple[Optional[str], Set[str]]:
    """
    Args:
        git_url: Git repository URL
        username: Authentication username (uses GIT_USERNAME env var if None)
        password: Authentication password (uses GIT_PASSWORD env var if None)
        ref: Reference to push (default: refs/heads/master)
    
    Returns:
        Tuple of (old_remote_sha1, pushed_objects)
    
    Raises:
        NetworkError: If push fails
        AuthenticationError: If authentication fails
    """
    if username is None:
        username = os.environ.get('GIT_USERNAME')
        if not username:
            raise NetworkError("Username not provided and GIT_USERNAME not set")
    
    if password is None:
        password = os.environ.get('GIT_PASSWORD')
        if not password:
            raise NetworkError("Password not provided and GIT_PASSWORD not set")
    
    remote_sha1 = get_remote_ref(git_url, username, password, ref)
    local_sha1 = get_local_ref(ref)
    
    if local_sha1 is None:
        raise NetworkError(f"Local ref {ref} does not exist")
    
    missing = find_missing_objects(local_sha1, remote_sha1)
    
    print(f'Pushing to {git_url}')
    print(f'Updating {ref}: {remote_sha1 or "no commits"} -> {local_sha1}')
    print(f'Sending {len(missing)} object{"s" if len(missing) != 1 else ""}')
    
    command = f'{remote_sha1 or ("0" * 40)} {local_sha1} {ref}\x00 report-status'
    lines = [command.encode()]
    request_data = build_lines_data(lines) + create_pack(missing)
    
    url = f'{git_url}/git-receive-pack'
    response = http_request(url, username, password, data=request_data)
    
    lines = extract_lines(response)
    
    if len(lines) < 2:
        raise NetworkError(f"Invalid server response: expected at least 2 lines, got {len(lines)}")
    
    if lines[0] != b'unpack ok\n':
        raise NetworkError(f"Server rejected pack: {lines[0].decode()}")
    
    expected_ok = f'ok {ref}\n'.encode()
    if lines[1] != expected_ok:
        raise NetworkError(f"Server rejected ref update: {lines[1].decode()}")
    
    print("Push successful!")
    
    return (remote_sha1, missing)
