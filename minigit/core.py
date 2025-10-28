import hashlib
import os
import zlib
from typing import Tuple, Optional
from .exceptions import GitError, ObjectNotFoundError, InvalidObjectError


class ObjectType:
    COMMIT = 'commit'
    TREE = 'tree'
    BLOB = 'blob'


class GitObject:
    
    def __init__(self, obj_type: str, content: bytes):
        if obj_type not in (ObjectType.COMMIT, ObjectType.TREE, ObjectType.BLOB):
            raise InvalidObjectError(f"Invalid object type: {obj_type}")
        self.obj_type = obj_type
        self.content = content
        self._sha1 = None
    
    @property
    def sha1(self) -> str:
        if self._sha1 is None:
            self._sha1 = hash_object(self.content, self.obj_type, write=False)
        return self._sha1
    
    def __repr__(self):
        return f"GitObject({self.obj_type}, {len(self.content)} bytes, {self.sha1[:7]})"


def hash_object(contents: bytes, obj_type: str, write: bool = True) -> str:
    """
    Args:
        contents: Raw object content
        obj_type: One of 'blob', 'tree', 'commit'
        write: Whether to write to .git/objects
    
    Returns:
        40-character SHA-1 hex string
    
    Raises:
        GitError: If not in a git repository
        InvalidObjectError: If object type is invalid
    """
    if obj_type not in (ObjectType.COMMIT, ObjectType.TREE, ObjectType.BLOB):
        raise InvalidObjectError(f"Invalid object type: {obj_type}")
    
    header = f'{obj_type} {len(contents)}'.encode()
    full_data = header + b'\x00' + contents
    object_id = hashlib.sha1(full_data).hexdigest()
    
    if write:
        if not os.path.exists('.git'):
            raise GitError("Not a git repository (or any of the parent directories)")
        
        path = os.path.join('.git', 'objects', object_id[:2], object_id[2:])
        
        if not os.path.exists(path):
            os.makedirs(os.path.dirname(path), exist_ok=True)
            write_file(path, zlib.compress(full_data))
    
    return object_id


def find_object(sha1_prefix: str) -> str:
    """
    Args:
        sha1_prefix: Partial or full SHA-1 hash
    
    Returns:
        Full path to object file
    
    Raises:
        ValueError: If prefix too short, object not found, or ambiguous
        GitError: If not in a git repository
    """
    if not os.path.exists('.git'):
        raise GitError("Not a git repository")
    
    if len(sha1_prefix) < 2:
        raise ValueError('Hash prefix must be 2 or more characters')
    
    obj_dir = os.path.join('.git', 'objects', sha1_prefix[:2])
    
    if not os.path.exists(obj_dir):
        raise ObjectNotFoundError(f"Object {sha1_prefix!r} not found")
    
    rest = sha1_prefix[2:]
    try:
        objects = [name for name in os.listdir(obj_dir) if name.startswith(rest)]
    except FileNotFoundError:
        raise ObjectNotFoundError(f"Object {sha1_prefix!r} not found")
    
    if not objects:
        raise ObjectNotFoundError(f"Object {sha1_prefix!r} not found")
    
    if len(objects) > 1:
        raise ValueError(
            f'Ambiguous SHA-1 prefix {sha1_prefix!r} matches {len(objects)} objects'
        )
    
    return os.path.join(obj_dir, objects[0])


def read_object(sha1_prefix: str) -> Tuple[str, bytes]:
    """
    Args:
        sha1_prefix: Partial or full SHA-1 hash
    
    Returns:
        Tuple of (object_type, content_bytes)
    
    Raises:
        ObjectNotFoundError: If object not found
        InvalidObjectError: If object format is invalid
    """
    try:
        path = find_object(sha1_prefix)
        full_data = zlib.decompress(read_file(path))
    except (ValueError, OSError) as e:
        raise ObjectNotFoundError(f"Could not read object {sha1_prefix!r}: {e}")
    
    try:
        nul_index = full_data.index(b'\x00')
        header = full_data[:nul_index]
        obj_type, size_str = header.decode().split()
        size = int(size_str)
        data = full_data[nul_index + 1:]
    except (ValueError, UnicodeDecodeError) as e:
        raise InvalidObjectError(f"Invalid object format: {e}")
    
    if size != len(data):
        raise InvalidObjectError(
            f'Object size mismatch: header says {size}, got {len(data)} bytes'
        )
    
    return (obj_type, data)


def get_local_ref(ref_name: str = 'refs/heads/master') -> Optional[str]:
    """
    Args:
        ref_name: Reference name (e.g., 'refs/heads/master')
    
    Returns:
        Commit SHA-1 or None if ref doesn't exist
    """
    ref_path = os.path.join('.git', ref_name)
    try:
        return read_file(ref_path).decode().strip()
    except (FileNotFoundError, GitError):
        return None


def update_ref(ref_name: str, commit_sha1: str):
    ref_path = os.path.join('.git', ref_name)
    os.makedirs(os.path.dirname(ref_path), exist_ok=True)
    write_file(ref_path, (commit_sha1 + '\n').encode())


def read_file(path: str) -> bytes:
    try:
        with open(path, 'rb') as f:
            return f.read()
    except IOError as e:
        raise GitError(f"Could not read file {path!r}: {e}")


def write_file(path: str, data: bytes):
    try:
        with open(path, 'wb') as f:
            f.write(data)
    except IOError as e:
        raise GitError(f"Could not write file {path!r}: {e}")
