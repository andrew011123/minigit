import os
import stat
from typing import List, Tuple, Set
from .core import hash_object, read_object, ObjectType
from .index import read_index
from .exceptions import GitError


def write_tree() -> str:
    """
    Returns:
        SHA-1 hash of the tree object
    
    Raises:
        GitError: If tree cannot be created
    
    Note:
        Currently only supports flat directory structure (no subdirectories)
    """
    entries = read_index()
    tree_entries = []
    
    for entry in entries:
        if '/' in entry.path:
            raise GitError(
                f"Subdirectories not yet supported: {entry.path}\n"
                "This implementation currently only supports files in the root directory."
            )
        
        mode_path = f'{entry.mode:o} {entry.path}'.encode()
        tree_entry = mode_path + b'\x00' + entry.sha1
        tree_entries.append(tree_entry)
    
    return hash_object(b''.join(tree_entries), ObjectType.TREE)


def read_tree(sha1: str = None, data: bytes = None) -> List[Tuple[int, str, str]]:
    """
    Args:
        sha1: SHA-1 hash of tree object
        data: Raw tree data
    
    Returns:
        List of (mode, path, sha1) tuples
    
    Raises:
        GitError: If tree cannot be read
        TypeError: If neither sha1 nor data provided
    """
    if sha1 is not None:
        obj_type, data = read_object(sha1)
        if obj_type != ObjectType.TREE:
            raise GitError(f"Expected tree object, got {obj_type}")
    elif data is None:
        raise TypeError('Must specify either "sha1" or "data"')
    
    entries = []
    i = 0
    
    while i < len(data):
        end = data.find(b'\x00', i)
        if end == -1:
            break
        
        try:
            mode_str, path = data[i:end].decode().split(' ', 1)
            mode = int(mode_str, 8)  # Mode is in octal
            
            # Next 20 bytes are SHA-1 hash
            if end + 21 > len(data):
                raise GitError("Truncated tree entry")
            
            digest = data[end + 1:end + 21]
            entries.append((mode, path, digest.hex()))
            
            i = end + 21
        except (ValueError, UnicodeDecodeError) as e:
            raise GitError(f"Invalid tree entry at offset {i}: {e}")
    
    return entries


def find_tree_objects(tree_sha1: str) -> Set[str]:
    """
    Args:
        tree_sha1: SHA-1 hash of tree object
    
    Returns:
        Set of SHA-1 hashes (includes tree itself, subtrees, and blobs)
    """
    objects = {tree_sha1}
    
    try:
        for mode, path, sha1 in read_tree(sha1=tree_sha1):
            if stat.S_ISDIR(mode):
                objects.update(find_tree_objects(sha1))
            else:
                objects.add(sha1)
    except GitError:
        pass
    
    return objects


def print_tree(sha1: str, prefix: str = '', show_sha: bool = True):
    """
    Args:
        sha1: SHA-1 hash of tree object
        prefix: Indentation prefix for nested display
        show_sha: Whether to show SHA-1 hashes
    """
    try:
        entries = read_tree(sha1=sha1)
    except GitError as e:
        print(f"{prefix}Error reading tree: {e}")
        return
    
    for mode, path, entry_sha1 in entries:
        if stat.S_ISDIR(mode):
            type_icon = "📁"
            type_str = "tree"
        else:
            type_icon = "📄"
            type_str = "blob"
        
        if show_sha:
            print(f"{prefix}{type_icon} {path} ({type_str} {entry_sha1[:7]})")
        else:
            print(f"{prefix}{type_icon} {path}")
        
        if stat.S_ISDIR(mode):
            print_tree(entry_sha1, prefix + "  ", show_sha)
