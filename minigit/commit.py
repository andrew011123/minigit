import os
import time
from typing import Optional, Set, List, Dict
from .core import hash_object, read_object, get_local_ref, update_ref, ObjectType
from .tree import write_tree, find_tree_objects
from .exceptions import GitError


def create_commit(message: str, author: Optional[str] = None, parent: Optional[str] = None, tree: Optional[str] = None) -> str:
    """
    Args:
        message: Commit message
        author: Author string in format "Name <email>" (uses env vars if None)
        parent: Parent commit SHA-1 (uses current HEAD if None)
        tree: Tree SHA-1 (creates from index if None)
    
    Returns:
        SHA-1 hash of the commit object
    
    Raises:
        GitError: If commit cannot be created
    """
    if tree is None:
        tree = write_tree()
    
    if parent is None:
        parent = get_local_ref('refs/heads/master')
    
    if author is None:
        try:
            name = os.environ['GIT_AUTHOR_NAME']
            email = os.environ['GIT_AUTHOR_EMAIL']
            author = f'{name} <{email}>'
        except KeyError:
            raise GitError(
                "Author not specified and GIT_AUTHOR_NAME/GIT_AUTHOR_EMAIL "
                "environment variables not set"
            )
    
    timestamp = int(time.time())
    utc_offset = -time.timezone
    author_time = '{} {}{:02}{:02}'.format(
        timestamp,
        '+' if utc_offset >= 0 else '-',
        abs(utc_offset) // 3600,
        (abs(utc_offset) // 60) % 60
    )
    
    lines = [f'tree {tree}']
    
    if parent:
        lines.append(f'parent {parent}')
    
    lines.append(f'author {author} {author_time}')
    lines.append(f'committer {author} {author_time}')
    lines.append('')
    lines.append(message)
    lines.append('')
    
    data = '\n'.join(lines).encode()
    sha1 = hash_object(data, ObjectType.COMMIT)
    
    update_ref('refs/heads/master', sha1)
    
    return sha1


def read_commit(sha1: str) -> Dict[str, any]:
    """
    Args:
        sha1: Commit SHA-1 hash
    
    Returns:
        Dictionary with keys: tree, parents, author, committer, message
    
    Raises:
        GitError: If commit cannot be read or parsed
    """
    obj_type, data = read_object(sha1)
    
    if obj_type != ObjectType.COMMIT:
        raise GitError(f"Expected commit object, got {obj_type}")
    
    lines = data.decode().split('\n')
    
    commit_info = {
        'tree': None,
        'parents': [],
        'author': None,
        'committer': None,
        'message': ''
    }
    
    i = 0
    while i < len(lines) and lines[i]:
        line = lines[i]
        
        if line.startswith('tree '):
            commit_info['tree'] = line[5:]
        elif line.startswith('parent '):
            commit_info['parents'].append(line[7:])
        elif line.startswith('author '):
            commit_info['author'] = line[7:]
        elif line.startswith('committer '):
            commit_info['committer'] = line[10:]
        
        i += 1
    
    if i < len(lines):
        commit_info['message'] = '\n'.join(lines[i + 1:]).strip()
    
    return commit_info


def find_commit_objects(commit_sha1: str) -> Set[str]:
    """
    Args:
        commit_sha1: SHA-1 hash of commit
    
    Returns:
        Set of SHA-1 hashes (commit, tree, blobs, parent commits)
    """
    objects = {commit_sha1}
    
    try:
        commit_info = read_commit(commit_sha1)
        
        if commit_info['tree']:
            objects.update(find_tree_objects(commit_info['tree']))
        
        for parent in commit_info['parents']:
            objects.update(find_commit_objects(parent))
            
    except GitError:
        pass
    
    return objects


def get_commit_history(start_commit: Optional[str] = None, 
                       max_count: Optional[int] = None) -> List[Dict]:
    """
    Args:
        start_commit: Starting commit SHA-1 (uses HEAD if None)
        max_count: Maximum number of commits to return
    
    Returns:
        List of commit info dictionaries, newest first
    """
    if start_commit is None:
        start_commit = get_local_ref('refs/heads/master')
    
    if start_commit is None:
        return []
    
    history = []
    visited = set()
    to_visit = [start_commit]
    
    while to_visit and (max_count is None or len(history) < max_count):
        commit_sha1 = to_visit.pop(0)
        
        if commit_sha1 in visited:
            continue
        
        visited.add(commit_sha1)
        
        try:
            commit_info = read_commit(commit_sha1)
            commit_info['sha1'] = commit_sha1
            history.append(commit_info)
            
            to_visit.extend(commit_info['parents'])
            
        except GitError:
            continue
    
    return history


def visualize_commit_history(max_count: int = 20):
    """
    Args:
        max_count: Maximum number of commits to show
    """
    history = get_commit_history(max_count=max_count)
    
    if not history:
        print("No commits yet.")
        return
    
    print("\nCommit History:")
    print("=" * 70)
    
    for i, commit in enumerate(history):
        sha1 = commit['sha1']
        message = commit['message'].split('\n')[0] 
        author = commit['author'].split()[0] if commit['author'] else 'Unknown'
        
        if i == 0:
            connector = "* "
        else:
            connector = "│\n* "
        
        print(f"{connector}commit {sha1[:7]} ({author})")
        print(f"  {message}")
        
        if i < len(history) - 1:
            print("  │")
    
    print("=" * 70)
