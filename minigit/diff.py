import difflib
from typing import List, Tuple
from .core import read_object, read_file, ObjectType
from .index import read_index, get_status
from .exceptions import GitError


def diff_files(path1: str, content1: bytes, path2: str, content2: bytes,
               context_lines: int = 3) -> List[str]:
    """
    Args:
        path1: Name/path for first file
        content1: Content of first file
        path2: Name/path for second file  
        content2: Content of second file
        context_lines: Number of context lines around changes
    
    Returns:
        List of diff lines
    """
    try:
        lines1 = content1.decode('utf-8').splitlines(keepends=False)
        lines2 = content2.decode('utf-8').splitlines(keepends=False)
    except UnicodeDecodeError:
        return [f"Binary files {path1} and {path2} differ"]
    
    diff = difflib.unified_diff(
        lines1, lines2,
        fromfile=path1,
        tofile=path2,
        lineterm='',
        n=context_lines
    )
    
    return list(diff)


def diff_index_working(paths: List[str] = None) -> List[Tuple[str, List[str]]]:
    """
    Args:
        paths: Specific paths to diff (all changed files if None)
    
    Returns:
        List of (path, diff_lines) tuples
    """
    changed, _, _ = get_status()
    
    if paths:
        changed = [p for p in changed if p in paths]
    
    if not changed:
        return []
    
    entries_by_path = {e.path: e for e in read_index()}
    diffs = []
    
    for path in changed:
        if path not in entries_by_path:
            continue
        
        sha1 = entries_by_path[path].sha1.hex()
        try:
            obj_type, indexed_data = read_object(sha1)
            if obj_type != ObjectType.BLOB:
                continue
        except Exception:
            continue
        
        try:
            working_data = read_file(path)
        except Exception:
            continue
        
        diff_lines = diff_files(
            f"{path} (index)",
            indexed_data,
            f"{path} (working copy)",
            working_data
        )
        
        if diff_lines:
            diffs.append((path, diff_lines))
    
    return diffs


def print_diff(context_lines: int = 3):
    """
    Args:
        context_lines: Number of context lines around changes
    """
    diffs = diff_index_working()
    
    if not diffs:
        print("No changes to show.")
        return
    
    for i, (path, diff_lines) in enumerate(diffs):
        if i > 0:
            print("-" * 70)
        
        for line in diff_lines:
            if line.startswith('+++') or line.startswith('---'):
                print(f"\033[1m{line}\033[0m")
            elif line.startswith('+'):
                print(f"\033[32m{line}\033[0m")
            elif line.startswith('-'):
                print(f"\033[31m{line}\033[0m")
            elif line.startswith('@@'):
                print(f"\033[36m{line}\033[0m")
            else:
                print(line)


def diff_commits(commit1: str, commit2: str) -> List[Tuple[str, str, List[str]]]:
    """
    Args:
        commit1: First commit SHA-1
        commit2: Second commit SHA-1
    
    Returns:
        List of (path, status, diff_lines) tuples
        Status can be: 'modified', 'added', 'deleted'
    """
    # This would require tree comparison which is complex
    # For now, return a placeholder
    raise NotImplementedError(
        "Commit-to-commit diff not yet implemented. "
        "Use diff_index_working() for working directory changes."
    )


def get_diff_stats() -> dict:
    """
    Returns:
        Dictionary with 'files_changed', 'insertions', 'deletions'
    """
    diffs = diff_index_working()
    
    stats = {
        'files_changed': len(diffs),
        'insertions': 0,
        'deletions': 0
    }
    
    for _, diff_lines in diffs:
        for line in diff_lines:
            if line.startswith('+') and not line.startswith('+++'):
                stats['insertions'] += 1
            elif line.startswith('-') and not line.startswith('---'):
                stats['deletions'] += 1

    return stats
