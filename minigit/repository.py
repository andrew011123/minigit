import os
from .core import write_file
from .exceptions import RepositoryError


def init_repository(path: str = '.'):
    """
    Args:
        path: Directory to initialize repository in
    
    Raises:
        RepositoryError: If repository already exists or cannot be created
    """
    if path != '.' and not os.path.exists(path):
        try:
            os.makedirs(path)
        except OSError as e:
            raise RepositoryError(f"Could not create directory {path}: {e}")
    
    git_dir = os.path.join(path, '.git')
    
    if os.path.exists(git_dir):
        raise RepositoryError(f"Repository already exists at {git_dir}")
    
    try:
        os.mkdir(git_dir)
        
        for subdir in ['objects', 'refs', 'refs/heads', 'refs/tags']:
            os.makedirs(os.path.join(git_dir, subdir), exist_ok=True)
        
        head_path = os.path.join(git_dir, 'HEAD')
        write_file(head_path, b'ref: refs/heads/master')
        
        config_path = os.path.join(git_dir, 'config')
        config_content = b"""[core]
	repositoryformatversion = 0
	filemode = true
	bare = false
"""
        write_file(config_path, config_content)
        
        print(f'Initialized empty Git repository in {os.path.abspath(git_dir)}')
        
    except OSError as e:
        raise RepositoryError(f"Could not create repository structure: {e}")


def is_repository(path: str = '.') -> bool:
    """
    Args:
        path: Directory to check
    
    Returns:
        True if directory contains a .git folder
    """
    git_dir = os.path.join(path, '.git')
    return os.path.isdir(git_dir)


def find_repository_root(start_path: str = '.') -> str:
    """
    Args:
        start_path: Directory to start search from
    
    Returns:
        Absolute path to repository root
    
    Raises:
        RepositoryError: If not inside a Git repository
    """
    current = os.path.abspath(start_path)
    
    while True:
        if is_repository(current):
            return current
        
        parent = os.path.dirname(current)
        
        # Reached root of filesystem
        if parent == current:
            raise RepositoryError(
                "Not a git repository (or any of the parent directories): .git"
            )
        
        current = parent


def get_repository_info(path: str = '.') -> dict:
    """
    Args:
        path: Repository path
    
    Returns:
        Dictionary with repository information
    """
    if not is_repository(path):
        raise RepositoryError(f"Not a Git repository: {path}")
    
    git_dir = os.path.join(path, '.git')
    
    info = {
        'path': os.path.abspath(path),
        'git_dir': os.path.abspath(git_dir),
        'is_bare': False,
    }
    
    objects_dir = os.path.join(git_dir, 'objects')
    object_count = 0
    
    if os.path.exists(objects_dir):
        for subdir in os.listdir(objects_dir):
            subdir_path = os.path.join(objects_dir, subdir)
            if os.path.isdir(subdir_path) and len(subdir) == 2:
                object_count += len(os.listdir(subdir_path))
    
    info['object_count'] = object_count
    
    head_path = os.path.join(git_dir, 'HEAD')
    if os.path.exists(head_path):
        try:
            with open(head_path, 'r') as f:
                head_content = f.read().strip()
            
            if head_content.startswith('ref: '):
                info['current_branch'] = head_content[5:]
            else:
                info['current_branch'] = 'detached HEAD'
        except:
            info['current_branch'] = 'unknown'
    
    return info
