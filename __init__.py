__version__ = '1.0.0'
__author__ = 'Andrew Johnson'

from .core import hash_object, read_object, ObjectType
from .repository import init_repository, is_repository
from .index import add_files, get_status
from .commit import create_commit, get_commit_history
from .exceptions import GitError

__all__ = [
    'hash_object',
    'read_object',
    'ObjectType',
    'init_repository',
    'is_repository',
    'add_files',
    'get_status',
    'create_commit',
    'get_commit_history',
    'GitError',
]
