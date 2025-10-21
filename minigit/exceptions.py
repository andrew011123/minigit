class GitError(Exception):
    """Base exception for all Git-related errors."""
    pass


class RepositoryError(GitError):
    """Repository initialization or structure errors."""
    pass


class ObjectNotFoundError(GitError):
    """Raised when a Git object cannot be found."""
    pass


class InvalidObjectError(GitError):
    """Raised when a Git object has invalid format or type."""
    pass


class IndexError(GitError):
    """Errors related to reading or writing the index."""
    pass


class MergeConflictError(GitError):
    """Raised when a merge conflict occurs."""
    pass


class NetworkError(GitError):
    """Errors during network operations (push/fetch)."""
    pass


class AuthenticationError(NetworkError):
    """Authentication failed during network operations."""
    pass
