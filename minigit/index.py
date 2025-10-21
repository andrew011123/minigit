import hashlib
import os
import operator
import struct
from collections import namedtuple
from typing import List, Set, Tuple
from .core import hash_object, read_file, write_file, ObjectType
from .exceptions import IndexError as GitIndexError


IndexEntry = namedtuple('IndexEntry', [
    'ctime_s', 'ctime_n',   # Creation time (seconds, nanoseconds)
    'mtime_s', 'mtime_n',   # Modification time (seconds, nanoseconds)
    'dev', 'ino',            # Device and inode numbers
    'mode', 'uid', 'gid',    # Permissions, user ID, group ID
    'size',                  # File size in bytes
    'sha1',                  # SHA-1 hash of content
    'flags',                 # Metadata flags
    'path',                  # File path
])


def read_index() -> List[IndexEntry]:
    """
    Returns:
        List of IndexEntry objects, sorted by path
    
    Raises:
        GitIndexError: If index file doesn't exist or is corrupted
    """
    index_path = os.path.join('.git', 'index')
    
    try:
        data = read_file(index_path)
    except FileNotFoundError:
        return []
    except Exception as e:
        raise GitIndexError(f"Could not read index file: {e}")
    
    if len(data) < 20:
        raise GitIndexError("Index file too short")
    
    digest = hashlib.sha1(data[:-20]).digest()
    if digest != data[-20:]:
        raise GitIndexError("Index checksum mismatch - file may be corrupted")
    
    if len(data) < 12:
        raise GitIndexError("Index file header too short")
    
    try:
        signature, version, num_entries = struct.unpack('!4sLL', data[:12])
    except struct.error as e:
        raise GitIndexError(f"Could not parse index header: {e}")
    
    if signature != b'DIRC':
        raise GitIndexError(f"Invalid index signature: {signature!r}")
    
    if version != 2:
        raise GitIndexError(f"Unsupported index version: {version}")

    entry_data = data[12:-20]
    entries = []
    i = 0
    
    while i + 62 < len(entry_data):
        try:
            fields_end = i + 62
            fields = struct.unpack('!LLLLLLLLLL20sH', entry_data[i:fields_end])
            
            path_end = entry_data.index(b'\x00', fields_end)
            path = entry_data[fields_end:path_end]
            
            entry = IndexEntry(*(fields + (path.decode(),)))
            entries.append(entry)
            
            entry_len = ((62 + len(path) + 8) // 8) * 8
            i += entry_len
            
        except (struct.error, ValueError, UnicodeDecodeError) as e:
            raise GitIndexError(f"Could not parse index entry at offset {i}: {e}")
    
    if len(entries) != num_entries:
        raise GitIndexError(
            f"Entry count mismatch: header says {num_entries}, parsed {len(entries)}"
        )
    
    return entries

def _normalize_stat_value(value, max_value=0xFFFFFFFF):
    """
    Normalize stat values to fit in unsigned 32-bit integer.
    
    Windows can return values that don't fit or aren't meaningful.
    We clamp them to valid range.
    """
    if value is None or value < 0:
        return 0
    if value > max_value:
        return value & max_value
    return value

def write_index(entries: List[IndexEntry]):
    """
    Args:
        entries: List of index entries (will be sorted by path)
    
    Raises:
        GitIndexError: If writing fails
    """
    sorted_entries = sorted(entries, key=operator.attrgetter('path'))
    
    packed_entries = []
    for entry in sorted_entries:
        try:
            entry_head = struct.pack(
                '!LLLLLLLLLL20sH',
                _normalize_stat_value(entry.ctime_s),
                _normalize_stat_value(entry.ctime_n),
                _normalize_stat_value(entry.mtime_s),
                _normalize_stat_value(entry.mtime_n),
                _normalize_stat_value(entry.dev),
                _normalize_stat_value(entry.ino),
                _normalize_stat_value(entry.mode),
                _normalize_stat_value(entry.uid),
                _normalize_stat_value(entry.gid),
                _normalize_stat_value(entry.size),
                entry.sha1,
                entry.flags
            )
            
            path = entry.path.encode()
            length = ((62 + len(path) + 8) // 8) * 8
            packed_entry = entry_head + path + b'\x00' * (length - 62 - len(path))
            packed_entries.append(packed_entry)
            
        except (struct.error, UnicodeEncodeError) as e:
            raise GitIndexError(f"Could not pack index entry {entry.path!r}: {e}")
    
    header = struct.pack('!4sLL', b'DIRC', 2, len(sorted_entries))
    all_data = header + b''.join(packed_entries)
    digest = hashlib.sha1(all_data).digest()
    
    try:
        write_file(os.path.join('.git', 'index'), all_data + digest)
    except Exception as e:
        raise GitIndexError(f"Could not write index file: {e}")



def add_files(paths: List[str]):
    """
    Args:
        paths: List of file paths to add
    
    Raises:
        GitIndexError: If file cannot be read or added
    """
    paths = [p.replace('\\', '/') for p in paths]
    
    try:
        all_entries = read_index()
    except GitIndexError:
        all_entries = []
    
    entries = [e for e in all_entries if e.path not in paths]
    
    for path in paths:
        if not os.path.exists(path):
            raise GitIndexError(f"File not found: {path}")
        
        if os.path.isdir(path):
            raise GitIndexError(f"Cannot add directory directly: {path}")
        
        try:
            sha1 = hash_object(read_file(path), ObjectType.BLOB)
            
            st = os.stat(path)
            flags = len(path.encode())
            
            if flags >= (1 << 12):
                raise GitIndexError(f"Path too long: {path}")
            
            entry = IndexEntry(
                int(st.st_ctime), 0,  # ctime
                int(st.st_mtime), 0,  # mtime
                st.st_dev, st.st_ino,
                st.st_mode, st.st_uid, st.st_gid,
                st.st_size,
                bytes.fromhex(sha1),
                flags,
                path
            )
            entries.append(entry)
            
        except Exception as e:
            raise GitIndexError(f"Could not add {path!r}: {e}")
    
    write_index(entries)


def get_status() -> Tuple[List[str], List[str], List[str]]:
    """
    Returns:
        Tuple of (changed_paths, new_paths, deleted_paths)
    """
    paths = set()
    for root, dirs, files in os.walk('.'):
        dirs[:] = [d for d in dirs if d != '.git']
        
        for file in files:
            path = os.path.join(root, file)
            # Normalize path
            path = path.replace('\\', '/').lstrip('./')
            paths.add(path)
    
    try:
        entries = read_index()
    except GitIndexError:
        entries = []
    
    entries_by_path = {e.path: e for e in entries}
    entry_paths = set(entries_by_path)
    
    changed = {
        p for p in (paths & entry_paths)
        if hash_object(read_file(p), ObjectType.BLOB, write=False) !=
           entries_by_path[p].sha1.hex()
    }
    
    new = paths - entry_paths
    
    deleted = entry_paths - paths
    
    return (sorted(changed), sorted(new), sorted(deleted))


def list_files(details: bool = False) -> List[str]:
    """
    Args:
        details: If True, include mode, SHA-1, and stage number
    
    Returns:
        List of formatted file information strings
    """
    try:
        entries = read_index()
    except GitIndexError:
        return []
    
    results = []
    for entry in entries:
        if details:
            stage = (entry.flags >> 12) & 3
            results.append(
                f'{entry.mode:06o} {entry.sha1.hex()} {stage}\t{entry.path}'
            )
        else:
            results.append(entry.path)
    
    return results
