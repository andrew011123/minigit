IndexEntry = collections.namedtuple('IndexEntry', ['ctime_s', 'ctime_n', 'mtime_s', 'mtime_n', 'dev', 'ino', 'mode', 'uid', 'gid', 'size', 'sha1', 'flags', 'path',])

def init(repo):
  os.mkdir(repo)
  gitdir = os.path.join(repo, '.git')
  try:
      os.mkdir(gitdir)
  except FileExistsError:
      raise RuntimeError(f"Repository already exists at {gitdir}")
  for name in ['objects', 'refs', 'refs/heads']:
      os.mkdir(os.path.join(repo, '.git', name))
  write_file(os.path.join(repo, '.git', 'HEAD'), b'ref: refs/heads/master')
  print('Initialized empty repository: {}'.format(repo))

def hash_object(contents, type, write=True):
  header = '{type} {len(contents)}'.encode()
  full_data = b"\x00".join([header, contents])
  object_ID = hashlib.sha1(full_data).hexdigest()
  if write:
    path = os.path.join('.git', 'objects', object_ID[:2], object_ID[2:])
    if not os.path.exists(path):
      os.makedirs(os.path.dirname(path), exist_ok=True)
      write_file(path, zlib.compress(full_data))
  return object_ID

def read_index():
    try:
      index = os.path.join('.git', 'index')
      data = read_file(index)
    except FileNotFoundError:
      return [f"Fatal: could not read index file '{index}': No such file or directory"]
    digest = hashlib.sha1(data[:-20]).digest()
    assert digest == data[-20:], 'invalid index checksum'
    signature, version, num_entries = struct.unpack('!4sLL', data[:12])
    assert signature == b'DIRC', \'invalid index signature {}'.format(signature)
    assert version == 2, 'unknown index version {}'.format(version)
    entry_data = data[12:-20]
    entries = []
    i = 0
    while i + 62 < len(entry_data):
      fields_end = i + 62
      fields = struct.unpack('!LLLLLLLLLL20sH', entry_data[i:fields_end])
      path_end = entry_data.index(b'\x00', fields_end)
      path = entry_data[fields_end:path_end]
      entry = IndexEntry(*(fields + (path.decode(),)))
      entries.append(entry)
      entry_len = ((62 + len(path) + 8) // 8) * 8
      i += entry_len
    assert len(entries) == num_entries
    return entries

def read_file(path):
  with open(path, 'rb') as f:
    return f.read()

def write_file(path, data):
  with open(path, 'wb') as f:
    f.write(data)
