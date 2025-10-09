## PyGit: A simplified but functional Git implementation in pure Python to understand how Git works behind the scenes.


### Features

✅ Repository initialization (init)
✅ Staging files (add)
✅ Creating commits (commit)
✅ Viewing status (status)
✅ Showing diffs (diff)
✅ Commit history with visualization (log)
✅ Push to remote repositories (push)
✅ Content-addressable object storage
✅ Index/staging area
✅ Tree and blob objects
✅ Pack file generation for network transfer
✅ Zero external dependencies (pure Python stdlib)

### Why PyGit?

**Understanding Git internals makes you a better developer. PyGit demonstrates:**

- How Git stores objects (blobs, trees, commits)
- How the staging area works
- How commits form a DAG (directed acyclic graph)
- How push protocol works
- Why Git is so fast and efficient

### Installation
**From Source**
```
git clone https://github.com/yourusername/pygit.git
cd pygit
pip install -e 
```
**Using Docker**
```
docker build -t pygit .
docker run -it pygit
```
**Quick Start**
```
# Initialize a repository
pygit init my-repo
cd my-repo

# Create a file
echo "Hello, Git!" > README.md

# Stage the file
pygit add README.md

# Check status
pygit status

# Commit
export GIT_AUTHOR_NAME="Your Name"
export GIT_AUTHOR_EMAIL="you@example.com"
pygit commit -m "Initial commit"

# View history
pygit log

# See what changed
echo "More content" >> README.md
pygit diff

# Push to remote (GitHub)
pygit push https://github.com/user/repo.git -u username -p token
```
**Commands**

| Command | Description | Example |
|---------|-------------|---------|
| `init` | Initialize a new repository | `pygit init my-repo` |
| `add` | Stage files for commit | `pygit add file1.txt file2.txt` |
| `status` | Show working tree status | `pygit status` |
| `commit` | Record changes to repository | `pygit commit -m "Add feature"` |
| `diff` | Show changes between index and working tree | `pygit diff` |
| `log` | Show commit history | `pygit log -n 10` |
| `ls-files` | List files in index | `pygit ls-files -s` |
| `cat-file` | Display object contents | `pygit cat-file pretty abc123` |
| `hash-object` | Compute object hash | `pygit hash-object file.txt -w` |
| `push` | Update remote refs | `pygit push <url> -u user -p pass` |
| `info` | Show repository information | `pygit info` |

**Architecture**
```
pygit/
├── __init__.py          # Package initialization
├── core.py              # Object storage (hash, read, write)
├── index.py             # Staging area operations
├── tree.py              # Tree object handling
├── commit.py            # Commit operations
├── diff.py              # Diff generation
├── network.py           # Push protocol
├── repository.py        # Repository management
├── cli.py               # Command-line interface
└── exceptions.py        # Custom exceptions
```
### How It Works
**Object Storage**

Git stores everything as objects identified by SHA-1 hashes:
```
# Create a blob object
content = b"Hello, World!"
header = b"blob 13\x00"
full_data = header + content
sha1 = hashlib.sha1(full_data).hexdigest()
# Store at .git/objects/af/5626b4a114...
```

**The Index (Staging Area)**

Binary file at .git/index containing:
- File metadata (timestamps, permissions, size)
- SHA-1 hash of file contents
- Path name

**Commits**
```
tree abc123def456...
parent 789ghi012jkl...
author Name <email> 1234567890 -0800
committer Name <email> 1234567890 -0800

Commit message goes here
```
**Tree Objects**
```
100644 blob 5716ca... README.md
100644 blob 551156... main.py
040000 tree 99a456... src/
```

**Testing**
```
# Install development dependencies
pip install -e ".[dev]"

# Run tests
pytest tests/ -v

# With coverage
pytest tests/ --cov=pygit --cov-report=html

# Run specific test
pytest tests/test_pygit.py::TestRepository::test_init_creates_structure
```

**Limitations**

This is an educational implementation with some intentional simplifications:

- No subdirectories: Only supports flat file structure (single directory level)
- No merging: Doesn't implement merge algorithm
- No branches: Only master branch supported
- No fetch/pull: Only push is implemented
- No .gitignore: All files are tracked
- No submodules: Not supported
- Basic diff: Unified diff only, no word-diff or other formats

**Comparison with Real Git**

| Feature | PyGit | Git |
|---------|-------|-----|
| Object storage | ✅ | ✅ |
| Commits | ✅ | ✅ |
| Trees and blobs | ✅ | ✅ |
| Index/staging | ✅ | ✅ |
| Push | ✅ | ✅ |
| Branches | ❌ | ✅ |
| Merge | ❌ | ✅ |
| Fetch/Pull | ❌ | ✅ |
| Subdirectories | ❌ | ✅ |
| Delta compression | ❌ | ✅ |
| Garbage collection | ❌ | ✅ |
| Performance | Slow | Fast (C) |

**Learning Resources**

- Blog Post: See blog_post.md for detailed explanation
- Code Comments: Every function is documented
- Tests: tests/test_pygit.py shows usage examples

### Advanced Usage
**Examining Objects**
```
# Hash a file
pygit hash-object myfile.txt -w

# View object type
pygit cat-file type abc123

# View object size
pygit cat-file size abc123

# Pretty-print object
pygit cat-file pretty abc123
```

**Index Operations**
```
# List files in index
pygit ls-files

# List with details (mode, hash, stage)
pygit ls-files -s
```

**Repository Info**
```
# Show repo information
pygit info
```

Output:
```
Repository Information:
  Path: /home/user/my-repo
  Git directory: /home/user/my-repo/.git
  Current branch: refs/heads/master
  Objects stored: 42
```
### Extending PyGit

### FAQ
Q: Why Python instead of C like real Git?
A: Python is more readable for educational purposes. Performance isn't the goal.
Q: Does this work with GitHub/GitLab?
A: Yes! The push command works with any Git server supporting HTTP basic auth.
Q: Can real Git read PyGit repositories?
A: Yes! PyGit creates standard Git objects. You can use real Git commands in a PyGit repo.

### Acknowledgements/Licensing
MIT License - See LICENSE file for details.

**Author**
Andrew Johnson
