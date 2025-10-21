import os
import pytest
import tempfile
import shutil
from pathlib import Path

import sys
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from minigit.core import hash_object, read_object, find_object, ObjectType
from minigit.repository import init_repository, is_repository, find_repository_root
from minigit.index import add_files, read_index, get_status, write_index
from minigit.commit import create_commit, read_commit, get_commit_history
from minigit.tree import write_tree, read_tree
from minigit.diff import diff_files, diff_index_working
from minigit.exceptions import GitError, RepositoryError, ObjectNotFoundError


class TestRepository:
    
    def test_init_creates_structure(self, tmp_path):
        repo_path = tmp_path / "test_repo"
        init_repository(str(repo_path))
        
        assert (repo_path / ".git").is_dir()
        assert (repo_path / ".git" / "objects").is_dir()
        assert (repo_path / ".git" / "refs" / "heads").is_dir()
        assert (repo_path / ".git" / "HEAD").is_file()
    
    def test_init_prevents_double_init(self, tmp_path):
        repo_path = tmp_path / "test_repo"
        init_repository(str(repo_path))
        
        with pytest.raises(RepositoryError):
            init_repository(str(repo_path))
    
    def test_is_repository(self, tmp_path):
        repo_path = tmp_path / "test_repo"
        assert not is_repository(str(repo_path))
        
        init_repository(str(repo_path))
        assert is_repository(str(repo_path))
    
    def test_find_repository_root(self, tmp_path):
        repo_path = tmp_path / "test_repo"
        init_repository(str(repo_path))
        
        subdir = repo_path / "subdir" / "nested"
        subdir.mkdir(parents=True)
        
        os.chdir(subdir)
        root = find_repository_root()
        assert Path(root).resolve() == repo_path.resolve()


class TestObjects:
    
    @pytest.fixture
    def repo(self, tmp_path):
        repo_path = tmp_path / "test_repo"
        init_repository(str(repo_path))
        os.chdir(repo_path)
        return repo_path
    
    def test_hash_blob_object(self, repo):
        content = b"Hello, World!"
        sha1 = hash_object(content, ObjectType.BLOB, write=True)
        
        assert len(sha1) == 40
        assert sha1.isalnum()
        
        obj_path = repo / ".git" / "objects" / sha1[:2] / sha1[2:]
        assert obj_path.is_file()
    
    def test_read_object(self, repo):
        content = b"Test content"
        sha1 = hash_object(content, ObjectType.BLOB, write=True)
        
        obj_type, data = read_object(sha1)
        assert obj_type == ObjectType.BLOB
        assert data == content
    
    def test_hash_same_content_same_hash(self, repo):
        content = b"Identical content"
        sha1_1 = hash_object(content, ObjectType.BLOB, write=True)
        sha1_2 = hash_object(content, ObjectType.BLOB, write=True)
        
        assert sha1_1 == sha1_2
    
    def test_find_object_by_prefix(self, repo):
        content = b"Find me!"
        sha1 = hash_object(content, ObjectType.BLOB, write=True)
        
        found_path = find_object(sha1[:7])
        assert sha1[2:] in found_path
    
    def test_find_object_not_found(self, repo):
        with pytest.raises(ObjectNotFoundError):
            find_object("deadbeef")
    
    def test_hash_different_types(self, repo):
        content = b"Same content"
        blob_sha = hash_object(content, ObjectType.BLOB, write=True)
        commit_sha = hash_object(content, ObjectType.COMMIT, write=True)
        
        assert blob_sha != commit_sha


class TestIndex:
    
    @pytest.fixture
    def repo(self, tmp_path):
        repo_path = tmp_path / "test_repo"
        init_repository(str(repo_path))
        os.chdir(repo_path)
        
        test_file = repo_path / "test.txt"
        test_file.write_text("Test content\n")
        
        return repo_path
    
    def test_add_file(self, repo):
        add_files(["test.txt"])
        
        entries = read_index()
        assert len(entries) == 1
        assert entries[0].path == "test.txt"
    
    def test_add_multiple_files(self, repo):
        (repo / "file1.txt").write_text("Content 1")
        (repo / "file2.txt").write_text("Content 2")
        
        add_files(["file1.txt", "file2.txt"])
        
        entries = read_index()
        assert len(entries) == 2
        paths = [e.path for e in entries]
        assert "file1.txt" in paths
        assert "file2.txt" in paths
    
    def test_add_updates_existing(self, repo):
        add_files(["test.txt"])
        entries_1 = read_index()
        
        (repo / "test.txt").write_text("Modified content\n")
        add_files(["test.txt"])
        entries_2 = read_index()
        
        assert len(entries_2) == 1
        assert entries_1[0].sha1 != entries_2[0].sha1
    
    def test_status_new_file(self, repo):
        changed, new, deleted = get_status()
        
        assert "test.txt" in new
        assert len(changed) == 0
        assert len(deleted) == 0
    
    def test_status_after_add(self, repo):
        add_files(["test.txt"])
        changed, new, deleted = get_status()
        
        assert len(new) == 0
        assert len(changed) == 0
        assert len(deleted) == 0
    
    def test_status_modified(self, repo):
        add_files(["test.txt"])
        
        (repo / "test.txt").write_text("Modified!\n")
        
        changed, new, deleted = get_status()
        assert "test.txt" in changed
    
    def test_status_deleted(self, repo):
        add_files(["test.txt"])
        (repo / "test.txt").unlink()
        
        changed, new, deleted = get_status()
        assert "test.txt" in deleted


class TestCommit:
    
    @pytest.fixture
    def repo(self, tmp_path, monkeypatch):
        repo_path = tmp_path / "test_repo"
        init_repository(str(repo_path))
        os.chdir(repo_path)
        
        monkeypatch.setenv("GIT_AUTHOR_NAME", "Test Author")
        monkeypatch.setenv("GIT_AUTHOR_EMAIL", "test@example.com")
        
        (repo_path / "test.txt").write_text("Initial content\n")
        add_files(["test.txt"])
        
        return repo_path
    
    def test_create_commit(self, repo):
        sha1 = create_commit("Initial commit")
        
        assert len(sha1) == 40
        
        obj_type, data = read_object(sha1)
        assert obj_type == ObjectType.COMMIT
        assert b"Initial commit" in data
    
    def test_commit_with_author(self, repo):
        sha1 = create_commit("Test", author="Custom <custom@example.com>")
        
        obj_type, data = read_object(sha1)
        assert b"Custom <custom@example.com>" in data
    
    def test_read_commit(self, repo):
        sha1 = create_commit("Test commit")
        
        commit_info = read_commit(sha1)
        assert commit_info['message'] == "Test commit"
        assert commit_info['tree'] is not None
        assert 'author' in commit_info
    
    def test_commit_history(self, repo):
        sha1_1 = create_commit("First")
        
        (repo / "test.txt").write_text("Modified\n")
        add_files(["test.txt"])
        sha1_2 = create_commit("Second")
        
        history = get_commit_history()
        assert len(history) == 2
        assert history[0]['sha1'] == sha1_2
        assert history[1]['sha1'] == sha1_1
    
    def test_commit_without_author_env_fails(self, repo, monkeypatch):
        monkeypatch.delenv("GIT_AUTHOR_NAME", raising=False)
        monkeypatch.delenv("GIT_AUTHOR_EMAIL", raising=False)
        
        with pytest.raises(GitError):
            create_commit("Test")


class TestTree:
    
    @pytest.fixture
    def repo(self, tmp_path):
        repo_path = tmp_path / "test_repo"
        init_repository(str(repo_path))
        os.chdir(repo_path)
        
        (repo_path / "file1.txt").write_text("Content 1")
        (repo_path / "file2.txt").write_text("Content 2")
        add_files(["file1.txt", "file2.txt"])
        
        return repo_path
    
    def test_write_tree(self, repo):
        tree_sha = write_tree()
        
        assert len(tree_sha) == 40
        
        obj_type, data = read_object(tree_sha)
        assert obj_type == ObjectType.TREE
    
    def test_read_tree(self, repo):
        tree_sha = write_tree()
        entries = read_tree(sha1=tree_sha)
        
        assert len(entries) == 2
        paths = [path for _, path, _ in entries]
        assert "file1.txt" in paths
        assert "file2.txt" in paths


class TestDiff:
    
    def test_diff_files(self):
        content1 = b"line 1\nline 2\nline 3\n"
        content2 = b"line 1\nmodified line 2\nline 3\n"
        
        diff = diff_files("file1", content1, "file2", content2)
        
        assert len(diff) > 0
        assert any("-line 2" in line for line in diff)
        assert any("+modified line 2" in line for line in diff)
    
    def test_diff_binary_files(self):
        content1 = b"\x00\x01\x02"
        content2 = b"\x00\x01\x03"
        
        diff = diff_files("bin1", content1, "bin2", content2)
        
        assert len(diff) == 1
        assert "Binary files" in diff[0]


@pytest.fixture
def tmp_path():
    tmp_dir = tempfile.mkdtemp()
    yield Path(tmp_dir)
    shutil.rmtree(tmp_dir, ignore_errors=True)


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])
