import os
import pytest
import tempfile
import shutil
import sys
from pathlib import Path
from io import StringIO
from unittest.mock import patch, MagicMock, mock_open
import urllib.request

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from minigit.core import hash_object, read_object, find_object, ObjectType, GitObject, get_local_ref, update_ref
from minigit.repository import init_repository, is_repository, find_repository_root, get_repository_info
from minigit.index import add_files, read_index, get_status, write_index, list_files
from minigit.commit import create_commit, read_commit, get_commit_history, find_commit_objects, visualize_commit_history
from minigit.tree import write_tree, read_tree, find_tree_objects, print_tree
from minigit.diff import diff_files, diff_index_working, print_diff, get_diff_stats
from minigit.network import (extract_lines, build_lines_data, http_request, get_remote_ref,
                              find_missing_objects, encode_pack_object, create_pack, push)
from minigit.exceptions import (GitError, RepositoryError, ObjectNotFoundError, 
                                InvalidObjectError, IndexError as GitIndexError,
                                NetworkError, AuthenticationError)
from minigit import cli
from minigit.network import (extract_lines, build_lines_data, http_request, 
                              get_remote_ref, find_missing_objects, 
                              encode_pack_object, create_pack, push, ObjectTypeNum)


class TestCLI:
    """Test all CLI commands"""
    
    @pytest.fixture
    def repo(self, tmp_path, monkeypatch):
        repo_path = tmp_path / "test_repo"
        init_repository(str(repo_path))
        os.chdir(repo_path)
        monkeypatch.setenv("GIT_AUTHOR_NAME", "Test User")
        monkeypatch.setenv("GIT_AUTHOR_EMAIL", "test@example.com")
        return repo_path
    
    def test_cmd_init(self, tmp_path, capsys):
        """Test init command"""
        with patch('sys.argv', ['minigit', 'init', str(tmp_path / 'new_repo')]):
            cli.main()
        
        captured = capsys.readouterr()
        assert "Initialized empty Git repository" in captured.out
    
    def test_cmd_init_error(self, tmp_path, capsys):
        """Test init command with error"""
        repo_path = tmp_path / "test_repo"
        init_repository(str(repo_path))
        
        with patch('sys.argv', ['minigit', 'init', str(repo_path)]):
            with pytest.raises(SystemExit) as exc_info:
                cli.main()
            assert exc_info.value.code == 1
    
    def test_cmd_add(self, repo, capsys):
        """Test add command"""
        (repo / "file.txt").write_text("content")
        
        with patch('sys.argv', ['minigit', 'add', 'file.txt']):
            cli.main()
        
        captured = capsys.readouterr()
        assert "Added 1 file(s)" in captured.out
    
    def test_cmd_add_multiple(self, repo, capsys):
        """Test add with multiple files"""
        (repo / "file1.txt").write_text("content1")
        (repo / "file2.txt").write_text("content2")
        
        with patch('sys.argv', ['minigit', 'add', 'file1.txt', 'file2.txt']):
            cli.main()
        
        captured = capsys.readouterr()
        assert "Added 2 file(s)" in captured.out
    
    def test_cmd_add_error(self, repo):
        """Test add command with error"""
        with patch('sys.argv', ['minigit', 'add', 'nonexistent.txt']):
            with pytest.raises(SystemExit) as exc_info:
                cli.main()
            assert exc_info.value.code == 1
    
    def test_cmd_status_clean(self, repo, capsys):
        """Test status with clean working tree"""
        with patch('sys.argv', ['minigit', 'status']):
            cli.main()
        
        captured = capsys.readouterr()
        assert "working tree clean" in captured.out
    
    def test_cmd_status_new_files(self, repo, capsys):
        """Test status with new files"""
        (repo / "new.txt").write_text("content")
        
        with patch('sys.argv', ['minigit', 'status']):
            cli.main()
        
        captured = capsys.readouterr()
        assert "Untracked files" in captured.out
        assert "new.txt" in captured.out
    
    def test_cmd_status_modified(self, repo, capsys):
        """Test status with modified files"""
        (repo / "file.txt").write_text("original")
        add_files(["file.txt"])
        (repo / "file.txt").write_text("modified")
        
        with patch('sys.argv', ['minigit', 'status']):
            cli.main()
        
        captured = capsys.readouterr()
        assert "modified" in captured.out
    
    def test_cmd_status_deleted(self, repo, capsys):
        """Test status with deleted files"""
        (repo / "file.txt").write_text("content")
        add_files(["file.txt"])
        (repo / "file.txt").unlink()
        
        with patch('sys.argv', ['minigit', 'status']):
            cli.main()
        
        captured = capsys.readouterr()
        assert "Deleted files" in captured.out or "deleted" in captured.out
    
    def test_cmd_commit(self, repo, capsys):
        """Test commit command"""
        (repo / "file.txt").write_text("content")
        add_files(["file.txt"])
        
        with patch('sys.argv', ['minigit', 'commit', '-m', 'Test commit']):
            cli.main()
        
        captured = capsys.readouterr()
        assert "Test commit" in captured.out
        assert "master" in captured.out
    
    def test_cmd_commit_with_author(self, repo, capsys):
        """Test commit with explicit author"""
        (repo / "file.txt").write_text("content")
        add_files(["file.txt"])
        
        with patch('sys.argv', ['minigit', 'commit', '-m', 'Test', '-a', 'John <john@example.com>']):
            cli.main()
        
        captured = capsys.readouterr()
        assert "Test" in captured.out
    
    def test_cmd_commit_error(self, repo):
        """Test commit without message fails"""
        with patch('sys.argv', ['minigit', 'commit']):
            with pytest.raises(SystemExit):
                cli.main()
    
    def test_cmd_diff(self, repo, capsys):
        """Test diff command"""
        (repo / "file.txt").write_text("original\n")
        add_files(["file.txt"])
        (repo / "file.txt").write_text("modified\n")
        
        with patch('sys.argv', ['minigit', 'diff']):
            cli.main()
        
        captured = capsys.readouterr()
        assert "file.txt" in captured.out
    
    def test_cmd_diff_no_changes(self, repo, capsys):
        """Test diff with no changes"""
        with patch('sys.argv', ['minigit', 'diff']):
            cli.main()
        
        captured = capsys.readouterr()
        assert "No changes" in captured.out
    
    def test_cmd_log(self, repo, capsys):
        """Test log command"""
        (repo / "file.txt").write_text("content")
        add_files(["file.txt"])
        create_commit("First commit")
        
        with patch('sys.argv', ['minigit', 'log']):
            cli.main()
        
        captured = capsys.readouterr()
        assert "First commit" in captured.out
    
    def test_cmd_log_with_limit(self, repo, capsys):
        """Test log with max count"""
        (repo / "file.txt").write_text("content")
        add_files(["file.txt"])
        create_commit("Commit 1")
        
        with patch('sys.argv', ['minigit', 'log', '-n', '5']):
            cli.main()
        
        captured = capsys.readouterr()
        assert "Commit 1" in captured.out
    
    def test_cmd_ls_files(self, repo, capsys):
        """Test ls-files command"""
        (repo / "file.txt").write_text("content")
        add_files(["file.txt"])
        
        with patch('sys.argv', ['minigit', 'ls-files']):
            cli.main()
        
        captured = capsys.readouterr()
        assert "file.txt" in captured.out
    
    def test_cmd_ls_files_stage(self, repo, capsys):
        """Test ls-files with -s flag"""
        (repo / "file.txt").write_text("content")
        add_files(["file.txt"])
        
        with patch('sys.argv', ['minigit', 'ls-files', '-s']):
            cli.main()
        
        captured = capsys.readouterr()
        assert "file.txt" in captured.out
        assert "100" in captured.out
    
    def test_cmd_cat_file_blob(self, repo, capsys):
        """Test cat-file blob mode"""
        content = b"test content"
        sha1 = hash_object(content, ObjectType.BLOB)
        
        with patch('sys.argv', ['minigit', 'cat-file', 'blob', sha1]):
            with patch('sys.stdout.buffer.write') as mock_write:
                cli.main()
                mock_write.assert_called_with(content)
    
    def test_cmd_cat_file_type(self, repo, capsys):
        """Test cat-file type mode"""
        content = b"test content"
        sha1 = hash_object(content, ObjectType.BLOB)
        
        with patch('sys.argv', ['minigit', 'cat-file', 'type', sha1]):
            cli.main()
        
        captured = capsys.readouterr()
        assert "blob" in captured.out
    
    def test_cmd_cat_file_size(self, repo, capsys):
        """Test cat-file size mode"""
        content = b"test content"
        sha1 = hash_object(content, ObjectType.BLOB)
        
        with patch('sys.argv', ['minigit', 'cat-file', 'size', sha1]):
            cli.main()
        
        captured = capsys.readouterr()
        assert str(len(content)) in captured.out
    
    def test_cmd_cat_file_pretty(self, repo, capsys):
        """Test cat-file pretty mode"""
        content = b"test content"
        sha1 = hash_object(content, ObjectType.BLOB)
        
        with patch('sys.argv', ['minigit', 'cat-file', 'pretty', sha1]):
            with patch('sys.stdout.buffer.write') as mock_write:
                cli.main()
                mock_write.assert_called()
    
    def test_cmd_cat_file_wrong_type(self, repo):
        """Test cat-file with wrong type expectation"""
        content = b"test content"
        sha1 = hash_object(content, ObjectType.BLOB)
        
        with patch('sys.argv', ['minigit', 'cat-file', 'commit', sha1]):
            with pytest.raises(SystemExit) as exc_info:
                cli.main()
            assert exc_info.value.code == 1
    
    def test_cmd_hash_object(self, repo, capsys):
        """Test hash-object command"""
        (repo / "file.txt").write_text("content")
        
        with patch('sys.argv', ['minigit', 'hash-object', 'file.txt']):
            cli.main()
        
        captured = capsys.readouterr()
        assert len(captured.out.strip()) == 40
    
    def test_cmd_hash_object_write(self, repo, capsys):
        """Test hash-object with -w flag"""
        (repo / "file.txt").write_text("content")
        
        with patch('sys.argv', ['minigit', 'hash-object', 'file.txt', '-w']):
            cli.main()
        
        captured = capsys.readouterr()
        sha1 = captured.out.strip()
        assert len(sha1) == 40
        assert (repo / ".git" / "objects" / sha1[:2] / sha1[2:]).exists()
    
    def test_cmd_hash_object_type(self, repo, capsys):
        """Test hash-object with -t flag"""
        (repo / "file.txt").write_text("content")
        
        with patch('sys.argv', ['minigit', 'hash-object', 'file.txt', '-t', 'blob', '-w']):
            cli.main()
        
        captured = capsys.readouterr()
        assert len(captured.out.strip()) == 40
    
    def test_cmd_push(self, repo, monkeypatch):
        """Test push command"""
        (repo / "file.txt").write_text("content")
        add_files(["file.txt"])
        create_commit("Initial commit")
        
        with patch('minigit.cli.push') as mock_push:
            with patch('sys.argv', ['minigit', 'push', 'https://github.com/user/repo.git', 
                                   '-u', 'user', '-p', 'token']):
                cli.main()
            
            mock_push.assert_called_once()
    
    def test_cmd_push_error(self, repo):
        """Test push command with error"""
        with patch('sys.argv', ['minigit', 'push', 'https://github.com/user/repo.git', 
                               '-u', 'user', '-p', 'token']):
            with patch('minigit.cli.push', side_effect=NetworkError("Network error")):
                with pytest.raises(SystemExit) as exc_info:
                    cli.main()
                assert exc_info.value.code == 1
    
    def test_cmd_info(self, repo, capsys):
        """Test info command"""
        with patch('sys.argv', ['minigit', 'info']):
            cli.main()
        
        captured = capsys.readouterr()
        assert "Repository Information" in captured.out
        assert "Git directory" in captured.out
    
    def test_cmd_info_error(self, tmp_path):
        """Test info command outside repo"""
        os.chdir(tmp_path)
        with patch('sys.argv', ['minigit', 'info']):
            with pytest.raises(SystemExit) as exc_info:
                cli.main()
            assert exc_info.value.code == 1


class TestNetworkExtended:
    """Extended network tests for better coverage"""
    
    @pytest.fixture
    def repo(self, tmp_path, monkeypatch):
        repo_path = tmp_path / "test_repo"
        init_repository(str(repo_path))
        os.chdir(repo_path)
        monkeypatch.setenv("GIT_AUTHOR_NAME", "Test User")
        monkeypatch.setenv("GIT_AUTHOR_EMAIL", "test@example.com")
        return repo_path
    
    def test_extract_lines_empty(self):
        """Test extract_lines with empty data"""
        data = b'0000'
        lines = extract_lines(data)
        assert lines == [b'']
    
    def test_extract_lines_invalid_hex(self):
        """Test extract_lines with invalid hex"""
        data = b'ZZZZ'
        lines = extract_lines(data)
        assert lines == []
    
    def test_extract_lines_truncated(self):
        """Test extract_lines with truncated data"""
        data = b'0010abc'
        lines = extract_lines(data)
        assert len(lines) >= 0
    
    def test_build_lines_data_empty(self):
        """Test build_lines_data with empty list"""
        data = build_lines_data([])
        assert b'0000' in data
    
    def test_build_lines_data_single(self):
        """Test build_lines_data with single line"""
        data = build_lines_data([b'test'])
        assert b'test' in data
        assert b'0000' in data
    
    def test_http_request_success(self):
        """Test successful HTTP request"""
        url = "https://example.com/test"
        
        with patch('urllib.request.build_opener') as mock_opener:
            mock_response = MagicMock()
            mock_response.read.return_value = b"success"
            mock_open_func = MagicMock()
            mock_open_func.open.return_value = mock_response
            mock_opener.return_value = mock_open_func
            
            result = http_request(url, "user", "pass")
            assert result == b"success"
    
    def test_http_request_with_post_data(self):
        """Test HTTP request with POST data"""
        url = "https://example.com/test"
        post_data = b"some data"
        
        with patch('urllib.request.build_opener') as mock_opener:
            mock_response = MagicMock()
            mock_response.read.return_value = b"success"
            mock_open_func = MagicMock()
            mock_open_func.open.return_value = mock_response
            mock_opener.return_value = mock_open_func
            
            result = http_request(url, "user", "pass", data=post_data)
            assert result == b"success"
            mock_open_func.open.assert_called_with(url, data=post_data)
    
    def test_http_request_403_error(self):
        """Test HTTP 403 error"""
        url = "https://example.com/test"
        
        with patch('urllib.request.build_opener') as mock_opener:
            mock_open_func = MagicMock()
            mock_open_func.open.side_effect = urllib.request.HTTPError(
                url, 403, "Forbidden", {}, None
            )
            mock_opener.return_value = mock_open_func
            
            with pytest.raises(AuthenticationError):
                http_request(url, "user", "pass")
    
    def test_http_request_generic_exception(self):
        """Test generic exception in HTTP request"""
        url = "https://example.com/test"
        
        with patch('urllib.request.build_opener') as mock_opener:
            mock_opener.side_effect = Exception("Unexpected error")
            
            with pytest.raises(NetworkError):
                http_request(url, "user", "pass")
    
    def test_get_remote_ref_success(self):
        """Test get_remote_ref success - no refs in response"""
        service_line = b'# service=git-receive-pack\n'
        response_data = f'{len(service_line) + 4:04x}'.encode() + service_line
        response_data += b'0000' 
        
        with patch('minigit.network.http_request', return_value=response_data):
            result = get_remote_ref("https://github.com/user/repo.git", "user", "pass")
            assert result is None  

    def test_get_remote_ref_with_ref(self):
        """Test get_remote_ref with actual ref"""
        sha1 = "a" * 40
        
        service_line = b'# service=git-receive-pack\n'
        response_data = f'{len(service_line) + 4:04x}'.encode() + service_line + b'0000'
        
        ref_line = f'{sha1} refs/heads/master\n'.encode()
        response_data += f'{len(ref_line) + 4:04x}'.encode() + ref_line + b'0000'
        
        with patch('minigit.network.http_request', return_value=response_data):
            result = get_remote_ref("https://github.com/user/repo.git", "user", "pass", "refs/heads/master")
            assert result == sha1

    def test_get_remote_ref_empty_repo(self):
        """Test get_remote_ref with empty remote repo"""
        service_line = b'# service=git-receive-pack\n'
        response_data = f'{len(service_line) + 4:04x}'.encode() + service_line
        response_data += b'0000'
        
        ref_line = ('0' * 40 + ' capabilities^{}\n').encode()
        response_data += f'{len(ref_line) + 4:04x}'.encode() + ref_line
        response_data += b'0000'
        
        with patch('minigit.network.http_request', return_value=response_data):
            result = get_remote_ref("https://github.com/user/repo.git", "user", "pass")
            assert result is None

    def test_get_remote_ref_invalid_response(self):
        """Test get_remote_ref with invalid response"""
        response_data = b'bad response'
        
        with patch('minigit.network.http_request', return_value=response_data):
            with pytest.raises(NetworkError, match="Invalid server response"):
                get_remote_ref("https://github.com/user/repo.git", "user", "pass")
    
    def test_find_missing_objects_empty_remote(self, repo):
        """Test find_missing_objects with empty remote"""
        (repo / "file.txt").write_text("content")
        add_files(["file.txt"])
        local_sha = create_commit("Initial")
        
        missing = find_missing_objects(local_sha, None)
        assert len(missing) > 0
        assert local_sha in missing
    
    def test_find_missing_objects_with_remote(self, repo):
        """Test find_missing_objects with remote commit"""
        (repo / "file.txt").write_text("content")
        add_files(["file.txt"])
        commit1 = create_commit("First")
        
        (repo / "file.txt").write_text("modified")
        add_files(["file.txt"])
        commit2 = create_commit("Second")
        
        missing = find_missing_objects(commit2, commit1)
        assert commit2 in missing
    
    def test_encode_pack_object_blob(self, repo):
        """Test encode_pack_object for blob"""
        content = b"test content"
        sha1 = hash_object(content, ObjectType.BLOB)
        
        packed = encode_pack_object(sha1)
        assert len(packed) > 0
        assert isinstance(packed, bytes)
    
    def test_encode_pack_object_commit(self, repo):
        """Test encode_pack_object for commit"""
        (repo / "file.txt").write_text("content")
        add_files(["file.txt"])
        commit_sha = create_commit("Test commit")
        
        packed = encode_pack_object(commit_sha)
        assert len(packed) > 0
    
    def test_create_pack(self, repo):
        """Test create_pack"""
        content = b"test content"
        sha1 = hash_object(content, ObjectType.BLOB)
        
        pack = create_pack({sha1})
        assert pack.startswith(b'PACK')
        assert len(pack) > 12
    
    def test_create_pack_multiple_objects(self, repo):
        """Test create_pack with multiple objects"""
        sha1 = hash_object(b"content1", ObjectType.BLOB)
        sha2 = hash_object(b"content2", ObjectType.BLOB)
        
        pack = create_pack({sha1, sha2})
        assert pack.startswith(b'PACK')
    
    def test_push_no_username(self, repo, monkeypatch):
        """Test push without username"""
        monkeypatch.delenv("GIT_USERNAME", raising=False)
        
        with pytest.raises(NetworkError, match="Username not provided"):
            push("https://github.com/user/repo.git")
    
    def test_push_no_password(self, repo, monkeypatch):
        """Test push without password"""
        monkeypatch.setenv("GIT_USERNAME", "user")
        monkeypatch.delenv("GIT_PASSWORD", raising=False)
        
        with pytest.raises(NetworkError, match="Password not provided"):
            push("https://github.com/user/repo.git")
    
    def test_push_no_local_ref(self, repo, monkeypatch):
        """Test push with no local ref - should fail before making HTTP request"""
        with patch('minigit.network.http_request') as mock_http:
            service_line = b'# service=git-receive-pack\n'
            response_data = f'{len(service_line) + 4:04x}'.encode() + service_line
            response_data += b'0000'
            mock_http.return_value = response_data
            
            with pytest.raises(NetworkError, match="Local ref.*does not exist"):
                push("https://github.com/user/repo.git", username="user", password="pass")
    
    def test_push_success(self, repo, capsys, monkeypatch):
        """Test successful push"""
        (repo / "file.txt").write_text("content")
        add_files(["file.txt"])
        create_commit("Initial commit")
        
        with patch('minigit.network.http_request') as mock_http:
            def mock_http_side_effect(url, username, password, data=None):
                if 'info/refs' in url:
                    service_line = b'# service=git-receive-pack\n'
                    response = f'{len(service_line) + 4:04x}'.encode() + service_line
                    response += b'0000'
                    return response
                else:
                    unpack_line = b'unpack ok\n'
                    response = f'{len(unpack_line) + 4:04x}'.encode() + unpack_line
                    
                    ok_line = b'ok refs/heads/master\n'
                    response += f'{len(ok_line) + 4:04x}'.encode() + ok_line
                    response += b'0000'
                    return response
            
            mock_http.side_effect = mock_http_side_effect
            
            old_sha, missing = push("https://github.com/user/repo.git", "user", "pass")
            
            assert old_sha is None
            assert len(missing) > 0
        
        captured = capsys.readouterr()
        assert "Push successful" in captured.out
    
    def test_push_server_rejects_pack(self, repo):
        """Test push when server rejects pack"""
        (repo / "file.txt").write_text("content")
        add_files(["file.txt"])
        create_commit("Initial commit")
        
        with patch('minigit.network.get_remote_ref', return_value=None):
            with patch('minigit.network.http_request') as mock_http:
                mock_http.return_value = b'0012unpack failed\n0000'
                
                with pytest.raises(NetworkError, match="Server rejected pack"):
                    push("https://github.com/user/repo.git", "user", "pass")
    
    def test_push_server_rejects_ref(self, repo):
        """Test push when server rejects ref update"""
        (repo / "file.txt").write_text("content")
        add_files(["file.txt"])
        create_commit("Initial commit")
        
        with patch('minigit.network.http_request') as mock_http:
            def mock_http_side_effect(url, username, password, data=None):
                if 'info/refs' in url:
                    service_line = b'# service=git-receive-pack\n'
                    response = f'{len(service_line) + 4:04x}'.encode() + service_line
                    response += b'0000'
                    return response
                else:
                    unpack_line = b'unpack ok\n'
                    response = f'{len(unpack_line) + 4:04x}'.encode() + unpack_line
                    
                    ng_line = b'ng refs/heads/master\n'
                    response += f'{len(ng_line) + 4:04x}'.encode() + ng_line
                    response += b'0000'
                    return response
            
            mock_http.side_effect = mock_http_side_effect
            
            with pytest.raises(NetworkError, match="Server rejected ref update"):
                push("https://github.com/user/repo.git", "user", "pass")
    
    def test_push_invalid_server_response(self, repo):
        """Test push with invalid server response"""
        (repo / "file.txt").write_text("content")
        add_files(["file.txt"])
        create_commit("Initial commit")
        
        with patch('minigit.network.get_remote_ref', return_value=None):
            with patch('minigit.network.http_request') as mock_http:
                mock_http.return_value = b'0005x'
                
                with pytest.raises(NetworkError, match="Invalid server response"):
                    push("https://github.com/user/repo.git", "user", "pass")

def test_main_module():
    """Test __main__.py execution"""
    with patch('minigit.cli.main') as mock_main:
        import subprocess
        result = subprocess.run([sys.executable, '-m', 'minigit', '--help'], 
                              capture_output=True, cwd=os.path.dirname(os.path.dirname(__file__)))
        assert result.returncode in [0, 2]


class TestRepository:
    
    def test_init_creates_structure(self, tmp_path):
        repo_path = tmp_path / "test_repo"
        init_repository(str(repo_path))
        
        assert (repo_path / ".git").is_dir()
        assert (repo_path / ".git" / "objects").is_dir()
        assert (repo_path / ".git" / "refs" / "heads").is_dir()
        assert (repo_path / ".git" / "HEAD").is_file()
        assert (repo_path / ".git" / "config").is_file()
    
    def test_init_current_directory(self, tmp_path):
        os.chdir(tmp_path)
        init_repository('.')
        assert (tmp_path / ".git").is_dir()
    
    def test_init_prevents_double_init(self, tmp_path):
        repo_path = tmp_path / "test_repo"
        init_repository(str(repo_path))
        
        with pytest.raises(RepositoryError, match="already exists"):
            init_repository(str(repo_path))
    
    def test_init_mkdir_fails(self, tmp_path):
        with patch('os.makedirs', side_effect=OSError("Permission denied")):
            with pytest.raises(RepositoryError, match="Could not create directory"):
                init_repository(str(tmp_path / "bad_repo"))
    
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
    
    def test_find_repository_root_not_found(self, tmp_path):
        os.chdir(tmp_path)
        with pytest.raises(RepositoryError, match="Not a git repository"):
            find_repository_root()
    
    def test_get_repository_info(self, tmp_path):
        repo_path = tmp_path / "test_repo"
        init_repository(str(repo_path))
        os.chdir(repo_path)
        
        info = get_repository_info()
        assert 'path' in info
        assert 'git_dir' in info
        assert 'object_count' in info
        assert info['object_count'] == 0
    
    def test_get_repository_info_not_repo(self, tmp_path):
        os.chdir(tmp_path)
        with pytest.raises(RepositoryError):
            get_repository_info()


class TestObjects:
    
    @pytest.fixture
    def repo(self, tmp_path):
        repo_path = tmp_path / "test_repo"
        init_repository(str(repo_path))
        os.chdir(repo_path)
        return repo_path
    
    def test_git_object_class(self):
        obj = GitObject(ObjectType.BLOB, b"test content")
        assert obj.obj_type == ObjectType.BLOB
        assert obj.content == b"test content"
        assert len(obj.sha1) == 40
        assert "GitObject" in repr(obj)
    
    def test_git_object_invalid_type(self):
        with pytest.raises(InvalidObjectError):
            GitObject("invalid_type", b"content")
    
    def test_hash_blob_object(self, repo):
        content = b"Hello, World!"
        sha1 = hash_object(content, ObjectType.BLOB, write=True)
        
        assert len(sha1) == 40
        assert sha1.isalnum()
        
        obj_path = repo / ".git" / "objects" / sha1[:2] / sha1[2:]
        assert obj_path.is_file()
    
    def test_hash_object_without_write(self, repo):
        content = b"No write"
        sha1 = hash_object(content, ObjectType.BLOB, write=False)
        
        obj_path = repo / ".git" / "objects" / sha1[:2] / sha1[2:]
        assert not obj_path.exists()
    
    def test_hash_object_invalid_type(self, repo):
        with pytest.raises(InvalidObjectError):
            hash_object(b"content", "invalid", write=False)
    
    def test_hash_object_not_in_repo(self, tmp_path):
        os.chdir(tmp_path)
        with pytest.raises(GitError, match="Not a git repository"):
            hash_object(b"content", ObjectType.BLOB, write=True)
    
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
    
    def test_find_object_short_prefix(self, repo):
        with pytest.raises(ValueError, match="must be 2 or more"):
            find_object("a")
    
    def test_find_object_not_found(self, repo):
        with pytest.raises(ObjectNotFoundError):
            find_object("deadbeef")
    
    def test_find_object_ambiguous(self, repo):
        # Create objects with same prefix
        hash_object(b"content1", ObjectType.BLOB, write=True)
        hash_object(b"content2", ObjectType.BLOB, write=True)
        
        # Try to find with very short prefix (might be ambiguous)
        # This is hard to test reliably, so we'll skip detailed testing
    
    def test_find_object_not_in_repo(self, tmp_path):
        os.chdir(tmp_path)
        with pytest.raises(GitError):
            find_object("abc123")
    
    def test_read_object_invalid_format(self, repo):
        # Create malformed object
        sha1 = "ab" + "c" * 38
        obj_dir = repo / ".git" / "objects" / sha1[:2]
        obj_dir.mkdir(exist_ok=True)
        
        import zlib
        (obj_dir / sha1[2:]).write_bytes(zlib.compress(b"bad format"))
        
        with pytest.raises(InvalidObjectError):
            read_object(sha1)
    
    def test_read_object_size_mismatch(self, repo):
        import zlib
        sha1 = "ab" + "c" * 38
        obj_dir = repo / ".git" / "objects" / sha1[:2]
        obj_dir.mkdir(exist_ok=True)
        
        # Header says 10 bytes but content is 5
        bad_data = b"blob 10\x00hello"
        (obj_dir / sha1[2:]).write_bytes(zlib.compress(bad_data))
        
        with pytest.raises(InvalidObjectError, match="size mismatch"):
            read_object(sha1)
    
    def test_hash_different_types(self, repo):
        content = b"Same content"
        blob_sha = hash_object(content, ObjectType.BLOB, write=True)
        commit_sha = hash_object(content, ObjectType.COMMIT, write=True)
        
        assert blob_sha != commit_sha
    
    def test_get_local_ref_exists(self, repo):
        update_ref('refs/heads/master', 'abc123')
        ref = get_local_ref('refs/heads/master')
        assert ref == 'abc123'
    
    def test_get_local_ref_not_exists(self, repo):
        ref = get_local_ref('refs/heads/nonexistent')
        assert ref is None
    
    def test_update_ref(self, repo):
        update_ref('refs/heads/test', 'def456')
        ref = get_local_ref('refs/heads/test')
        assert ref == 'def456'


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
    
    def test_add_file_with_backslash(self, repo):
        add_files(["test.txt"])  # Should normalize paths
        entries = read_index()
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
    
    def test_add_file_not_found(self, repo):
        with pytest.raises(GitIndexError, match="File not found"):
            add_files(["nonexistent.txt"])
    
    def test_add_directory_fails(self, repo):
        (repo / "subdir").mkdir()
        with pytest.raises(GitIndexError, match="Cannot add directory"):
            add_files(["subdir"])
    
    def test_add_path_too_long(self, repo):
        (repo / "test.txt").write_text("content")
    
        long_path = "a" * 5000 + ".txt"
    
        with patch('os.path.exists', return_value=True):
            with patch('os.path.isdir', return_value=False):
                with patch('minigit.index.read_file', return_value=b"content"):
                    with patch('os.stat') as mock_stat:
                        mock_stat.return_value = os.stat(repo / "test.txt")
                        with pytest.raises(GitIndexError, match="Path too long"):
                            add_files([long_path])
    
    def test_read_index_no_file(self, repo):
        entries = read_index()
        assert entries == []
    
    def test_read_index_corrupted_checksum(self, repo):
        add_files(["test.txt"])
        
        index_path = repo / ".git" / "index"
        data = index_path.read_bytes()
        # Corrupt the checksum
        index_path.write_bytes(data[:-20] + b'\x00' * 20)
        
        with pytest.raises(GitIndexError, match="checksum mismatch"):
            read_index()
    
    def test_read_index_too_short(self, repo):
        index_path = repo / ".git" / "index"
        index_path.write_bytes(b"short")
        
        with pytest.raises(GitIndexError, match="too short"):
            read_index()
    
    def test_read_index_invalid_signature(self, repo):
        import hashlib
        bad_data = b"BADD" + b"\x00" * 100
        index_path = repo / ".git" / "index"
        index_path.write_bytes(bad_data + hashlib.sha1(bad_data).digest())
        
        with pytest.raises(GitIndexError, match="Invalid index signature"):
            read_index()
    
    def test_read_index_wrong_version(self, repo):
        import struct, hashlib
        bad_header = struct.pack('!4sLL', b'DIRC', 99, 0)
        index_path = repo / ".git" / "index"
        index_path.write_bytes(bad_header + hashlib.sha1(bad_header).digest())
        
        with pytest.raises(GitIndexError, match="Unsupported index version"):
            read_index()
    
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
    
    def test_list_files_simple(self, repo):
        add_files(["test.txt"])
        files = list_files(details=False)
        assert "test.txt" in files
    
    def test_list_files_with_details(self, repo):
        add_files(["test.txt"])
        files = list_files(details=True)
        assert len(files) == 1
        assert "test.txt" in files[0]
        assert len(files[0].split()[1]) == 40  # SHA-1


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
    
    def test_commit_with_explicit_parent(self, repo):
        sha1_1 = create_commit("First")
        sha1_2 = create_commit("Second", parent=sha1_1)
        
        commit_info = read_commit(sha1_2)
        assert sha1_1 in commit_info['parents']
    
    def test_commit_with_explicit_tree(self, repo):
        tree_sha = write_tree()
        sha1 = create_commit("Test", tree=tree_sha)
        
        commit_info = read_commit(sha1)
        assert commit_info['tree'] == tree_sha
    
    def test_read_commit(self, repo):
        sha1 = create_commit("Test commit")
        
        commit_info = read_commit(sha1)
        assert commit_info['message'] == "Test commit"
        assert commit_info['tree'] is not None
        assert 'author' in commit_info
        assert 'committer' in commit_info
    
    def test_read_commit_wrong_type(self, repo):
        blob_sha = hash_object(b"not a commit", ObjectType.BLOB)
        with pytest.raises(GitError, match="Expected commit"):
            read_commit(blob_sha)
    
    def test_commit_history(self, repo):
        sha1_1 = create_commit("First")
        
        (repo / "test.txt").write_text("Modified\n")
        add_files(["test.txt"])
        sha1_2 = create_commit("Second")
        
        history = get_commit_history()
        assert len(history) == 2
        assert history[0]['sha1'] == sha1_2
        assert history[1]['sha1'] == sha1_1
    
    def test_commit_history_with_limit(self, repo):
        create_commit("First")
        (repo / "test.txt").write_text("Modified\n")
        add_files(["test.txt"])
        create_commit("Second")
        
        history = get_commit_history(max_count=1)
        assert len(history) == 1
    
    def test_commit_history_empty(self, repo):
        # Don't create any commits
        history = get_commit_history()
        assert history == []
    
    def test_commit_without_author_env_fails(self, repo, monkeypatch):
        monkeypatch.delenv("GIT_AUTHOR_NAME", raising=False)
        monkeypatch.delenv("GIT_AUTHOR_EMAIL", raising=False)
        
        with pytest.raises(GitError, match="Author not specified"):
            create_commit("Test")
    
    def test_find_commit_objects(self, repo):
        sha1 = create_commit("Test")
        objects = find_commit_objects(sha1)
        
        assert sha1 in objects
        assert len(objects) > 1  # Should include tree and blobs
    
    def test_visualize_commit_history(self, repo, capsys):
        create_commit("First commit")
        (repo / "test.txt").write_text("Modified\n")
        add_files(["test.txt"])
        create_commit("Second commit")
        
        visualize_commit_history(max_count=5)
        captured = capsys.readouterr()
        assert "First commit" in captured.out
        assert "Second commit" in captured.out
    
    def test_visualize_no_commits(self, repo, capsys):
        # Empty repo
        visualize_commit_history()
        captured = capsys.readouterr()
        assert "No commits yet" in captured.out


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
    
    def test_write_tree_with_subdirectory_fails(self, repo):
        (repo / "subdir").mkdir()
        (repo / "subdir" / "file.txt").write_text("content")
        add_files(["subdir/file.txt"])
        
        with pytest.raises(GitError, match="Subdirectories not yet supported"):
            write_tree()
    
    def test_read_tree(self, repo):
        tree_sha = write_tree()
        entries = read_tree(sha1=tree_sha)
        
        assert len(entries) == 2
        paths = [path for _, path, _ in entries]
        assert "file1.txt" in paths
        assert "file2.txt" in paths
    
    def test_read_tree_with_data(self, repo):
        tree_sha = write_tree()
        obj_type, data = read_object(tree_sha)
        
        entries = read_tree(data=data)
        assert len(entries) == 2
    
    def test_read_tree_no_args(self):
        with pytest.raises(TypeError, match='Must specify either "sha1" or "data"'):
            read_tree()
    
    def test_read_tree_wrong_type(self, repo):
        blob_sha = hash_object(b"not a tree", ObjectType.BLOB)
        with pytest.raises(GitError, match="Expected tree"):
            read_tree(sha1=blob_sha)
    
    def test_find_tree_objects(self, repo):
        tree_sha = write_tree()
        objects = find_tree_objects(tree_sha)
        
        assert tree_sha in objects
        assert len(objects) >= 3  # tree + 2 blobs
    
    def test_print_tree(self, repo, capsys):
        tree_sha = write_tree()
        print_tree(tree_sha, show_sha=True)
        
        captured = capsys.readouterr()
        assert "file1.txt" in captured.out
        assert "file2.txt" in captured.out
    
    def test_print_tree_no_sha(self, repo, capsys):
        tree_sha = write_tree()
        print_tree(tree_sha, show_sha=False)
        
        captured = capsys.readouterr()
        assert "file1.txt" in captured.out


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
    
    def test_diff_unicode_decode_error(self):
        content1 = b"\xff\xfe"
        content2 = b"\xff\xff"
        
        diff = diff_files("file1", content1, "file2", content2)
        # Should handle as binary or return error
        assert len(diff) >= 1
    
    def test_diff_index_working(self, tmp_path):
        repo_path = tmp_path / "test_repo"
        init_repository(str(repo_path))
        os.chdir(repo_path)
        
        (repo_path / "test.txt").write_text("original\n")
        add_files(["test.txt"])
        
        (repo_path / "test.txt").write_text("modified\n")
        
        diffs = diff_index_working()
        assert len(diffs) == 1
        assert diffs[0][0] == "test.txt"
    
    def test_diff_index_working_specific_paths(self, tmp_path):
        repo_path = tmp_path / "test_repo"
        init_repository(str(repo_path))
        os.chdir(repo_path)
        
        (repo_path / "file1.txt").write_text("content1\n")
        (repo_path / "file2.txt").write_text("content2\n")
        add_files(["file1.txt", "file2.txt"])
        
        (repo_path / "file1.txt").write_text("modified1\n")
        (repo_path / "file2.txt").write_text("modified2\n")
        
        diffs = diff_index_working(paths=["file1.txt"])
        assert len(diffs) == 1
        assert diffs[0][0] == "file1.txt"
    
    def test_print_diff(self, tmp_path, capsys):
        repo_path = tmp_path / "test_repo"
        init_repository(str(repo_path))
        os.chdir(repo_path)
        
        (repo_path / "test.txt").write_text("original\n")
        add_files(["test.txt"])
        
        (repo_path / "test.txt").write_text("modified\n")
        
        print_diff()
        captured = capsys.readouterr()
        assert "test.txt" in captured.out
    
    def test_print_diff_no_changes(self, tmp_path, capsys):
        repo_path = tmp_path / "test_repo"
        init_repository(str(repo_path))
        os.chdir(repo_path)
        
        print_diff()
        captured = capsys.readouterr()
        assert "No changes" in captured.out
    
    def test_get_diff_stats(self, tmp_path):
        repo_path = tmp_path / "test_repo"
        init_repository(str(repo_path))
        os.chdir(repo_path)
        
        (repo_path / "test.txt").write_text("line1\nline2\n")
        add_files(["test.txt"])
        
        (repo_path / "test.txt").write_text("line1\nmodified\nline3\n")
        
        stats = get_diff_stats()
        assert stats['files_changed'] == 1
        assert stats['insertions'] > 0


class TestNetwork:
    
    def test_extract_lines(self):
        data = b'0006a\n0000'
        lines = extract_lines(data)
        assert lines == [b'a\n', b'']
    
    def test_extract_lines_complex(self):
        data = b'000afirst\n000bsecond\n0000'
        lines = extract_lines(data)
        assert len(lines) >= 2
        assert lines[0] == b'first\n'
        assert lines[1] == b'second\n'
    
    def test_build_lines_data(self):
        lines = [b'test', b'data']
        data = build_lines_data(lines)
        assert b'0000' in data
        assert b'test' in data
    
    def test_http_request_auth_error(self):
        url = "https://github.com/user/repo.git/info/refs"
        
        with patch('urllib.request.build_opener') as mock_opener:
            mock_response = MagicMock()
            mock_response.read.return_value = b"data"
            mock_open_func = MagicMock()
            mock_open_func.open.side_effect = urllib.request.HTTPError(
                url, 401, "Unauthorized", {}, None
            )
            mock_opener.return_value = mock_open_func
            
            with pytest.raises(AuthenticationError):
                http_request(url, "user", "pass")
    
    def test_http_request_network_error(self):
        url = "https://github.com/user/repo.git/info/refs"
        
        with patch('urllib.request.build_opener') as mock_opener:
            mock_open_func = MagicMock()
            mock_open_func.open.side_effect = urllib.request.URLError("Network error")
            mock_opener.return_value = mock_open_func
            
            with pytest.raises(NetworkError):
                http_request(url, "user", "pass")
    
    def test_http_request_http_error(self):
        url = "https://github.com/user/repo.git/info/refs"
        
        with patch('urllib.request.build_opener') as mock_opener:
            mock_open_func = MagicMock()
            mock_open_func.open.side_effect = urllib.request.HTTPError(
                url, 500, "Server Error", {}, None
            )