import runpy
import sys
from types import SimpleNamespace
from unittest.mock import patch
import pytest

from minigit import cli
from minigit.exceptions import GitError


def test_run_module_main_help(tmp_path, monkeypatch):
    """Execute module as __main__ with --help to cover __main__.py"""
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv('GIT_AUTHOR_NAME', 'Test')
    monkeypatch.setenv('GIT_AUTHOR_EMAIL', 'test@example.com')
    monkeypatch.setenv('GIT_USERNAME', 'user')
    monkeypatch.setenv('GIT_PASSWORD', 'pass')

    monkeypatch.setattr(sys, 'argv', ['minigit', '--help'])
    with pytest.raises(SystemExit) as exc:
        runpy.run_module('minigit', run_name='__main__')
    # argparse exits with code 0 for --help
    assert exc.value.code in (0, None)


def test_cmd_cat_file_unhandled_type(capsys):
    """cmd_cat_file should exit when encountering an unhandled type in pretty mode"""
    args = SimpleNamespace(mode='pretty', hash_prefix='deadbeef')

    with patch('minigit.cli.read_object', return_value=('mystery', b'data')):
        with pytest.raises(SystemExit) as exc:
            cli.cmd_cat_file(args)

    captured = capsys.readouterr()
    assert 'unhandled type' in captured.err
    assert exc.value.code == 1


def test_cmd_hash_object_handles_giterror(monkeypatch):
    """cmd_hash_object should print error and exit when read_file raises GitError"""
    args = SimpleNamespace(path='nofile', type='blob', write=False)

    def bad_read(path):
        raise GitError('fail')

    monkeypatch.setattr('minigit.cli.read_file', bad_read)

    with pytest.raises(SystemExit) as exc:
        cli.cmd_hash_object(args)

    assert exc.value.code == 1


def test_cmd_commit_prints_stats(monkeypatch, capsys):
    """When get_diff_stats reports changes, cmd_commit prints stats line"""
    args = SimpleNamespace(message='Test commit', author=None)

    monkeypatch.setattr('minigit.cli.create_commit', lambda msg, author=None: 'a'*40)
    monkeypatch.setattr('minigit.cli.get_diff_stats', lambda: {'files_changed': 1, 'insertions': 2, 'deletions': 0})

    cli.cmd_commit(args)

    captured = capsys.readouterr()
    assert '1 file(s) changed' in captured.out


def test_cmd_status_all_sections(capsys):
    """cmd_status prints all sections when changed, new and deleted present"""
    args = SimpleNamespace()

    with patch('minigit.cli.get_status', return_value=(['file1'], ['file2'], ['file3'])):
        cli.cmd_status(args)

    captured = capsys.readouterr()
    assert 'Changes not staged for commit:' in captured.out
    assert 'Untracked files:' in captured.out
    assert 'Deleted files:' in captured.out


def test_cmd_commit_handles_giterror():
    """cmd_commit should exit with code 1 when create_commit raises GitError"""
    args = SimpleNamespace(message='x', author=None)

    with patch('minigit.cli.create_commit', side_effect=GitError('boom')):
        with pytest.raises(SystemExit) as exc:
            cli.cmd_commit(args)
    assert exc.value.code == 1


def test_cmd_diff_handles_giterror():
    args = SimpleNamespace()
    with patch('minigit.cli.print_diff', side_effect=GitError('boom')):
        with pytest.raises(SystemExit) as exc:
            cli.cmd_diff(args)
    assert exc.value.code == 1


def test_cmd_log_handles_giterror():
    args = SimpleNamespace(max_count=5)
    with patch('minigit.cli.visualize_commit_history', side_effect=GitError('boom')):
        with pytest.raises(SystemExit) as exc:
            cli.cmd_log(args)
    assert exc.value.code == 1


def test_cmd_ls_files_handles_giterror():
    args = SimpleNamespace(stage=False)
    with patch('minigit.cli.list_files', side_effect=GitError('boom')):
        with pytest.raises(SystemExit) as exc:
            cli.cmd_ls_files(args)
    assert exc.value.code == 1


def test_cmd_cat_file_tree_pretty(capsys):
    args = SimpleNamespace(mode='pretty', hash_prefix='zz')

    # Make read_object report a tree and read_tree return one entry
    mode_val = 0o040000  # pretend directory bits (stat.S_IFDIR)
    entry = (mode_val, 'subdir/file.txt', 'a'*40)

    with patch('minigit.cli.read_object', return_value=('tree', b'data')):
        with patch('minigit.cli.read_tree', return_value=[entry]):
            cli.cmd_cat_file(args)

    captured = capsys.readouterr()
    assert 'subdir/file.txt' in captured.out
