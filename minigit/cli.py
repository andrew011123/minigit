import argparse
import sys
from .repository import init_repository, get_repository_info
from .index import add_files, list_files, get_status
from .commit import create_commit, visualize_commit_history
from .diff import print_diff, get_diff_stats
from .core import read_object, hash_object, read_file, ObjectType
from .tree import read_tree, print_tree
from .network import push
from .exceptions import GitError
from .github_api import create_github_repo
import stat


def cmd_init(args):
    try:
        init_repository(args.repo)
    except GitError as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)


def cmd_add(args):
    try:
        add_files(args.paths)
        print(f"Added {len(args.paths)} file(s) to index")
    except GitError as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)


def cmd_status(args):
    try:
        changed, new, deleted = get_status()
        
        if not any([changed, new, deleted]):
            print("Nothing to commit, working tree clean")
            return
        
        if changed:
            print("Changes not staged for commit:")
            for path in changed:
                print(f"  \033[31mmodified:\033[0m   {path}")
            print()
        
        if new:
            print("Untracked files:")
            for path in new:
                print(f"  \033[31m{path}\033[0m")
            print()
        
        if deleted:
            print("Deleted files:")
            for path in deleted:
                print(f"  \033[31mdeleted:\033[0m    {path}")
            print()
        
        if new:
            print('(use "git add <file>..." to include in what will be committed)')
        
    except GitError as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)


def cmd_commit(args):
    try:
        sha1 = create_commit(args.message, author=args.author)
        print(f"[master {sha1[:7]}] {args.message}")
        
        stats = get_diff_stats()
        if stats['files_changed'] > 0:
            print(f" {stats['files_changed']} file(s) changed, "
                  f"{stats['insertions']} insertion(s)(+), "
                  f"{stats['deletions']} deletion(s)(-)")
    except GitError as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)


def cmd_diff(args):
    try:
        print_diff()
    except GitError as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)


def cmd_log(args):
    try:
        visualize_commit_history(max_count=args.max_count)
    except GitError as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)


def cmd_ls_files(args):
    try:
        files = list_files(details=args.stage)
        for f in files:
            print(f)
    except GitError as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)


def cmd_cat_file(args):
    try:
        obj_type, data = read_object(args.hash_prefix)
        
        if args.mode in ['commit', 'tree', 'blob']:
            if obj_type != args.mode:
                print(f"Error: expected {args.mode}, got {obj_type}", 
                      file=sys.stderr)
                sys.exit(1)
            sys.stdout.buffer.write(data)
        
        elif args.mode == 'size':
            print(len(data))
        
        elif args.mode == 'type':
            print(obj_type)
        
        elif args.mode == 'pretty':
            if obj_type in ['commit', 'blob']:
                sys.stdout.buffer.write(data)
            elif obj_type == 'tree':
                for mode, path, sha1 in read_tree(data=data):
                    type_str = 'tree' if stat.S_ISDIR(mode) else 'blob'
                    print(f'{mode:06o} {type_str} {sha1}\t{path}')
            else:
                print(f"Error: unhandled type {obj_type}", file=sys.stderr)
                sys.exit(1)
        
    except GitError as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)


def cmd_hash_object(args):
    try:
        sha1 = hash_object(read_file(args.path), args.type, write=args.write)
        print(sha1)
    except GitError as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)


def cmd_push(args):
    try:
        push(args.git_url, username=args.username, password=args.password)
    except GitError as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)


def cmd_info(args):
    try:
        info = get_repository_info()
        print("Repository Information:")
        print(f"  Path: {info['path']}")
        print(f"  Git directory: {info['git_dir']}")
        print(f"  Current branch: {info.get('current_branch', 'unknown')}")
        print(f"  Objects stored: {info['object_count']}")
    except GitError as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)


def cmd_create_repo(args):
    try:
        clone_url = create_github_repo(args.name, username=args.username, token=args.token)
        print(clone_url)
    except GitError as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)


def main():
    parser = argparse.ArgumentParser(
        prog='minigit',
        description='A simple Git implementation in Python'
    )
    
    subparsers = parser.add_subparsers(dest='command', metavar='command')
    subparsers.required = True
    
    parser_init = subparsers.add_parser('init', help='initialize a new repository')
    parser_init.add_argument('repo', help='directory name for new repository')
    parser_init.set_defaults(func=cmd_init)
    
    parser_add = subparsers.add_parser('add', help='add file(s) to index')
    parser_add.add_argument('paths', nargs='+', metavar='path',
                           help='path(s) of files to add')
    parser_add.set_defaults(func=cmd_add)
    
    parser_status = subparsers.add_parser('status', help='show working copy status')
    parser_status.set_defaults(func=cmd_status)
    
    parser_commit = subparsers.add_parser('commit', 
                                         help='commit current state of index')
    parser_commit.add_argument('-m', '--message', required=True,
                              help='commit message')
    parser_commit.add_argument('-a', '--author',
                              help='author in format "Name <email>"')
    parser_commit.set_defaults(func=cmd_commit)
    
    parser_diff = subparsers.add_parser('diff',
                                       help='show diff of changed files')
    parser_diff.set_defaults(func=cmd_diff)
    
    parser_log = subparsers.add_parser('log', help='show commit history')
    parser_log.add_argument('-n', '--max-count', type=int, default=20,
                           help='limit number of commits to show')
    parser_log.set_defaults(func=cmd_log)
    
    parser_ls = subparsers.add_parser('ls-files', help='list files in index')
    parser_ls.add_argument('-s', '--stage', action='store_true',
                          help='show object details')
    parser_ls.set_defaults(func=cmd_ls_files)
    
    parser_cat = subparsers.add_parser('cat-file', help='display object contents')
    parser_cat.add_argument('mode',
                           choices=['commit', 'tree', 'blob', 'size', 'type', 'pretty'],
                           help='display mode')
    parser_cat.add_argument('hash_prefix', help='SHA-1 hash or prefix')
    parser_cat.set_defaults(func=cmd_cat_file)
    
    parser_hash = subparsers.add_parser('hash-object',
                                       help='hash and optionally store object')
    parser_hash.add_argument('path', help='file to hash')
    parser_hash.add_argument('-t', '--type',
                            choices=['commit', 'tree', 'blob'],
                            default='blob',
                            help='object type')
    parser_hash.add_argument('-w', '--write', action='store_true',
                            help='write object to store')
    parser_hash.set_defaults(func=cmd_hash_object)
    
    parser_push = subparsers.add_parser('push', help='push to remote repository')
    parser_push.add_argument('git_url', help='repository URL')
    parser_push.add_argument('-u', '--username', help='authentication username')
    parser_push.add_argument('-p', '--password', help='authentication password')
    parser_push.set_defaults(func=cmd_push)
    
    parser_info = subparsers.add_parser('info', help='show repository information')
    parser_info.set_defaults(func=cmd_info)

    parser_create = subparsers.add_parser('create-repo', help='create a GitHub repository for the current user')
    parser_create.add_argument('name', help='name of the repository to create')
    parser_create.add_argument('-u', '--username', help='GitHub username (optional)')
    parser_create.add_argument('-t', '--token', help='GitHub personal access token or password')
    parser_create.set_defaults(func=cmd_create_repo)
    
    args = parser.parse_args()
    args.func(args)


if __name__ == '__main__':
    main()
