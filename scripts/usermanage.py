#!/usr/bin/env python

##################################################
## Tool to manage add/delete of htpass users in OCP cluster
##################################################
## Author: mwilkers@redhat.com
## Maintainer: Rhg-aws-mgmt@redhat.com
##################################################

import argparse
import os
import sys
import pathlib
import shlex
import re
import base64
import subprocess


SCRIPT_DIR = pathlib.Path(__file__).parent.absolute()
BASE_REPO_PATH = SCRIPT_DIR.parent.absolute()
SCRATCH_HTPASS_FILE_NAME= "htpass.txt"
SCRATCH_HTPASS_FULL_FILE_NAME= f'{BASE_REPO_PATH}/build/htpass.txt'
SCRATCH_MANIFEST_FILE_NAME = "htpasswd.yaml"
SCRATCH_MANIFEST_FULL_FILE_PATH = f'{BASE_REPO_PATH}/overlays/applications/auth/{SCRATCH_MANIFEST_FILE_NAME}'
ADMIN_PERMS_FULL_DIR= f'{BASE_REPO_PATH}/overlays/applications/auth/assign-admin'

command = {}
users = []


def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument("action", type=str, help='username to take action on')
    parser.add_argument("username", type=str, nargs='?', help='username to take action on')
    parser.add_argument("--password", type=str, nargs='?', help='username to take action on')
    parser.add_argument("--count", type=int, nargs='?', help='count for actions against sequenced users')
    parser.add_argument("--start", type=int, nargs='?', help='count for actions against sequenced users')
    return parser.parse_args()

def validate_ocp_logged_in():
    cmd = "oc whoami"
    args = shlex.split(cmd)
    result = subprocess.run(args, stdout=subprocess.PIPE )

    if result.returncode != 0:
        print("Please make sure you are logged into OpenShift")
        sys.exit(1)

def validate_input(args):
    if args.action == "add" or args.action == "delete":
        if len(args.username) == 0:
            raise argparse.ArgumentTypeError("Must specify 'username' with 'add|delete' actions")
    elif args.action == "get":
        print("Retrieving")
    elif args.action == "save":
        print("Saving")
    else:
        raise argparse.ArgumentTypeError("Wrong value")

def htpasswd_execute(command):
    os.chdir(f'{BASE_REPO_PATH}/build')
    os.system(command)

def load_file():
    text = open(SCRATCH_HTPASS_FULL_FILE_NAME)
    raw_data = text.read()
    text.seek(0)
    data = text.readlines()
    for line in data:
        username, password = line.strip().split(':')
        users.append(username)
    text.close()
    return users, raw_data

def download_htpasswd():
    cmd = "oc get secret htpass-secret -o=jsonpath=\\'{.data}\\' -n openshift-config"
    args = shlex.split(cmd)

    try:
        result = subprocess.run(args, stdout=subprocess.PIPE )
    except OSError:
        print("no htpasswd file exists. Creating one")

    if result.returncode == 1:
        os.system(f'touch {SCRATCH_HTPASS_FULL_FILE_NAME}')
    else:
        test = re.search('^\'map\[htpasswd:(.*)\]\'$', result.stdout.decode('utf-8')).group(1)

        decoded_result = base64.b64decode(test).decode("utf-8")
        for line in decoded_result.splitlines():
            username, password = line.strip().split(':')
            users.append(username)


        f = open(f'{SCRATCH_HTPASS_FULL_FILE_NAME}', "w")
        f.write(decoded_result)
        f.close()

    # return users, decoded_result
    return

def write_admin_permissions(username):
    template = f"""
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  annotations:
    rbac.authorization.kubernetes.io/autoupdate: "true"
  labels:
    kubernetes.io/bootstrapping: rbac-defaults
  name: cluster-admin-{username}
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: cluster-admin
subjects:
- apiGroup: rbac.authorization.k8s.io
  kind: Group
  name: system:masters
- apiGroup: rbac.authorization.k8s.io
  kind: User
  name: {username}
"""
    f = open(f'{ADMIN_PERMS_FULL_DIR}/{username}.yaml', "w")
    f.write(template)
    f.close()

def delete_admin_permissions(username):
    os.remove(f'{ADMIN_PERMS_FULL_DIR}/{username}.yaml')

def save_htpasswd():
    cmd = f'''oc create secret generic htpass-secret 
          --from-file=htpasswd={BASE_REPO_PATH}/build/{SCRATCH_HTPASS_FILE_NAME}
          --dry-run=client
          -oyaml
          -n openshift-config'''

    args = shlex.split(cmd)
    result = subprocess.run(args, stdout=subprocess.PIPE )


    f = open(SCRATCH_MANIFEST_FULL_FILE_PATH, "w")
    f.write(result.stdout.decode('utf-8'))
    f.close()
    seal_secret(SCRATCH_MANIFEST_FULL_FILE_PATH)


def add_user( args, user_list):
    print(args)
    if args.password is None:
        command=  f"htpasswd -B {SCRATCH_HTPASS_FILE_NAME} {args.username}"
    else:
        command =  f"htpasswd -bB {SCRATCH_HTPASS_FILE_NAME} {args.username} {args.password}"

    # Check if user already exists in file
    if args.username in user_list:
        if not input(f"{args.username} already exists. Overwrite password?(y/n): ").lower().strip()[:1] == "y": sys.exit(1)
    htpasswd_execute(command)
    if 'admin' in args.username:
        write_admin_permissions(args.username)
        edit_kustomize("add", args.username)

def delete_user(username):
    command = f"htpasswd -D {SCRATCH_HTPASS_FILE_NAME} {username}"
    htpasswd_execute(command)
    if 'admin' in username:
        try:
            delete_admin_permissions(username)
        except:
            print("admin-permissions file does not exist: <continuing>")
        edit_kustomize("remove", username)

def edit_kustomize(action, username):
    os.chdir(ADMIN_PERMS_FULL_DIR)
    cmd = f"kustomize edit {action} resource {username}.yaml"
    print(cmd)
    args = shlex.split(cmd)
    try:
        result = subprocess.run(args, stdout=subprocess.PIPE )
    except:
        print("Admin permissions don't exist: <continuing>")


def set_count_and_start(args):
    count = None
    start = None

    if args.start is not None:
        start = args.start
    else:
        start = 1

    if args.count is not None:
        if args.start is not None:
            count = args.start + args.count
        else:
            count = args.count + 1
    return count, start

def seal_secret(full_path_to_file):

    dir = str(pathlib.Path(full_path_to_file).parent.absolute())
    filename = os.path.basename(full_path_to_file)
    command = f"kubeseal --format=yaml <{filename}>sealed-{filename}"
    os.chdir(f'{dir}')
    os.system(command)
    os.remove(SCRATCH_MANIFEST_FULL_FILE_PATH)

# def init_htpass():



def main():
    args = parse_args()
    validate_input(args)
    validate_ocp_logged_in()
    count, start = set_count_and_start(args)

    if args.action == "get":
        download_htpasswd()

    # elif args.action == "init":
    #     init_htpass()

    elif args.action == "add":
        user_list, decoded_data = load_file()
        if count is None:
            add_user(args, user_list)
        else:
            print("adding sequence of users")
            for i in range(start, count):
                username = f'{args.username}-{i}'
                print(f'Adding user: {username}')
                add_user(username, args, user_list)
            print("Done")


    elif args.action == "delete":
        user_list, decoded_data = load_file()
        if count is None:
            delete_user(args.username)
        else:
            print("adding sequence of users")
            for i in range(start, count):
                username = f'{args.username}-{i}'
                print(f'Deleting user: {username}')
                delete_user(username)
            print("Done")

    elif args.action == "save":
        user_list, file_contents = load_file()
        save_htpasswd()
    else:
        print("Invalid action")
        sys.exit(1)

if __name__ == "__main__":
    main()
