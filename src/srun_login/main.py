from srun_login.lib import SrunLogin
import sys


def login():
    args = sys.argv
    if len(args) < 2:
        print('usage: srun_login username [password]')
        exit(0)
    elif len(args) == 2:
        username = args[1]
        password = input('password: ')
    else:
        username = args[1]
        password = args[2]
    sl = SrunLogin(username, password)
    result = sl.run()
    if result['error'] == 'ok':
        exit(0)
    else:
        exit(1)
