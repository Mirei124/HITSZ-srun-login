from .lib import SrunLogin
import sys


def login():
    args = sys.argv
    if len(args) < 2:
        print('usage: srun_login username [password] [ip]')
        exit(0)
    username = args[1]
    if len(args) == 2:
        password = input('password: ')
    else:
        password = args[2]
    if len(args) > 3:
        ip = args[3]
    else:
        ip = None
    sl = SrunLogin(username, password, ip)
    result = sl.run()
    exit(sl.check_login_result(result))


if __name__ == "__main__":
    login()
