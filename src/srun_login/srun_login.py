#!/usr/bin/env python

import base64
import json
import random
import re
import time
import traceback
from argparse import ArgumentParser
from datetime import datetime
from hashlib import sha1

try:
    import requests
    from Crypto.Cipher import AES
    from Crypto.Util.Padding import pad
except ImportError:
    print(
        "\033[1;31mError:\033[0m Please run pip3 install requests pycryptodome -i https://mirrors.osa.moe/pypi/web/simple"
    )
    exit(1)

HEADERS = {
    "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"
}


def panic(msg: str):
    print(msg)
    traceback.print_exc()
    breakpoint()
    exit(1)


def randomString(n: int) -> str:
    chars = "ABCDEFGHJKMNPQRSTWXYZabcdefhijkmnprstwxyz2345678"
    return "".join([chars[random.randint(0, len(chars) - 1)] for _ in range(n)])


def aes_cbc_encrypt(data: bytes, key: bytes, iv: bytes) -> bytes:
    cipher = AES.new(key, AES.MODE_CBC, iv)
    padded_data = pad(data, AES.block_size)
    ciphertext = cipher.encrypt(padded_data)
    return ciphertext


def getAesString(password: str, salt: str) -> str:
    password2 = randomString(64) + password
    iv = randomString(16)
    rst = aes_cbc_encrypt(password2.encode(), salt.encode(), iv.encode())
    return base64.b64encode(rst).decode()


def test_aes_enc():
    rst = aes_cbc_encrypt(
        bytes.fromhex(
            "31ab9b5a9578d51b86c78b665f99a0e63d9cc16274eac1bb954e297e3e10ada8ca530a2d451d7486d0d5245a46a54258aebb998fba30ed8e529cc0f175e823a099887282ea055f72bbf01be61bc07612e06b4d5a5581a97e0aef283feab3e979fb9aa3a3c33dc4c52d310327307addfb29d92df8df58ccba3625b1af6ef013c8"
        ),
        bytes.fromhex("b8bf5d904e661bb83e70b33427a699ec2174ad30d1728c66ced05b46016733c2"),
        bytes.fromhex("8c1baf15c19d9127a30d3f781717cee7"),
    )
    rst = base64.b64encode(rst).decode()

    assert (
        rst
        == "mghAvOVaq18wTTZYwraHfVtA3WGdlgXfDq21HXsscdrYoupnaBXymgdE+hct4aaMWTQRn0F29jKs/bopBp1jUuQOT/pFYGau8SBtW5X4gfgHfdjC/lXNBTDXKx3ym5oJfH9qVISvNuucQffsgeRjkI04EWnWcUvcs+6ARnfwtZccdx4DPUHEO/rIpm/Ijq1C"
    )


def get_digits(n: int) -> str:
    f = time.time() * (10 ** (n - 10))
    return str(int(f))


def get_jquery_str() -> str:
    nums = "".join(map(str, random.choices(range(10), k=17)))
    return "jQuery1124" + nums + "_" + get_digits(13)


def get_user_ip() -> str:
    resp = requests.get("https://net.hitsz.edu.cn/srun_portal_pc", headers=HEADERS)
    ip = re.search(r'ip +: "([0-9\.]+?)"', resp.text)
    if not ip:
        panic("Match IP failed")

    ip = ip.group(1)  # pyright: ignore[reportOptionalMemberAccess]
    print(f"Use IP {ip}")
    return ip


def login(username: str, password: str):
    url1 = "https://ids.hit.edu.cn/authserver/login?service=http%3A%2F%2F10.248.98.2%2Fsrun_portal_sso"

    s = requests.Session()
    s.headers.update(HEADERS)
    resp = s.get(url1)
    body = resp.text

    salt = re.search(r'id="pwdEncryptSalt" value="(\S+?)"', body)
    if not salt:
        panic("salt match failed")
    else:
        salt = salt.group(1)
    execution = re.search(r'name="execution" value="(\S+?)"', body)
    if not execution:
        panic("execution match failed")
    else:
        execution = execution.group(1)
    assert salt and execution

    encryptPwd = getAesString(password, salt)
    req_body = {
        "username": username,
        "password": encryptPwd,
        "captcha": "",
        "rememberMe": "false",
        "_eventId": "submit",
        "cllt": "userNameLogin",
        "dllt": "generalLogin",
        "lt": "",
        "execution": execution,
    }
    resp = s.post(url1, data=req_body, allow_redirects=False)

    if resp.status_code < 300 or resp.status_code >= 400:
        panic("passwd error")
    target_url = resp.headers.get("Location")
    assert target_url

    ticket = target_url.split("=")[1]
    login_url = "https://net.hitsz.edu.cn/v1/srun_portal_sso?ticket=" + ticket
    print(f"Login url: {login_url}")
    resp = s.get(login_url)

    status = resp.json()
    print(status["message"])
    if hasattr(status, "data"):
        print("Online devices:")
        for i, data in enumerate(status["data"]):
            print("{:d} {:>15s} {:s}".format(i + 1, data["ip"], data["add_time"]))


def logout(username: str, ip: str):
    time_ = get_digits(10)
    data = time_ + username + ip + "1" + time_
    sign = sha1(data.encode()).hexdigest()

    params = {
        "callback": get_jquery_str(),
        "user_ip": ip,
        "username": username,
        "time": time_,
        "unbind": "1",
        "sign": sign,
        "_": time_ + str(random.randint(100, 999)),
    }

    resp = requests.get("https://net.hitsz.edu.cn/cgi-bin/rad_user_dm", params=params, headers=HEADERS)
    print(resp.text)


def query(ip: str):
    params = {"callback": get_jquery_str(), "ip": ip, "_": get_digits(13)}
    resp = requests.get("https://net.hitsz.edu.cn/cgi-bin/rad_user_info", params=params, headers=HEADERS)
    try:
        json_str = resp.text[42:-1]
        infos = json.loads(json_str)
        if not infos.get("user_name"):
            print(infos)
            print("Not login")
            return
        print("Current login: {:s} {:s}".format(infos["user_name"], infos["products_name"]))
        online_devices = json.loads(infos["online_device_detail"])
        print("Online devices:")
        i = 0
        for k, v in online_devices.items():
            add_time = datetime.fromtimestamp(float(v["add_time"])).strftime("%Y-%m-%d %H:%M:%S")
            print("{:d} {:>15s} {:s}".format(i + 1, v["ip"], add_time))
            i += 1

    except:
        panic(resp.text)


def main():
    parser = ArgumentParser()
    sub_parser = parser.add_subparsers(dest="command", required=True)
    login_parser = sub_parser.add_parser("login")
    login_parser.add_argument("username")
    login_parser.add_argument("password")

    logout_parser = sub_parser.add_parser("logout")
    logout_parser.add_argument("username")
    logout_parser.add_argument("ip", nargs="?", default=None)

    query_parser = sub_parser.add_parser("query")
    query_parser.add_argument("ip", nargs="?", default=None)

    args = parser.parse_args()

    match args.command:
        case "login":
            username = args.username.upper()
            login(username, args.password)

        case "logout":
            username = args.username.upper()
            ip = args.ip if args.ip is not None else get_user_ip()
            logout(username, ip)

        case "query":
            ip = args.ip if args.ip is not None else get_user_ip()
            query(ip)


if __name__ == "__main__":
    main()
