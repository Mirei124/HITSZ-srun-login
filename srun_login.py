import configparser
import hashlib
import hmac
import json
import os.path
import re
import time
import tkinter.messagebox
from tkinter import Label, Entry, Button, Tk

import requests

import srun_encryption

# from loguru import logger

# logger.add(r'srun.txt', rotation='1 MB')

headers = {
    "Host": "10.248.98.2",
    "Referer": "http://10.248.98.2/srun_portal_pc?ac_id=1&srun_wait=1&theme=basic2",
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) "
                  "Chrome/89.0.4389.82 Safari/537.36 Edg/89.0.774.50",
}


class Login:
    def __init__(self, username, password):
        self.login_page_url = 'http://10.248.98.2/srun_portal_pc?ac_id=1&srun_wait=1&theme=basic2'
        self.get_challenge_url = 'http://10.248.98.2/cgi-bin/get_challenge'
        self.portal_url = 'http://10.248.98.2/cgi-bin/srun_portal'
        self.callback = 'jQuery112402558423914676127_1615653299931'
        self.user_ip = ''
        self.username = username
        self.password = password

    def _get_info(self, token):
        d = {"username": self.username,
             "password": self.password,
             "ip": self.user_ip,
             "acid": "1",
             "enc_ver": "srun_bx1", }
        return srun_encryption.info(json.dumps(d), token)

    def _get_hmd5(self, token):
        return hmac.new(self.password.encode(), token.encode(), hashlib.md5).hexdigest()

    def _get_chksum(self, token, hmd5, i):
        chkstr = token + self.username
        chkstr += token + hmd5
        chkstr += token + "1"
        chkstr += token + self.user_ip
        chkstr += token + '200'
        chkstr += token + '1'
        chkstr += token + i
        return hashlib.sha1(chkstr.encode()).hexdigest()

    def run(self):
        try:
            login_page_text = requests.get(self.login_page_url, headers=headers, timeout=5).text
            self.user_ip = re.search(r'id="user_ip" value="([0-9.]+)"', login_page_text).group(1)
        except requests.exceptions.ConnectionError as e:
            # logger.warning('[失败]' + str(e))
            return -1
        params = {
            "callback": self.callback,
            "username": self.username,
            "ip": self.user_ip,
            "_": round(time.time() * 1000)
        }
        response = requests.get(self.get_challenge_url, params=params, headers=headers, timeout=5)
        return self._srun_portal(response.text)

    def _srun_portal(self, challenge):
        token = re.search(r'"challenge":"(.*?)"', challenge).group(1)
        i = self._get_info(token)
        hmd5 = self._get_hmd5(token)
        chksum = self._get_chksum(token, hmd5, i)
        password = '{MD5}' + hmd5
        params = {
            "callback": self.callback,
            "action": "login",
            "username": self.username,
            "password": password,
            "ac_id": "1",
            "ip": self.user_ip,
            "chksum": chksum,
            "info": i,
            "n": "200",
            "type": "1",
            "os": "Windows 10",
            "name": "Windows",
            "double_stack": "0",
            "_": round(time.time() * 1000),
        }
        response = requests.get(url=self.portal_url, params=params, headers=headers, timeout=5)
        if not re.search('("error":"ok"|Authentication success)', response.text):
            # logger.warning('[失败]' + response.text)
            return 0
        # logger.info('[成功]' + response.text)
        return 1


def try_login(username, password):
    login = Login(username, password)
    is_success = login.run()
    if is_success == 1:
        config = configparser.ConfigParser()
        config['default'] = {
            'username': username,
            'password': password
        }
        with open('srun.ini', 'w') as fp:
            config.write(fp)
        tkinter.messagebox.showinfo('校园网登录', '登录成功')
        return 1
    elif is_success == 0:
        tkinter.messagebox.showerror('校园网登录', '用户名或密码错误')
        return 0
    else:
        tkinter.messagebox.showerror('校园网登录', '请检查是否连接到校园网')
        return 0


class Window:
    def __init__(self):
        self.root = Tk()
        self.root.title('校园网登录')
        width = 500
        height = 300
        screen_width = self.root.winfo_screenwidth()
        screen_height = self.root.winfo_screenheight()
        window_x = (screen_width - width) // 2
        window_y = (screen_height - height) // 2
        self.root.geometry(f'{width}x{height}+{window_x}+{window_y}')

        Label(self.root, text='用户名：', bd=40).grid(row=0, column=0)
        self.E1 = Entry(self.root, width=30)
        self.E1.grid(row=0, column=1)
        Label(self.root, text='密码：', bd=40).grid(row=1, column=0)
        self.E2 = Entry(self.root, show='*', width=30)
        self.E2.grid(row=1, column=1)
        Button(self.root, text='登录', command=lambda: self.login(), width=8).grid(row=2, columnspan=2)
        self.root.mainloop()

    def login(self):
        username = self.E1.get()[:16]
        password = self.E2.get()[:16]
        if username == '' or password == '':
            tkinter.messagebox.showinfo('校园网登录', '请输入用户名和密码')
            return
        if try_login(username, password):
            self.root.destroy()


if __name__ == "__main__":
    read_config = 0
    if os.path.exists('srun.ini'):
        config = configparser.ConfigParser()
        config.read('srun.ini')
        try:
            username = config['default']['username'][:16]
            password = config['default']['password'][:16]
            read_config = 1
        except Exception as e:
            read_config = 0
            print(e)
    if read_config:
        try_login(username, password)
    else:
        window = Window()

# username = '12345'
# password = '123456'
# login = Login(username, password)
# login.run()
