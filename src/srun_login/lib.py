import hashlib
import hmac
import json
import math
import random
import re
import string
import time

import requests

headers = {
    "Accept":
    "text/javascript, application/javascript, application/ecmascript, application/x-ecmascript, */*; q=0.01",
    "Accept-Encoding":
    "gzip, deflate",
    "Accept-Language":
    "zh-CN,zh;q=0.9,en;q=0.8,en-GB;q=0.7,en-US;q=0.6",
    "Connection":
    "keep-alive",
    "Cookie":
    "lang=zh-CN",
    "Host":
    "10.248.98.2",
    "Referer":
    "http://10.248.98.2/srun_portal_pc?ac_id=1&srun_wait=1&theme=basic2",
    "User-Agent":
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/89.0.4389.82 Safari/537.36 Edg/89.0.774.50",
    "X-Requested-With":
    "XMLHttpRequest"
}


class SrunLogin:
    LOGIN_URL = 'http://10.248.98.2/srun_portal_pc?ac_id=1&theme=basic2'
    CHALLENGE_URL = 'http://10.248.98.2/cgi-bin/get_challenge'
    PORTAL_URL = 'http://10.248.98.2/cgi-bin/srun_portal'

    def __init__(self, username: str, password: str):
        if not username or not password:
            raise ValueError('username or password invalid')
        self.username = username
        self.password = password
        self.user_ip = None
        self.challenge = None
        self.domain = ''
        self.ac_id = '1'
        self.double_stack = 0
        self.enc = 'srun_bx1'
        random_str = ''.join(random.choices(string.digits, k=22))
        self.CALLBACKSTRING = 'jQuery' + random_str + '_' + str(
            round(time.time() * 1000))

    def _get_ip(self) -> str | None:
        resp = requests.get(url=SrunLogin.LOGIN_URL, headers=headers)
        # <input type="hidden" name="user_ip" id="user_ip" value="0.0.0.0">
        user_ip = re.search(r'<input.+user_ip.+value="([\d\.]+)">', resp.text)
        if user_ip:
            self.user_ip = user_ip.group(1)
            return user_ip.group(1)
        return None

    def _get_challenge(self) -> str | None:
        if not self.user_ip:
            raise ValueError('no user_ip')
        params = {
            'username': self.username,
            'ip': self.user_ip,
            'callback': self.CALLBACKSTRING,
            '_': str(round(time.time() * 1000))
        }
        resp = requests.get(url=SrunLogin.CHALLENGE_URL,
                            headers=headers,
                            params=params)
        # "challenge":"d3fce7",
        challenge = re.search(r'"challenge":"(\w+)"', resp.text)
        if challenge:
            self.challenge = challenge.group(1)
            return challenge.group(1)
        return None

    def _encrypt_data(self) -> dict:
        if not self.challenge or not self.user_ip:
            raise ValueError('no token or user_ip')
        n = '200'
        type_ = '1'
        token = self.challenge
        data_dict = {
            'username': self.username,
            'password': self.password,
            'ip': self.user_ip,
            'acid': self.ac_id,
            'enc_ver': self.enc
        }
        se = SrunEncrypt()
        i = se.info(data_dict, token)
        hmd5 = se.pwd(self.password, token)
        chkstr = token + self.username
        chkstr += token + hmd5
        chkstr += token + self.ac_id
        chkstr += token + self.user_ip
        chkstr += token + n
        chkstr += token + type_
        chkstr += token + i

        self.password = '{MD5}' + hmd5

        params = {
            'action': 'login',
            'username': self.username,
            'password': self.password,
            'ac_id': self.ac_id,
            'ip': self.user_ip,
            'chksum': se.chksum(chkstr),
            'info': i,
            'n': n,
            'type': type_,
            'os': 'Windows 10',
            'name': 'Windows',
            'double_stack': self.double_stack,
            'callback': self.CALLBACKSTRING,
            '_': str(round(time.time() * 1000))
        }
        return params

    def _submit(self, params: dict) -> dict:
        resp = requests.get(url=self.PORTAL_URL,
                            headers=headers,
                            params=params)
        resp_json = json.loads(resp.text[43:-1])
        result = {
            'error': resp_json.get('error', None),
            'error_msg': resp_json.get('error_msg', None),
            'suc_msg': resp_json.get('suc_msg', None)
        }
        print(result)
        return result

    def run(self) -> dict:
        self._get_ip()
        self._get_challenge()
        params = self._encrypt_data()
        return self._submit(params)


class SrunEncrypt:

    def __init__(self):
        self._PADCHAR = '='
        self._ALPHA = 'LVoJPiCN2R8G90yg+hmFHuacZ1OWMnrsSTXkYpUq/3dlbfKwv6xztjI7DeBE45QA'
        self._VERSION = '1.0'

    def _getbyte64(self, s: str, i: int) -> int:
        char = s[i]
        for idx in range(len(self._ALPHA)):
            if char == self._ALPHA[idx]:
                return idx
        raise ValueError('Cannot decode base64')

    def _setAlpha(self, s: str):
        self._ALPHA = s

    def _decode(self, s: str) -> str:
        pads = 0
        imax = len(s)
        x = []
        i = 0
        if imax == 0:
            return s
        if imax % 4 != 0:
            raise ValueError('Cannot decode base64')
        if s[imax - 1] == self._PADCHAR:
            pads = 1
            if s[imax - 2] == self._PADCHAR:
                pads = 2
            imax -= 4

        for i in range(0, imax, 4):
            b10 = (self._getbyte64(s, i) << 18) | (self._getbyte64(
                s, i + 1) << 12) | (self._getbyte64(s, i + 2) << 6) | (
                    self._getbyte64(s, i + 3))
            x.append(''.join(map(chr, [b10 >> 16,
                                       (b10 >> 8) & 255, b10 & 255])))
        if pads == 1:
            b10 = (self._getbyte64(s, i) << 18) | (self._getbyte64(
                s, i + 1) << 12) | (self._getbyte64(s, i + 2) << 6)
            x.append(''.join(map(chr, [b10 >> 16, (b10 >> 8) & 255])))
        else:
            b10 = (self._getbyte64(s, i) << 18) | (
                self._getbyte64(s, i + 1) << 12)
            x.append(chr(b10 >> 16))
        return ''.join(x)

    def _getbyte(self, s: str, i: int) -> int:
        x = ord(s[i])
        if x > 255:
            raise ValueError('INVALID_CHARACTER_ERR: DOM Exception 5')
        return x

    def _encode(self, s: str) -> str:
        x = []
        imax = len(s) - len(s) % 3
        if len(s) == 0:
            return s
        for i in range(0, imax, 3):
            b10 = (self._getbyte(s, i) << 16) | (
                self._getbyte(s, i + 1) << 8) | (self._getbyte(s, i + 2))
            x.append(self._ALPHA[b10 >> 18])
            x.append(self._ALPHA[(b10 >> 12) & 63])
            x.append(self._ALPHA[(b10 >> 6) & 63])
            x.append(self._ALPHA[b10 & 63])
        i = imax
        if len(s) - imax == 1:
            b10 = self._getbyte(s, i) << 16
            x.append(self._ALPHA[b10 >> 18] + self._ALPHA[(b10 >> 12) & 63] +
                     self._PADCHAR + self._PADCHAR)
        elif len(s) - imax == 2:
            b10 = (self._getbyte(s, i) << 16) | (self._getbyte(s, i + 1) << 8)
            x.append(self._ALPHA[b10 >> 18] + self._ALPHA[(b10 >> 12) & 63] +
                     self._ALPHA[(b10 >> 6) & 63] + self._PADCHAR)
        return ''.join(x)

    def info(self, data: dict, token: str) -> str:
        return '{SRBX1}' + self._encode(self.xEncode(json.dumps(data), token))

    def _get_ord(self, s: str, i: int) -> int:
        try:
            return ord(s[i])
        except IndexError:
            return 0

    def s(self, a: str, b: bool) -> list[int]:
        c = len(a)
        v = []
        for i in range(0, c, 4):
            v.append(
                self._get_ord(a, i) | self._get_ord(a, i + 1) << 8
                | self._get_ord(a, i + 2) << 16
                | self._get_ord(a, i + 3) << 24)
        if b:
            v.append(c)
        return v

    def l(self, a: list, b: bool) -> str | None:
        d = len(a)
        c = (d - 1) << 2
        if b:
            m = a[d - 1]
            if (m < c - 3) or (m > c):
                return None
            c = m
        for i in range(0, d):
            a[i] = ''.join(
                map(chr, [
                    a[i] & 0xff, a[i] >> 8 & 0xff, a[i] >> 16 & 0xff,
                    a[i] >> 24 & 0xff
                ]))
        if b:
            return ''.join(a)[0, c]
        else:
            return ''.join(a)

    def xEncode(self, str_: str, key: str) -> str | None:
        if not str_:
            return ''
        v = self.s(str_, True)
        k = self.s(key, False)
        if len(k) < 4:
            k = k + [0] * (4 - len(k))
        n = len(v) - 1
        z = v[n]
        c = 0x86014019 | 0x183639A0
        q = math.floor(6 + 52 / (n + 1))
        d = 0
        while q > 0:
            d = d + c & (0x8CE0D9BF | 0x731F2640)
            e = d >> 2 & 3
            p = 0
            while p < n:
                y = v[p + 1]
                m = z >> 5 ^ y << 2
                m = m + ((y >> 3 ^ z << 4) ^ (d ^ y))
                m = m + (k[(p & 3) ^ e] ^ z)
                v[p] = v[p] + m & (0xEFB8D130 | 0x10472ECF)
                z = v[p]
                p = p + 1
            y = v[0]
            m = z >> 5 ^ y << 2
            m = m + ((y >> 3 ^ z << 4) ^ (d ^ y))
            m = m + (k[(p & 3) ^ e] ^ z)
            v[n] = v[n] + m & (0xBB390742 | 0x44C6F8BD)
            z = v[n]
            q -= 1
        return self.l(v, False)

    def pwd(self, d: str, k: str) -> str:
        return hmac.new(d.encode(), k.encode(), hashlib.md5).hexdigest()

    def chksum(self, s: str) -> str:
        return hashlib.sha1(s.encode()).hexdigest()


# def test_encrypt_data():
#     s = SrunLogin('200010101', 'password')
#     s.user_ip = '10.250.37.129'
#     s.challenge = 'f4c9ab05e50171b28b4da0ca3b9dc9e8888824adaa9ccfcf6f58d2ab4ef8aafa'
#     params = s._encrypt_data()
#     assert params.get('password') == '{MD5}191592badcc88a60f398837cf6470d28'
#     assert params.get('chksum') == '3d75f3817b5671eea7e8ba8f147e9a5fbaf2ebfc'

# test_encrypt_data()
