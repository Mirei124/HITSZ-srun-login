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
from loguru import logger

import srun_encryption

logger.add(r'srun_log.txt', rotation='1 MB')

headers = {
    "Accept": "text/javascript, application/javascript, application/ecmascript, application/x-ecmascript, */*; q=0.01",
    "Accept-Encoding": "gzip, deflate",
    "Accept-Language": "zh-CN,zh;q=0.9,en;q=0.8,en-GB;q=0.7,en-US;q=0.6",
    "Connection": "keep-alive",
    "Cookie": "lang=zh-CN",
    "Host": "10.248.98.2",
    "Referer": "http://10.248.98.2/srun_portal_pc?ac_id=1&srun_wait=1&theme=basic2",
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) "
                  "Chrome/89.0.4389.82 Safari/537.36 Edg/89.0.774.50",
    "X-Requested-With": "XMLHttpRequest"}


class Login:
    login_page_url = 'http://10.248.98.2/srun_portal_pc?ac_id=1&srun_wait=1&theme=basic2'
    get_challenge_url = 'http://10.248.98.2/cgi-bin/get_challenge'
    portal_url = 'http://10.248.98.2/cgi-bin/srun_portal'
    callback = 'jQuery112402558423914676127_1615653299931'
    user_ip = ''

    def __init__(self, username, password):
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

    @staticmethod
    def format_error(error_msg):
        if error_msg == 'ok':
            return 'ok'
        error_dict = {"H": "时", "M": "分", "S": "秒", "E0000": "登录成功", "E2401": "User-Request",
                      "E2402": "Lost-Carrier", "E2404": "Idle-Timeout", "E2405": "Session-Timeout",
                      "E2406": "Admin-Reset", "E2407": "Admin-Reboot", "E2408": "Port-Error",
                      "E2409": "NAS-Error", "E2410": "NAS-Request", "E2411": "NAS-Reboot",
                      "E2412": "Port-Unneeded", "E2413": "Port-Preempted", "E2414": "Port-Suspended",
                      "E2415": "Service-Unavailable", "E2416": "Callback", "E2417": "User-Error",
                      "E2531": "用户不存在", "E2532": "您的两次认证的间隔太短,请稍候10秒后再重试登录", "E2533": "密码错误次数超过限制，请5分钟后再重试登录",
                      "E2534": "有代理行为被暂时禁用", "E2535": "认证系统已经被禁用", "E2536": "授权已过期", "E2553": "帐号或密码错误",
                      "E2601": "您使用的不是专用客户端,IPOE-PPPoE混杂模式请联系管理员重新打包客户端程序", "E2602": "您还没有绑定手机号或绑定的非联通手机号码",
                      "E2606": "用户被禁用", "E2607": "接口被禁用", "E2611": "您当前使用的设备非该账号绑定设备请绑定或使用绑定的设备登入",
                      "E2613": "NASPORT绑定错误", "E2614": "MAC地址绑定错误", "E2615": "IP地址绑定错误", "E2616": "用户已欠费",
                      "E2620": "已经在线了", "E2621": "已经达到授权人数", "E2806": "找不到符合条件的产品", "E2807": "找不到符合条件的计费策略",
                      "E2808": "找不到符合条件的控制策略", "E2833": "IP不在DHCP表中，需要重新拿地址。", "E2840": "校内地址不允许访问外网",
                      "E2841": "IP地址绑定错误", "E2842": "IP地址无需认证可直接上网", "E2843": "IP地址不在IP表中",
                      "E2844": "IP地址在黑名单中", "E2901": "第三方认证接口返回的错误信息", "E6500": "认证程序未启动", "E6501": "用户名输入错误",
                      "E6502": "注销时发生错误，或没有帐号在线", "E6503": "您的账号不在线上", "E6504": "注销成功，请等1分钟后登录",
                      "E6505": "您的MAC地址不正确", "E6506": "用户名或密码错误，请重新输入", "E6507": "您无须认证，可直接上网",
                      "E6508": "您已欠费，请尽快充值", "E6509": "您的资料已被修改正在等待同步，请2钟分后再试。如果您的帐号允许多个用户上线，请到WEB登录页面注销",
                      "E6510": "您的帐号已经被删除", "E6511": "IP已存在，请稍后再试", "E6512": "在线用户已满，请稍后再试",
                      "E6513": "正在注销在线账号，请重新连接", "E6514": "你的IP地址和认证地址不附，可能是经过小路由器登录的",
                      "E6515": "系统已禁止客户端登录，请使用WEB方式登录", "E6516": "您的流量已用尽", "E6517": "您的时长已用尽",
                      "E6518": "您的IP地址不合法，可能是：一、与绑的IP地址附；二、IP不允许在当前区域登录", "E6519": "当前时段不允许连接",
                      "E6520": "抱歉，您的帐号已禁用", "E6521": "您的IPv6地址不正确，请重新配置IPv6地址",
                      "E6522": "客户端时间不正确，请先同步时间（或者是调用方传送的时间格式不正确，不是时间戳；客户端和服务器之间时差超过2小时，括号里面内容不要提示给客户）",
                      "E6523": "认证服务无响应", "E6524": "计费系统尚未授权，目前还不能使用", "E6525": "后台服务器无响应;请联系管理员检查后台服务运行状态",
                      "E6526": "您的IP已经在线;可以直接上网;或者先注销再重新认证", "E6527": "当前设备不在线", "E6528": "您已经被服务器强制下线",
                      "E6529": "身份验证失败，但不返回错误消息", "E10039": "访客账号的使用次数已超过最大限制",
                      "ChallengeExpireError": "Challenge时间戳错误", "SignError": "签名错误",
                      "NotOnlineError": "当前设备不在线", "VcodeError": "验证码错误", "SpeedLimitError": "认证请求太频繁，请稍后10s重试",
                      "SrunPortalServerError": "Portal服务请求错误", "AuthResaultTimeoutErr": "Portal服务请求超时",
                      "IpAlreadyOnlineError": "本机IP已经使用其他账号登陆在线了",
                      "MemoryDbError": "SRun认证服务(srun_portal_server)无响应", "GetVerifyCode": "获取验证码",
                      "CasUsernameIsEmpty": "获取CAS用户名失败", "ProvisionalReleaseFail": "临时放行失败",
                      "INFOFailedBASRespondTimeout": "BAS无响应", "LogoutOK": "DM下线成功",
                      "SendVerifyCodeOK": "验证码发送成功", "PhoneNumberError": "手机号错误",
                      "IsEvokingWeChat": "正在唤起微信...", "Info": "信息", "OK": "确认",
                      "CheckServerTimestamp": "检查服务器时间", "TimestampError": "时间戳错误", "TypeError": "加密类型错误",
                      "VerifyCodeError": "验证码错误", "ACIDIsRequired": "缺少ACID",
                      "TypeIsEmptyOrError": "微信请求类型为空或错误", "ACIDIsEmpty": "缺少ACID", "BSSIDIsEmpty": "缺少BSSID",
                      "MACIsEmpty": "缺少MAC", "TokenIsEmpty": "缺少Token", "WeChatOptionNotFound": "未找到微信配置",
                      "CreateVisitorError": "创建访客失败", "NoResponseDataError": "无响应数据",
                      "VcodeTooOftenError": "两次间隔时间太短", "Wait": "请稍等...", "YouAreNotOnline": "该设备不在线",
                      "NasTypeNotFound": "NAS设备不存在",
                      "UserMustModifyPassword": "您的账号不存在或者密码比较简单，存在安全隐患，请登录自服务重置您的密码",
                      "AuthInfoError": "刷新页面后再次登录", "TokenError": "验证码发送失败",
                      "MissingRequiredParametersError": "登录失败，请联系网络管理员", "NoAcidError": "网络设备出问题，请稍候",
                      "OtpServerError": "身份验证器服务故障", "OtpCodeCheckError": "口令验证失败",
                      "OtpCodeHasBeenUsed": "动态码已被使用",
                      "E2901:(Thirdparty1)bind_user2:ldap_binderror": "账号或密码错误",
                      "E2901:(Thirdparty1)ldap_first_entryerror": "账号或密码错误",
                      "CHALLENGEfailed,BASrespondtimeout.": "网络连接超时，请稍后重试", "INFOError锛宔rr_code=2": "设备不在认证范围内",
                      "TheServerIsNotResponding": "服务等待超时，请稍后重试", "LimitDomainErr": "请使用中科院允许的邮箱进行登录",
                      "BxResaultTimeoutErr": "北向接口服务器异常，请查看日志或检查北向接口服务", "BxAddUserErr": "添加用户失败，请联系管理员",
                      "ZkNetworkError": "科技云服务异常", "ZkUserError": "登录中国科技云通行证的账号无效，请检查账号是否正确",
                      "BrowserVersionError": "请使用Chrome浏览器或360浏览器极速模式", "SsoServerError": "单点登陆服务异常，请检查服务",
                      "IPHasBeenOnlinePleaseLogout": "您的设备已经在线，不可重复提交"}
        error_msg = re.sub(r'(_|, | |^)(\S)', lambda x: x.group(2).upper(), error_msg)
        if error_msg in error_dict:
            return error_dict[error_msg]
        else:
            return error_msg

    def run(self):
        # 获取token
        try:
            login_page_text = requests.get(self.login_page_url, headers=headers, timeout=5).text
            self.user_ip = re.search(r'id="user_ip" value="([0-9.]+)"', login_page_text).group(1)
        except requests.exceptions.ConnectionError:
            return '网络连接错误(ConnectionError)'
        params = {
            "callback": self.callback,
            "username": self.username,
            "ip": self.user_ip,
            "_": round(time.time() * 1000)
        }
        response = requests.get(self.get_challenge_url, params=params, headers=headers, timeout=5)
        token = re.search(r'"challenge":"(.*?)"', response.text).group(1)

        # 加密
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
        logger.info(response.text)

        # 检查登录结果
        error_info = re.search(r'"error":"(.*?)"', response.text)
        if error_info:
            return self.format_error(error_info.group(1))
        else:
            return response.text


def try_login(username, password):
    login = Login(username, password)
    login_result = login.run()
    if login_result == 'ok':
        temp = Tk()
        temp.geometry('1x1+20000+20000')
        tkinter.messagebox.showinfo('登录成功', '登录成功')
        temp.destroy()
        config = configparser.ConfigParser()
        config['default'] = {
            'username': username,
            'password': password
        }
        with open('srun_config.ini', 'w') as fp:
            config.write(fp)
        return 1
    else:
        temp = Tk()
        temp.geometry('1x1+20000+20000')
        tkinter.messagebox.showerror('登录失败', login_result)
        temp.destroy()
        return 0


class Window:
    def __init__(self):
        self.root = Tk()
        self.root.title('校园网登录')
        # 设置窗口居中
        width = 500
        height = 300
        screen_width = self.root.winfo_screenwidth()
        screen_height = self.root.winfo_screenheight()
        window_x = (screen_width - width) // 2
        window_y = (screen_height - height) // 2
        self.root.geometry(f'{width}x{height}+{window_x}+{window_y}')

        # 设置布局
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
            tkinter.messagebox.showinfo('提示', '请输入用户名和密码')
            return
        if try_login(username, password):
            self.root.destroy()


def main():
    if os.path.exists('srun_config.ini'):
        config = configparser.ConfigParser()
        config.read('srun_config.ini')
        try:
            username = config['default']['username'][:16]
            password = config['default']['password'][:16]
        except Exception as e:
            logger.error(e)
            Window()
            return
        if try_login(username, password):
            return
    Window()


if __name__ == "__main__":
    main()

# username = '12345'
# password = '123456'
# login = Login(username, password)
# login.run()
