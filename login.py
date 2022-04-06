import re
import socket
import time
from urllib.parse import urlencode

from encryption.srun_base64 import *
from encryption.srun_md5 import *
from encryption.srun_sha1 import *
from encryption.srun_xencode import *


# 将参数转化为url
def json_to_url(path, params):
    url_str = urlencode(params)
    return path + '?' + url_str


# 自己实现的GET请求
def get(dns, data):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect(dns[0][4])
        s.sendall(bytes(data, encoding="ascii"))
        head = b''
        data = b''
        content = b''
        while True:
            part = s.recv(BUFFER_LENGTH)
            if head:
                content += part
                if len(content) == required_length:
                    s.close()
                    return content
            else:
                data += part
                if data.find(b'\r\n\r\n') > -1:
                    head = data.split(b'\r\n\r\n')[0]
                    if len(data.split(b'\r\n\r\n')) == 2:
                        content = data.split(b'\r\n\r\n')[1]
                    else:
                        content = b''
                    tmp = str(re.findall(b"Content-Length: (.+?)\r\n", head))
                    required_length = int(re.findall('\d+', tmp)[0])


# 参数
BUFFER_LENGTH = 1024
GET_CHALLENGE_API = '/cgi-bin/get_challenge'
SRUN_PORTAL_API = '/cgi-bin/srun_portal'
N = '200'
TYPE = '1'
# TODO:选择连接类型
# 有线连接
# AC_ID = '163'
# 无线连接
AC_ID = '135'
ENC = 'srun_bx1'
# TODO:填入用户名和密码
username = ''
password = ''

# 获取服务器dns
dns = socket.getaddrinfo("auth4.tsinghua.edu.cn", 80, socket.AF_INET, socket.SOCK_STREAM)

# get_challenge获取token
get_challenge_params = {
    "callback": "jQuery1113017458507325873507_" + str(int(time.time() * 1000)),
    "username": username,
    "ip": '',
    "_": int(time.time() * 1000),
}
path = json_to_url(GET_CHALLENGE_API, get_challenge_params)
data = "GET {0} HTTP/1.1\r\nHost: auth4.tsinghua.edu.cn\r\nUser-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) " \
       "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/97.0.4692.99 Safari/537.36\r\n\r\n".format(path)
get_challenge_response = get(dns, data)
token = re.search(b'"challenge":"(.*?)"', get_challenge_response).group(1).decode()

# 加密处理
# info
info_temp = {
    "username": username,
    "password": password,
    "ip": '',
    "acid": AC_ID,
    "enc_ver": ENC
}
i = re.sub("'", '"', str(info_temp))
i = re.sub(" ", '', i)
i = "{SRBX1}" + get_base64(get_xencode(i, token))
# hmd5
hmd5 = get_md5(password, token)
# chkstr
chkstr = token + username
chkstr += token + hmd5
chkstr += token + AC_ID
chkstr += token + ''
chkstr += token + N
chkstr += token + TYPE
chkstr += token + i
chksum = get_sha1(chkstr)

# 登录请求
srun_portal_params = {
    'callback': 'jQuery1113017458507325873507_' + str(int(time.time() * 1000)),
    'action': 'login',
    'username': username,
    'password': '{MD5}' + hmd5,
    'ac_id': AC_ID,
    'ip': '',
    'chksum': chksum,
    'info': i,
    'n': N,
    'type': TYPE,
    'os': 'windows+10',
    'name': 'windows',
    'double_stack': '1',
    '_': int(time.time() * 1000)
}
path = json_to_url(SRUN_PORTAL_API, srun_portal_params)
data = "GET {0} HTTP/1.1\r\nHost: auth4.tsinghua.edu.cn\r\nUser-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) " \
       "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/97.0.4692.99 Safari/537.36\r\n\r\n".format(path)
srun_portal_response = get(dns, data)
res = re.search(b'"res":"(.*?)"', srun_portal_response).group(1).decode('utf-8')
print(res)
