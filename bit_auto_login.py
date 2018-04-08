import base64
import hashlib
import math
import urllib.request
import urllib.parse
import hmac
import time
import json
import re
import os

def ordat(msg, idx):
    if len(msg) > idx:
        return ord(msg[idx])
    return 0
 
def sencode(msg, key):
    l = len(msg)
    pwd = []
    for i in range(0, l, 4):
        pwd.append(
            ordat(msg, i) | ordat(msg, i + 1) << 8 | ordat(msg, i + 2) << 16
            | ordat(msg, i + 3) << 24)
    if key:
        pwd.append(l)
    return pwd
 
 
def lencode(msg, key):
    l = len(msg)
    ll = (l - 1) << 2
    if key:
        m = msg[l - 1]
        if m < ll - 3 or m > ll:
            return
        ll = m
    for i in range(0, l):
        msg[i] = bytes([(msg[i] >> (_ * 8)) & 0xff for _ in range(4)])
    if key:
        return b"".join(msg)[0:ll]
    return b"".join(msg)
 
 
def xencode(msg, key):
    if msg == "":
        return ""
    pwd = sencode(msg, True)
    pwdk = sencode(key, False)
    if len(pwdk) < 4:
        pwdk = pwdk + [0] * (4 - len(pwdk))
    n = len(pwd) - 1
    z = pwd[n]
    y = pwd[0]
    c = 0x86014019 | 0x183639A0
    m = 0
    e = 0
    p = 0
    q = math.floor(6 + 52 / (n + 1))
    d = 0
    while 0 < q:
        d = d + c & (0x8CE0D9BF | 0x731F2640)
        e = d >> 2 & 3
        p = 0
        while p < n:
            y = pwd[p + 1]
            m = z >> 5 ^ y << 2
            m = m + ((y >> 3 ^ z << 4) ^ (d ^ y))
            m = m + (pwdk[(p & 3) ^ e] ^ z)
            pwd[p] = pwd[p] + m & (0xEFB8D130 | 0x10472ECF)
            z = pwd[p]
            p = p + 1
        y = pwd[0]
        m = z >> 5 ^ y << 2
        m = m + ((y >> 3 ^ z << 4) ^ (d ^ y))
        m = m + (pwdk[(p & 3) ^ e] ^ z)
        pwd[n] = pwd[n] + m & (0xBB390742 | 0x44C6F8BD)
        z = pwd[n]
        q = q - 1
    return lencode(pwd, False)

def login(username, password):
    d = dict(zip(b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=",b"LVoJPiCN2R8G90yg+hmFHuacZ1OWMnrsSTXkYpUq/3dlbfKwv6xztjI7DeBE45QA="))
    acid = "1"
    res = urllib.request.urlopen("http://10.0.0.55/cgi-bin/get_challenge?callback=jsonp%d&username=%s&ip=" % (int(time.time() * 100), username))
    res = res.read().decode()
    res = json.loads(res[res.find("{"): res.find("}") + 1])
    token = res['challenge']
    ip = res['online_ip']
    msg = '{"username":"%s","password":"%s","ip":"%s","acid":"%s","enc_ver":"srun_bx1"}'%(username, password,ip,acid)
    msg = base64.b64encode(xencode(msg, token))
    msg = bytes([d[_] for _ in msg])
    info = "{SRBX1}" + msg.decode()
    md5 = hmac.new(token.encode(),b"", digestmod='md5').hexdigest()
    data = {
        "callback":"jsonp%d" % int(time.time() * 100),
        "action":"login",
        "username":username,
        "password":"{MD5}" + md5,
        "ac_id":"1",
        "ip": ip,
        "info": info,
        "chksum": hashlib.sha1((token + username + token + md5 + token + acid + token + ip + token + "200" + token + "1" + token + info).encode()).hexdigest(),
        "n":"200",
        "type":"1"
    }
    res = urllib.request.urlopen("http://10.0.0.55/cgi-bin/srun_portal?" + urllib.parse.urlencode(data))
    print(res.read().decode())


def ping(url='www.baidu.com'):
    return os.system("ping %s -n 1 -4")


if __name__ == "__main__":
    while 1:
        if ping(): login("xx", "xx")
        time.sleep(5 * 60)