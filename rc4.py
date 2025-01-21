""" 
RC4(ARCFOUR) の実装とFMS攻撃のデモ

ちゃんと理解して作ったわけじゃないのでたぶんどっか間違ってる

参考:
    https://en.wikipedia.org/wiki/Fluhrer,_Mantin_and_Shamir_attack
    https://kevinliu.me/posts/rc4/
"""

### RC4(ARCFOUR)の実装

def xor(a, b):
    return bytes(i^ j for i, j in zip(a, b))

def keystream(key):
    S = list(range(256))
    j = 0
    for i in range(256):
        j = (j+S[i]+key[i%len(key)])%256
        S[i], S[j] = S[j], S[i]

    i = j = 0
    while True:
        i = (i+1)%256
        j = (j+S[i])%256
        S[i], S[j] = S[j], S[i]
        yield S[(S[i]+S[j])%256]

def encrypt(key, msg):
    """RC4"""
    return xor(msg, keystream(key))

# wikipediaに載ってた暗号文の例でテスト
msg = b'Plaintext'
key = b'Key'
ans = 0xBBF316E8D940AF0AD3
ctxt = encrypt(key, msg)
assert msg == encrypt(key, ctxt)
assert int.from_bytes(ctxt, 'big') == ans


# FMS攻撃のデモ

from secrets import token_bytes
from collections import Counter

# 解読対象の40bit(5byte) 秘密鍵(WEPキー)
ans = b'himi2'

def get_target_packet(key):
    iv = bytes([len(key)+3, 255]) + token_bytes(1)
    msg = b'\xAA' # WEPパケットの先頭バイト
    return iv + encrypt(iv + ans, msg)

def calc_next_keybyte(key, packet):
    key = packet[:3] + key
    S = list(range(256))
    j = 0
    for i in range(len(key)):
        j = (j + S[i] + key[i])%256
        S[i], S[j] = S[j], S[i]
    o = 0xAA ^ packet[3]
    return (o - j - S[len(key)])%256

def fms_attack():
    key = bytearray()
    for _ in range(5):
        cnt = Counter()
        for _ in range(1000):# 1000回でだいたい正しくなる
            packet = get_target_packet(key)
            b = calc_next_keybyte(key, packet)
            cnt[b] += 1
        b = cnt.most_common(1)[0][0]
        key.append(b)
    return bytes(key)

key = fms_attack()
assert key == ans

