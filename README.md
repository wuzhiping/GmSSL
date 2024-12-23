# GmSSL
国密算法
## http://gmssl.org/
## https://www.gmssl.cn
## http://gmssl.org/docs/quickstart.html
sudo apt-get -y install cmake
```code
import unittest
from gmssl import *

class TestMain(unittest.TestCase):
    def test_sm4(self):
            key = b'1234567812345678'
            plaintext = b'block of message'
            ciphertext_hex = 'dd99d30fd7baf5af2930335d2554ddb7'
            sm4 = Sm4(key, DO_ENCRYPT)
            ciphertext = sm4.encrypt(plaintext)
            self.assertEqual(ciphertext, bytes.fromhex(ciphertext_hex))
            sm4 = Sm4(key, DO_DECRYPT)
            decrypted = sm4.encrypt(ciphertext)
            self.assertEqual(decrypted, plaintext)

    def test_sm4_cbc(self):
        key = b'1234567812345678'
        iv = b'1234567812345678'
        plaintext = b'abc'
        ciphertext_hex = '532b22f9a096e7e5b8d84a620f0f7078'
        sm4_cbc = Sm4Cbc(key, iv, DO_ENCRYPT)
        ciphertext = sm4_cbc.update(plaintext)
        ciphertext += sm4_cbc.finish()
        self.assertEqual(ciphertext, bytes.fromhex(ciphertext_hex))
        sm4_cbc = Sm4Cbc(key, iv, DO_DECRYPT)
        decrypted = sm4_cbc.update(ciphertext)
        decrypted += sm4_cbc.finish()
        self.assertEqual(decrypted, plaintext)

    def test_sm4_ctr(self):
        key = b'1234567812345678'
        iv = b'1234567812345678'
        plaintext = b'abc'
        ciphertext_hex = '890106'
        sm4_ctr = Sm4Ctr(key, iv)
        ciphertext = sm4_ctr.update(plaintext)
        ciphertext += sm4_ctr.finish()
        self.assertEqual(ciphertext, bytes.fromhex(ciphertext_hex))
        sm4_ctr = Sm4Ctr(key, iv)
        decrypted = sm4_ctr.update(ciphertext)
        decrypted += sm4_ctr.finish()
        self.assertEqual(decrypted, plaintext)

    def test_sm4_gcm(self):
        key = b'1234567812345678'
        iv = b'0123456789ab'
        aad = b'Additional Authenticated Data'
        taglen = 16
        plaintext = b'abc'
        ciphertext_hex = '7d8bd8fdc7ea3b04c15fb61863f2292c15eeaa'
        sm4_gcm = Sm4Gcm(key, iv, aad, taglen, DO_ENCRYPT)
        ciphertext = sm4_gcm.update(plaintext)
        ciphertext += sm4_gcm.finish()
        self.assertEqual(ciphertext, bytes.fromhex(ciphertext_hex))
        sm4_gcm = Sm4Gcm(key, iv, aad, taglen, DO_DECRYPT)
        decrypted = sm4_gcm.update(ciphertext)
        decrypted += sm4_gcm.finish()
        self.assertEqual(decrypted, plaintext)

res = unittest.main(argv=[''], verbosity=3, exit=False)
```
