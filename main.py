import unittest
from rsa import setKeys, encrypt, decrypt, digital_sign, verify_auth

class TestRSA(unittest.TestCase):
    def setUp(self):
        self.public_k, self.private_k = setKeys(1024)
        self.test_str = "don't roll your own crypto"

    def test_rsaEncryption(self):
        encrypted_data = encrypt(self.test_str, self.public_k)
        decrypted_data = decrypt(encrypted_data, self.private_k)
        message = "encryption isn't working properly"
        self.assertEqual(self.test_str, decrypted_data, message)

    def test_rsaSigning(self):
        digital_signature = digital_sign(self.test_str, self.private_k)
        verification = verify_auth(self.test_str, digital_signature, self.public_k)
        self.assertEqual(True, verification)


if __name__ == '__main__':
    unittest.main()
