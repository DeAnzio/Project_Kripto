import os
import base64
import random
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

class SuperEncrypt:
    def __init__(self, password: str = None):
        """Initialize dengan password untuk key derivation"""
        self.password = password.encode() if password else b'default_password'
        self.key = self._derive_key()
    
    def _derive_key(self):
        """Derive AES key dari password menggunakan PBKDF2"""
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=16,  # 128-bit key untuk AES128
            salt=b'fixed_salt_123',  # Dalam production, gunakan random salt
            iterations=100000,
        )
        return kdf.derive(self.password)
    
    def _add_whitespace(self, text):
        """Tambahkan whitespace acak antara karakter"""
        if not text:
            return text
            
        result = ""
        chars = list(text)
        
        for i, char in enumerate(chars):
            result += char
            # 40% probability untuk menambah whitespace setelah karakter
            if random.random() < 0.4 and i < len(chars) - 1:
                # Tambah 1-3 spasi
                result += " " * random.randint(1, 3)
        
        return result
    
    def _remove_whitespace(self, text):
        """Hapus semua whitespace berlebih"""
        if not text:
            return text
        # Hapus multiple spaces, tabs, newlines
        import re
        return re.sub(r'\s+', ' ', text).strip()
    
    def encrypt_aes_gcm(self, plaintext):
        """Enkripsi dengan AES128-GCM"""
        try:
            aesgcm = AESGCM(self.key)
            nonce = os.urandom(12)  # 96-bit nonce
            ciphertext = aesgcm.encrypt(nonce, plaintext.encode('utf-8'), None)
            return base64.b64encode(nonce + ciphertext).decode('utf-8')
        except Exception as e:
            raise Exception(f"AES encryption failed: {e}")
    
    def decrypt_aes_gcm(self, ciphertext):
        """Dekripsi dengan AES128-GCM"""
        try:
            data = base64.b64decode(ciphertext)
            nonce = data[:12]
            ciphertext_data = data[12:]
            
            aesgcm = AESGCM(self.key)
            plaintext = aesgcm.decrypt(nonce, ciphertext_data, None)
            return plaintext.decode('utf-8')
        except Exception as e:
            raise Exception(f"AES decryption failed: {e}")
    
    def super_encrypt(self, plaintext):
        """Super Enkripsi: Whitespace + AES128-GCM"""
        if not plaintext:
            return ""
        
        # Step 1: Tambah whitespace
        text_with_ws = self._add_whitespace(plaintext)
        
        # Step 2: Enkripsi dengan AES-GCM
        encrypted = self.encrypt_aes_gcm(text_with_ws)
        
        return encrypted
    
    def super_decrypt(self, ciphertext):
        """Super Dekripsi: AES128-GCM + Remove Whitespace"""
        if not ciphertext:
            return ""
        
        # Step 1: Dekripsi AES-GCM
        decrypted_with_ws = self.decrypt_aes_gcm(ciphertext)
        
        # Step 2: Hapus whitespace berlebih
        clean_text = self._remove_whitespace(decrypted_with_ws)
        
        return clean_text

# Contoh penggunaan
if __name__ == "__main__":
    crypto = SuperEncrypt("my_secret_password")
    
    original = "Ini adalah pesan rahasia"
    encrypted = crypto.super_encrypt(original)
    decrypted = crypto.super_decrypt(encrypted)
    
    print(f"Original: {original}")
    print(f"Encrypted: {encrypted}")
    print(f"Decrypted: {decrypted}")
    print(f"Match: {original == decrypted}")