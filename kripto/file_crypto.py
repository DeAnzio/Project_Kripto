import os
import base64
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

class FileCrypto:
    def __init__(self, password: str = None):
        self.password = password.encode() if password else b'default_file_password'
        self.key = self._derive_key()
    
    def _derive_key(self):
        """Derive 32-byte key untuk ChaCha20"""
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,  # 256-bit key untuk ChaCha20
            salt=b'file_encryption_salt',
            iterations=100000,
        )
        return kdf.derive(self.password)
    
    def encrypt_file(self, file_data):
        """Enkripsi file data dengan ChaCha20-Poly1305"""
        try:
            chacha = ChaCha20Poly1305(self.key)
            nonce = os.urandom(12)  # 96-bit nonce
            
            # Enkripsi data
            encrypted_data = chacha.encrypt(nonce, file_data, None)
            
            # Gabungkan nonce + encrypted data dan encode ke base64
            result = base64.b64encode(nonce + encrypted_data).decode('utf-8')
            return result
            
        except Exception as e:
            raise Exception(f"File encryption failed: {e}")
    
    def decrypt_file(self, encrypted_data):
        """Dekripsi file data dengan ChaCha20-Poly1305"""
        try:
            # Decode dari base64
            data = base64.b64decode(encrypted_data)
            
            # Extract nonce (12 bytes) dan ciphertext
            nonce = data[:12]
            ciphertext = data[12:]
            
            chacha = ChaCha20Poly1305(self.key)
            
            # Dekripsi data
            decrypted_data = chacha.decrypt(nonce, ciphertext, None)
            return decrypted_data
            
        except Exception as e:
            raise Exception(f"File decryption failed: {e}")
    
    def encrypt_file_to_file(self, input_path, output_path):
        """Enkripsi file dan simpan ke file"""
        try:
            with open(input_path, 'rb') as f:
                file_data = f.read()
            
            encrypted_data = self.encrypt_file(file_data)
            
            with open(output_path, 'w') as f:
                f.write(encrypted_data)
                
            return True
        except Exception as e:
            raise Exception(f"File encryption to file failed: {e}")
    
    def decrypt_file_to_file(self, input_path, output_path):
        """Dekripsi file dan simpan ke file"""
        try:
            with open(input_path, 'r') as f:
                encrypted_data = f.read()
            
            decrypted_data = self.decrypt_file(encrypted_data)
            
            with open(output_path, 'wb') as f:
                f.write(decrypted_data)
                
            return True
        except Exception as e:
            raise Exception(f"File decryption to file failed: {e}")

# Contoh penggunaan
if __name__ == "__main__":
    file_crypto = FileCrypto("file_password")
    
    # Test dengan data kecil
    test_data = b"This is test file data for encryption"
    encrypted = file_crypto.encrypt_file(test_data)
    decrypted = file_crypto.decrypt_file(encrypted)
    
    print(f"Original: {test_data}")
    print(f"Decrypted: {decrypted}")
    print(f"Match: {test_data == decrypted}")