import numpy as np
from PIL import Image
import math

class PVDSteganography:
    def __init__(self):
        self.blocks_used = 0
    
    def text_to_binary(self, text):
        """Convert text to binary string"""
        return ''.join(format(ord(char), '08b') for char in text)
    
    def binary_to_text(self, binary_str):
        """Convert binary string to text"""
        # Split into 8-bit chunks
        chars = []
        for i in range(0, len(binary_str), 8):
            byte = binary_str[i:i+8]
            if len(byte) == 8:
                chars.append(chr(int(byte, 2)))
        return ''.join(chars)
    
    def get_difference_range(self, difference):
        """Tentukan range dan bits yang bisa disimpan berdasarkan difference"""
        if 0 <= difference <= 7:
            return 0, 7, 3  # 3 bits
        elif 8 <= difference <= 15:
            return 8, 15, 3  # 3 bits
        elif 16 <= difference <= 31:
            return 16, 31, 4  # 4 bits
        elif 32 <= difference <= 63:
            return 32, 63, 5  # 5 bits
        else:  # 64-255
            return 64, 255, 6  # 6 bits
    
    def embed_in_block(self, pixel1, pixel2, bits):
        """Embed bits dalam sepasang pixel"""
        if not bits:
            return pixel1, pixel2
        
        # Gunakan channel Red untuk embedding
        r1, g1, b1 = pixel1
        r2, g2, b2 = pixel2
        
        current_diff = abs(r1 - r2)
        lower_bound, upper_bound, capacity = self.get_difference_range(current_diff)
        
        # Convert bits to decimal value
        if len(bits) < capacity:
            bits = bits + '0' * (capacity - len(bits))
        
        secret_value = int(bits[:capacity], 2)
        new_diff = lower_bound + secret_value
        
        # Adjust pixels to achieve new difference
        if r1 >= r2:
            avg = (r1 + r2) // 2
            r1 = avg + math.ceil(new_diff / 2)
            r2 = avg - math.floor(new_diff / 2)
        else:
            avg = (r1 + r2) // 2
            r1 = avg - math.floor(new_diff / 2)
            r2 = avg + math.ceil(new_diff / 2)
        
        # Ensure pixel values are in valid range
        r1 = max(0, min(255, r1))
        r2 = max(0, min(255, r2))
        
        return (r1, g1, b1), (r2, g2, b2)
    
    def extract_from_block(self, pixel1, pixel2):
        """Extract bits dari sepasang pixel"""
        r1, g1, b1 = pixel1
        r2, g2, b2 = pixel2
        
        difference = abs(r1 - r2)
        lower_bound, upper_bound, capacity = self.get_difference_range(difference)
        
        secret_value = difference - lower_bound
        bits = format(secret_value, f'0{capacity}b')
        
        return bits
    
    def embed_text(self, image_path, secret_text, output_path):
        """Sembunyikan teks dalam gambar menggunakan PVD"""
        try:
            # Buka gambar
            img = Image.open(image_path)
            if img.mode != 'RGB':
                img = img.convert('RGB')
            
            pixels = np.array(img)
            height, width = pixels.shape[:2]
            
            # Convert text to binary + EOF marker
            binary_text = self.text_to_binary(secret_text) + '00000000' * 8  # 8 null bytes sebagai EOF
            
            text_index = 0
            total_bits = len(binary_text)
            
            # Process setiap 2x2 block
            for i in range(0, height - 1, 2):
                for j in range(0, width - 1, 2):
                    if text_index >= total_bits:
                        break
                    
                    # Ambil 2x2 block
                    p1 = tuple(pixels[i, j])
                    p2 = tuple(pixels[i, j + 1])
                    p3 = tuple(pixels[i + 1, j])
                    p4 = tuple(pixels[i + 1, j + 1])
                    
                    # Embed dalam dua pasang pixel
                    bits1 = binary_text[text_index:text_index+6] if text_index + 6 <= total_bits else None
                    if bits1:
                        new_p1, new_p2 = self.embed_in_block(p1, p2, bits1)
                        pixels[i, j] = new_p1
                        pixels[i, j + 1] = new_p2
                        text_index += len(bits1)
                    
                    bits2 = binary_text[text_index:text_index+6] if text_index + 6 <= total_bits else None
                    if bits2:
                        new_p3, new_p4 = self.embed_in_block(p3, p4, bits2)
                        pixels[i + 1, j] = new_p3
                        pixels[i + 1, j + 1] = new_p4
                        text_index += len(bits2)
                    
                    self.blocks_used += 1
            
            # Simpan gambar hasil
            result_img = Image.fromarray(pixels)
            result_img.save(output_path)
            
            return True, f"Embedded {len(secret_text)} characters using {self.blocks_used} blocks"
            
        except Exception as e:
            return False, f"Embedding failed: {e}"
    
    def extract_text(self, image_path):
        """Extract teks tersembunyi dari gambar"""
        try:
            img = Image.open(image_path)
            if img.mode != 'RGB':
                img = img.convert('RGB')
            
            pixels = np.array(img)
            height, width = pixels.shape[:2]
            
            extracted_bits = ""
            eof_marker = '0' * 64  # 8 null bytes dalam binary
            
            # Process setiap 2x2 block
            for i in range(0, height - 1, 2):
                for j in range(0, width - 1, 2):
                    # Ambil 2x2 block
                    p1 = tuple(pixels[i, j])
                    p2 = tuple(pixels[i, j + 1])
                    p3 = tuple(pixels[i + 1, j])
                    p4 = tuple(pixels[i + 1, j + 1])
                    
                    # Extract dari dua pasang pixel
                    bits1 = self.extract_from_block(p1, p2)
                    bits2 = self.extract_from_block(p3, p4)
                    
                    extracted_bits += bits1 + bits2
                    
                    # Check for EOF marker
                    if len(extracted_bits) >= 64 and extracted_bits[-64:] == eof_marker:
                        extracted_bits = extracted_bits[:-64]  # Remove EOF marker
                        text = self.binary_to_text(extracted_bits)
                        return True, text
            
            # Jika EOF tidak ditemukan, return semua extracted bits
            text = self.binary_to_text(extracted_bits)
            return True, text
            
        except Exception as e:
            return False, f"Extraction failed: {e}"

# Contoh penggunaan
if __name__ == "__main__":
    stego = PVDSteganography()
    
    # Embed text
    success, message = stego.embed_text("input.jpg", "Secret message here", "output.png")
    print(f"Embed: {success}, {message}")
    
    # Extract text
    success, extracted = stego.extract_text("output.png")
    print(f"Extract: {success}, Text: '{extracted}'")