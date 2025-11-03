
CREATE DATABASE IF NOT EXISTS kripto_db;
USE kripto_db;

-- Tabel users untuk login
CREATE TABLE IF NOT EXISTS users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(50) UNIQUE NOT NULL,
    password VARCHAR(32) NOT NULL, -- MD5 hash (32 characters)
    email VARCHAR(100),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Tabel untuk menyimpan pesan terenkripsi
CREATE TABLE IF NOT EXISTS encrypted_messages (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT,
    original_text TEXT,
    encrypted_text TEXT,
    encryption_type VARCHAR(50),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id)
);

-- Tabel untuk file terenkripsi
CREATE TABLE IF NOT EXISTS encrypted_files (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT,
    filename VARCHAR(255),
    file_size INT,
    encryption_type VARCHAR(50),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id)
);

-- Tabel untuk gambar steganografi
CREATE TABLE IF NOT EXISTS stego_images (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT,
    original_image VARCHAR(255),
    stego_image VARCHAR(255),
    hidden_text TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id)
);

-- Insert sample user (password: 'admin123' -> MD5: 0192023a7bbd73250516f069df18b500)
INSERT INTO users (username, password, email) VALUES 
('admin', '0192023a7bbd73250516f069df18b500', 'admin@example.com');