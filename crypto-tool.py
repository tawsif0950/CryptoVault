import os
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
import argparse

def generate_keys():
    """Generate RSA public and private keys."""
    key = RSA.generate(2048)
    private_key = key.export_key()
    public_key = key.publickey().export_key()
    
    with open('private_key.pem', 'wb') as f:
        f.write(private_key)
    with open('public_key.pem', 'wb') as f:
        f.write(public_key)

def encrypt_file(input_file, output_file):
    """Encrypt a file using AES-256-CBC and encrypt the AES key with RSA."""
    # Load the public key
    with open('public_key.pem', 'rb') as f:
        public_key = RSA.import_key(f.read())
    
    # Generate a random AES-256 key
    aes_key = get_random_bytes(32)
    
    # Encrypt the data with AES
    cipher_aes = AES.new(aes_key, AES.MODE_CBC)
    iv = cipher_aes.iv
    
    with open(input_file, 'rb') as f:
        plaintext = f.read()
    
    ciphertext = cipher_aes.encrypt(pad(plaintext, AES.block_size))
    
    # Encrypt the AES key with RSA
    cipher_rsa = PKCS1_OAEP.new(public_key)
    enc_aes_key = cipher_rsa.encrypt(aes_key)
    
    # Write the encrypted data to the output file
    with open(output_file, 'wb') as f:
        f.write(enc_aes_key)
        f.write(iv)
        f.write(ciphertext)

def decrypt_file(input_file, output_file):
    """Decrypt a file using the RSA private key to retrieve the AES key."""
    # Load the private key
    with open('private_key.pem', 'rb') as f:
        private_key = RSA.import_key(f.read())
    
    # Read the encrypted file components
    with open(input_file, 'rb') as f:
        enc_aes_key = f.read(256)  # RSA 2048-bit encrypted AES key (256 bytes)
        iv = f.read(16)            # AES IV (16 bytes)
        ciphertext = f.read()      # AES encrypted data
    
    # Decrypt the AES key
    cipher_rsa = PKCS1_OAEP.new(private_key)
    aes_key = cipher_rsa.decrypt(enc_aes_key)
    
    # Decrypt the data with AES
    cipher_aes = AES.new(aes_key, AES.MODE_CBC, iv)
    plaintext = unpad(cipher_aes.decrypt(ciphertext), AES.block_size)
    
    with open(output_file, 'wb') as f:
        f.write(plaintext)

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Secure File Encryption Tool using RSA and AES')
    subparsers = parser.add_subparsers(dest='command', help='Available commands')
    
    # Generate keys command
    subparsers.add_parser('generate_keys', help='Generate RSA public and private keys')
    
    # Encrypt command
    encrypt_parser = subparsers.add_parser('encrypt', help='Encrypt a file')
    encrypt_parser.add_argument('input', help='Input file to encrypt')
    encrypt_parser.add_argument('output', help='Output encrypted file')
    
    # Decrypt command
    decrypt_parser = subparsers.add_parser('decrypt', help='Decrypt a file')
    decrypt_parser.add_argument('input', help='Input file to decrypt')
    decrypt_parser.add_argument('output', help='Output decrypted file')
    
    args = parser.parse_args()
    
    if args.command == 'generate_keys':
        generate_keys()
        print("RSA keys generated: private_key.pem and public_key.pem")
    elif args.command == 'encrypt':
        encrypt_file(args.input, args.output)
        print(f"File encrypted: {args.output}")
    elif args.command == 'decrypt':
        decrypt_file(args.input, args.output)
        print(f"File decrypted: {args.output}")
    else:
        parser.print_help()
