# Ciberseguridad Lab 2
# AES implementation in Python using the Crypto library

import sys
import os

from Crypto.Cipher import AES # import AES cipher from the Crypto library

def encrypt( f: bytes, k:bytes ) -> tuple[bytes, bytes]:
    """
    Encrypts the input file using AES encryption in EAX mode.
    :param f: File to be encrypted, in bytes format.
    :param k: Encryption key, in bytes format.
    :return: Tuple of (nonce, ciphertext) of the encrypted file, in bytes format.
    """
    aes = AES.new(k, AES.MODE_EAX) # create a new AES cipher object with EAX mode
    c = aes.encrypt(f) # encrypt the input file using the AES cipher
    return aes.nonce, c  # return nonce and ciphertext

def decrypt( f: bytes, k: bytes, nonce: bytes ) -> bytes:
    """
    Decrypts the input file using AES decryption in EAX mode.
    :param f: File to be decrypted, in bytes format.
    :param k: Decryption key, in bytes format.
    :param nonce: Nonce used during encryption, in bytes format.
    :return: Plaintext of the decrypted file, in bytes format.
    """
    aes = AES.new(k, AES.MODE_EAX, nonce=nonce) # create a new AES cipher object with EAX mode and the nonce
    plaintext = aes.decrypt(f) # decrypt the input file using the AES cipher
    return plaintext

def run( m: str, f: bytes, kb: bytes, nonce: bytes = None ) -> tuple[bytes, bytes] | bytes | None:
    """
    Runs the encryption or decryption process based on the mode specified.
    :param m: Mode of operation, 'e' for encryption and 'd' for decryption.
    :param f: File to be encrypted/decrypted, in bytes format.
    :param kb: Key to be used for encryption/decryption, in bytes format.
    :param nonce: Nonce used during encryption, required for decryption, in bytes format.
    :return: For encryption mode, returns a tuple of (nonce, ciphertext) of the encrypted file, in bytes format.
             For decryption mode, returns the plaintext of the decrypted file, in bytes format.
             If an error occurs, returns None.
    """

    # Encryption mode
    if m == 'e':
        nonce, ciphertext = encrypt(f, kb)
        print(">> Encrypted file")
        return (nonce, ciphertext)

    # Decryption mode
    elif m == 'd':
        if nonce is None:
            print(">> Error: Nonce is required for decryption.")
            return None
        plaintext = decrypt(f, kb, nonce)
        print(">> Decrypted file")
        return plaintext

    # Invalid args
    else:
        print(">> Invalid mode. Use 'e' for encryption or 'd' for decryption.")
        return None

if __name__ == '__main__':
    if len(sys.argv) > 1:
        mode = sys.argv[1].lower()
        file_path = sys.argv[2]
        key_path = sys.argv[3] # path to the key file, in bytes format

        with open(key_path, 'rb') as key_file:
            key = key_file.read() # read the key from the key file

        with open(file_path, 'rb') as file:
            f_bytes = file.read() # read the input file to be encrypted/decrypted, in bytes format

        nonce = None
        if mode == 'd':
            # For decryption, read the nonce from the first 16 bytes of the file
            # The nonce is needed to initialize the AES cipher for decryption
            if len(f_bytes) < 16:
                print(">> Error: Encrypted file is too small to contain a nonce.")
                sys.exit(1)
            nonce = f_bytes[:16]
            f_bytes = f_bytes[16:]

        # run the encryption/decryption process based on the mode and get the result
        result = run(mode, f_bytes, key, nonce)

        # Extract filename from filepath
        filename = os.path.basename(file_path)
        name_without_ext = os.path.splitext(filename)[0]
        file_ext = os.path.splitext(filename)[1]

        # Encryption result -> save as a plain text file
        if result and mode == 'e':
            nonce, ciphertext = result
            output_file = f"enc_{name_without_ext}.txt"
            # Store nonce at the beginning of the output file
            with open(output_file, 'wb') as f:
                f.write(nonce + ciphertext)
            print(f">> Encrypted data written to {output_file}")

        # Decryption result -> maintain the file extension
        elif result and mode == 'd':
            output_file = f"dec_{name_without_ext}{file_ext}"
            with open(output_file, 'wb') as f:
                f.write(result)
            print(f">> Decrypted data written to {output_file}")
    else:
        # If no args are passed, give instructions :)
        print(">> Usage: python aes.py <mode> <file_path> <key_path>")
        print(">> <mode>: 'e' for encryption or 'd' for decryption")
        print(">> <file_path>: path to the file to encrypt/decrypt")
        print(">> <key_path>: path to the key file")
