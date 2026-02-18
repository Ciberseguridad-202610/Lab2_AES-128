# Ciberseguridad Lab 2
# AES implementation in Python using the Crypto library

import sys

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


def run():
    """
    Runs the AES encryption/decryption process based on the command-line arguments provided.
    :return: None
    """
    try:
        if len(sys.argv) > 3:
            mode = sys.argv[1].lower()
            file_path = sys.argv[2]
            key_path = sys.argv[3]  # path to the PEM file containing the RSA key

            filename = file_path.split("/")[-1]  # extract the filename from the file path

            with open(file_path, 'rb') as file:
                f_bytes = file.read()  # read the input file to be encrypted/decrypted, in bytes format

            with open(key_path, 'rb') as key_file:
                k = key_file.read()  # read the key from the key file, in bytes format

            if mode == 'e':
                nonce, ciphertext = encrypt(f_bytes, k)
                print(">> Encrypted file")
                with open(f"enc_{filename}", "wb") as file:
                    file.write( nonce + ciphertext )

            elif mode == 'd':
                if len(f_bytes) < 16:
                    print(">> Error: Encrypted file is too small to contain a nonce.")
                    sys.exit(1)
                nonce = f_bytes[:16]
                f_bytes = f_bytes[16:]
                plaintext = decrypt(f_bytes, k, nonce)
                print(">> Decrypted file")
                with open(f"dec_{filename}", "wb") as file:
                    file.write(plaintext)

            else:
                ValueError("Invalid mode. Use 'e' for encryption or 'd' for decryption.")

    except Exception as e:
        print(f">> There was an error: {e}")
        print(">> Usage: python aes.py <mode> <file_path> <key_path>")
        print(">> <mode>: 'e' for encryption or 'd' for decryption")
        print(">> <file_path>: path to the file to encrypt/decrypt")
        print(">> <key_path>: path to the key file")


if __name__ == '__main__':
    run()
