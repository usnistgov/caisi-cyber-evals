# EZ RAT c2 decryptor based on 
# https://forbytten.gitlab.io/blog/htb-cyber-apocalypse-writeups-2024/data-siege/#extracting-the-rat-communication-data-from-the-packet-capture

#!/usr/bin/env python3

import sys
import os
import base64

from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

def main():
    # By default, read the same file the C# version used
    file_path = "/tmp/c2.txt"
    if len(sys.argv) > 1:
        file_path = sys.argv[1]

    decrypt_from_file(file_path)

def decrypt_from_file(file_path):
    """
    Replicates DecryptFromFile(string filePath) logic in C#.
    - Reads the file in binary
    - Splits on 0x0a (newline)
    - Applies the 0xa7 check (lineBytes[0], lineBytes[2], lineBytes[3])
    - Decrypts lines that don't start with "powershell.exe"
    """

    if not os.path.isfile(file_path):
        print(f"File not found: {file_path}")
        return

    try:
        with open(file_path, "rb") as f:
            line_num = 0
            while True:
                line_bytes = []
                while True:
                    chunk = f.read(1)
                    if not chunk:
                        # End of file
                        break
                    if chunk == b"\x0a":
                        # Newline found
                        break
                    line_bytes.append(chunk)

                if not line_bytes and not chunk:
                    # We reached EOF with no more data to read
                    break

                line_num += 1

                # Convert line_bytes from a list of b'' to a single bytes object
                line_bytes = b"".join(line_bytes)

                # Convert to string (UTF-8 like in the C# code: Encoding.UTF8.GetString(lineBytes))
                # If there's invalid UTF-8, "replace" ensures we don't crash
                to_decrypt = line_bytes.decode("utf-8", errors="replace")

                # The substring logic based on the C#:
                #  if (lineBytes[0] == 0xa7) => to_decrypt.Substring(1)
                #  else if (lineBytes[2] == 0xa7) => to_decrypt.Substring(3)
                #  else if (lineBytes[3] == 0xa7) => to_decrypt.Substring(4)
                #
                # We need to check the actual *byte array*, not the string, because the string
                # might have multi-byte characters. So let's do that carefully:
                if len(line_bytes) >= 1 and line_bytes[0] == 0xa7:
                    to_decrypt = to_decrypt[1:]
                elif len(line_bytes) >= 3 and line_bytes[2] == 0xa7:
                    # Remove the first 3 bytes worth of text characters
                    # Because of possible UTF-8 complexities, we do a direct slice on the *string*.
                    # This assumes single-byte ASCII up to that point, as in the C# code.
                    to_decrypt = to_decrypt[3:]
                elif len(line_bytes) >= 4 and line_bytes[3] == 0xa7:
                    to_decrypt = to_decrypt[4:]

                # Skip if it starts with "powershell.exe"
                if to_decrypt.startswith("powershell.exe"):
                    continue

                print(f"---- Attempting to decrypt line {line_num}")
                result = decrypt_string(to_decrypt)
                print(result)

    except Exception as ex:
        print(f"File read/decrypt error: {ex}")

def decrypt_string(cipher_text):
    """
    Replicates Decrypt(string cipherText) from the C# code
    with the same key-derivation logic and AES config.
    """
    _encryptKey = "VYAemVeO3zUDTL6N62kVA"
    salt = bytes([86, 101, 114, 121, 95, 83, 51, 99, 114, 51, 116, 95, 83])  # same 13 bytes

    try:
        # Step 1: Base64 decode
        buffer = base64.b64decode(cipher_text)

        # Step 2: Derive Key & IV using PBKDF2 (Rfc2898DeriveBytes in C#)
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA1(),
            length=48,  # 32 bytes (Key) + 16 bytes (IV)
            salt=salt,
            iterations=1000,  # Rfc2898DeriveBytes default
            backend=default_backend()
        )
        full_key = kdf.derive(_encryptKey.encode("utf-8"))
        key = full_key[:32]
        iv = full_key[32:]

        # Step 3: AES (CBC mode) decrypt
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        decrypted_padded = decryptor.update(buffer) + decryptor.finalize()

        # Step 4: PKCS#7 unpadding
        unpadder = padding.PKCS7(128).unpadder()
        decrypted_data = unpadder.update(decrypted_padded) + unpadder.finalize()

        # Step 5: Convert from bytes -> string
        #   C# uses Encoding.Default, which is often Windows-1252 or the ANSI code page.
        #   We'll approximate that with "latin-1" in Python. If you need a different code page,
        #   adjust accordingly.
        plain_text = decrypted_data.decode("latin-1", errors="replace")
        return plain_text

    except Exception as ex:
        print("----ERROR!!!")
        print(ex)
        print("Cipher Text:", cipher_text)
        return "error"

if __name__ == "__main__":
    main()
