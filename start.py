from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad


def start():
    # Read in file as plain text 

    with open('mustang.bmp', 'rb') as file:
    # Read the first 6 bytes (52 bits) from the file as the header
    header = file.read(header_length_bits // 8)
    # Read the rest of the file into another variable
    data = file.read()

    ecb(data, header) 
    # or cbc(data, header)

# Function 1: Electronic CodeBook (ECB) 
# Each block of 128 bytes encrypted independently
def ecb(data, header):

    # thinking this is not the way he wanted us to do this??
    key = get_random_bytes(16) # Generating random key of 16 bytes or 128 bits 
    cipher = AES.new(key, AES.MODE_ECB) # Instance of AES cipher algorithm for CBC 
    encrypted_text = cipher.encrypt(pad(data, AES.block_size)) # PKCS#7 padding data

    # re-append the plaintext BMP headers
    encrypted_text = header + encrypted_text # so not the way to do this but same idea

    with open("output_ecb", 'wb') as output:
        output.write(encrypted_text) # rewrite encryption in a new file 


# are they looking for something more like this?
# def encrypt_ecb(plaintext, key):
#     ciphertext = []
#     for block in plaintext_blocks:
#         encrypted_block = aes_128_encrypt(block, key)
#         ciphertext.append(encrypted_block)
#     return ciphertext

# def encrypt_cbc(plaintext, key, iv):
#     ciphertext = []
#     previous_block = iv
#     for block in plaintext_blocks:
#         # XOR current plaintext block with previous ciphertext block (or IV)
#         xor_result = xor(block, previous_block)
#         # Encrypt the XOR result using AES-128
#         encrypted_block = aes_128_encrypt(xor_result, key)
#         ciphertext.append(encrypted_block)
#         # Set the previous ciphertext block to the current encrypted block
#         previous_block = encrypted_block
#     return ciphertext


# Function 2: Ciphertext Block Chaining (CBC)
# Each plaintext block gets XOR-ed with previous ciphertext block prior to encryption
def cbc(data, header):
    key = get_random_bytes(16) # Generating random key of 16 bytes or 128 bits
    iv = get_random_bytes(16) # Generating random IV of 16 bytes 
    cipher = AES.new(key, AES.MODE_CBC, iv) # Instance of AES cipher algorithm for CBC 
    encrypted_text = cipher.encrypt(pad(data, AES.block_size)) # Padding data

    # re-append the plaintext BMP headers
    encrypted_text = header + encrypted_text # so not the way to do this but same idea

    with open("output_ecb", 'wb') as output:
        output.write(encrypted_text) # rewrite encryption in a new file 

if __name__ == "__start__":
    start()
