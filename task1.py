from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad


def start():
    # Read in file as plain text 

    with open('mustang.bmp', 'rb') as file:
        header = file.read(54) # Read the first 54-bytes from the file as the header
         # Read the rest of the file into another variable
        data = file.read()

        ecb(data, header) 
        cbc(data, header)


# SPRUUUUU does the cbc and ecb output look correct I'm not so sure? 

# Function 1: Electronic CodeBook (ECB) 
# Each block of 128 bytes encrypted independently
def ecb(data, header):
    # thinking this is not the way he wanted us to do this??
    key = get_random_bytes(16)              # Generating random key of 16 bytes or 128 bits 
    cipher = AES.new(key, AES.MODE_ECB)     # Instance of AES cipher algorithm for CBC 
    ciphertext = []                         # This will be what we output 
    ciphertext += header                    # First thing add header to output 

    # only give it one block at a time 
    for i in range(0, len(data), AES.block_size):
        block = data[i: i + AES.block_size]
        padded = pad(block, AES.block_size)    
    
        ciphertext += cipher.encrypt(padded)    
  
    with open("output_ecb.bmp", 'wb') as output:
        output.write(bytes(ciphertext)) # rewrite encryption in a new file 

# Function 2: Ciphertext Block Chaining (CBC)
# Each plaintext block gets XOR-ed with previous ciphertext block prior to encryption
def cbc(data, header):

    key = get_random_bytes(16) # Generating random key of 16 bytes or 128 bits
    iv = get_random_bytes(16) # Generating random IV of 16 bytes 
    cipher = AES.new(key, AES.MODE_CBC, iv) # Instance of AES cipher algorithm for CBC 
    
    ciphertext = []                         # This will be what we output 
    ciphertext += header                    # First thing add header to output 

    previous_block = iv
    for i in range(0, len(data), AES.block_size):
        block = data[i: i + AES.block_size]
        padded = pad(block, AES.block_size) 

        xor_block = bytes(bit1 ^ bit2 for bit1, bit2 in zip(padded, previous_block))

        new_block = cipher.encrypt(xor_block)
        previous_block = new_block
        ciphertext += new_block

    with open("output_cbc.bmp", 'wb') as output:
        output.write(bytes(ciphertext)) # rewrite encryption in a new file 

if __name__ == "__main__":
    start()