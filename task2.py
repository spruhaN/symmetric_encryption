# Task II. The Limits of Confidentiality
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad

key = get_random_bytes(16)
iv = get_random_bytes(16)

def submit(input_string):
    # URL encode any ‘;’ and ‘=’ characters that appear in the user provided string
    newStr = ""
    for char in input_string:
        if char == ';':
            newStr += '%3B'
        elif char == '=':
            newStr += '%3D'
        else:
            newStr += char

    insert_str = "A" * 44

    # Prepend and append to the main string and apply CBC encryption
    finalStr = "userid=456;userdata=" + insert_str + newStr + ";session-id=31337"
    ciphertext = cbc(finalStr.encode('utf-8'))

    return ciphertext

def cbc(data):
    cipher = AES.new(key, AES.MODE_ECB) # Instance of AES cipher algorithm for ECB
    ciphertext = b''                    # First thing add header to output 
    previous_block = iv

    for i in range(0, len(data), AES.block_size):
        block = data[i: i + AES.block_size]
        
        if(i + AES.block_size > len(data)):
            block = pad(block, AES.block_size) 

        xor_block = bytes(bit1 ^ bit2 for bit1, bit2 in zip(block, previous_block))
        new_block = cipher.encrypt(xor_block)
        previous_block = new_block
        ciphertext += new_block

    return ciphertext

def update(cipher_text):
    
    # CODE CHANGE HERE
    text = ';admin=true;    '.encode('utf-8')
    block_to_change = cipher_text[32:47]

    delta =  bytes(x ^ y for x, y in zip(block_to_change, text))
    print("delta", delta)
    new_block = bytes(x ^ y for x, y in zip(block_to_change, delta))
    print("new", new_block)
    new = cipher_text[:32] + new_block + cipher_text[47:]
    return new

def verify(ciphertext):
    print("verify", ciphertext)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    decrypted_data = cipher.decrypt(ciphertext)

    original_text = decrypted_data.decode('utf-8')

    print(original_text)
    return ";admin=true;" in original_text
    # parse string for pattern: ";admin=true;"

if __name__ == "__main__":
    input = "You’re the man now, dog"
    ciphertext = submit(input)

    result = verify(ciphertext)
    print(result)   # should be false

    modified_cipher = update(ciphertext)
    result_new = verify(modified_cipher)
    print(result_new)   # should be true
