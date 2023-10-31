# Task II. The Limits of Confidentiality
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad

key = get_random_bytes(16)
iv = get_random_bytes(16)
cipher = AES.new(key, AES.MODE_ECB) # Instance of AES cipher algorithm for ECB

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
    print("final", finalStr)
    ciphertext = cbc(finalStr.encode('utf-8'))

    return finalStr, ciphertext

def cbc(data):
    ciphertext = b''                
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

def update(input_str, cipher_text):
    desired_result = ';admin=true;    '.encode('utf-8')
    target_block = input_str[48:64]

    delta =  bytes(x ^ y for x, y in zip(target_block, desired_result))

    # want to change ciphertext to when its XORed with decrupted plaintext
    previous_block = ciphertext[32:48] # unencrypted text 
    new_prev_block = bytes(x ^ y for x, y in zip(previous_block, delta))
   
    new = cipher_text[:32] + new_prev_block + cipher_text[48:]
    return new

def decrypt_cbc(ciphertext):
    previous_block = iv
    data = b""

    for i in range(0, len(ciphertext), AES.block_size):
        block = ciphertext[i: i + AES.block_size]
        decrypted = cipher.decrypt(block)
        plain_text = bytes(bit1 ^ bit2 for bit1, bit2 in zip(previous_block, decrypted))
       
        previous_block = block
        data += plain_text

    return data

def verify(ciphertext):
    print("verify", ciphertext)
    # decrypt manually!
    decrypted_data = decrypt_cbc(ciphertext)

    original_text = decrypted_data[48:].decode('utf-8')
    print("original_text", original_text)
    return ";admin=true;" in original_text
    # parse string for pattern: ";admin=true;"

if __name__ == "__main__":
    input_str = "You’re the man now, dog"
    finalStr, ciphertext = submit(input_str)

    result = verify(ciphertext)
    print(result)   # should be false

    modified_cipher = update(finalStr.encode('utf-8'),ciphertext)
    result_new = verify(modified_cipher)
    print(result_new)   # should be true
