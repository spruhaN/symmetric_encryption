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

    insert_str = "aaaaaaaaaaaa" # 12 a's - to close block 1 and have it be even block
    
    # prepending and appending to main string
    finalStr = "userid=456;userdata=" + insert_str + newStr + ";session-id=31337"
    ciphertext = cbc(finalStr.encode('utf-8')) 

    return ciphertext

def cbc(data):
    key = get_random_bytes(16) # Generating random key of 16 bytes or 128 bits
    iv = get_random_bytes(16) # Generating random IV of 16 bytes 
    cipher = AES.new(key, AES.MODE_ECB) # Instance of AES cipher algorithm for ECB
    
    ciphertext = []                    # First thing add header to output 
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

def update(ciphertext):
    # 100 a's / 12 a's 

    # 20 not divisible, add garbage before it 32 , add a repeated character between 33 - 48 (one whole block)
    # need to change block 2 to make predictable change in block 3
    # - repeated character block - xor it with something to create predictable 


    # C2 = [D] XOR [C1] message2 
    # C2 XOR with some delta = result will be garbage when xor decrypted message with C1
    # C3 decrypted XOR with C2 XOR delta = m3 XOR delta = delta to make changes we want in M3 
    # put repeated same character - A put it in 16 times now we can make figure it out 
    # A ;  ascii - 

    # M3 is AAAAAA and then you need to figure out what M3 is xored with delta = ;Admin=TRUE; 
    # Delta injected in block2 and then changes will be seen in block3 
    return ciphertext

def verify(decryptStr):
    cipher = AES.new(key, AES.MODE_CBC, iv)
    print(decryptStr)
    paddedStr = cipher.decrypt(decryptStr)

    # Parse string for patterns 
    return ";admin=true;" in paddedStr
    # parse string for pattern: ";admin=true;"

if __name__ == "__main__":
    input = "You’re the man now, dog"
    cipher = submit(input)

    result = verify(cipher)
    # print(result)   # should be false

    # modified_ciper = update(cipher)
    # result = verify(input)
    # print(result)   # should be true
