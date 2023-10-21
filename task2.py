# Task II. The Limits of Confidentiality
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad

key = get_random_bytes(16)
iv = get_random_bytes(16)


# THIS NEEDS WORK I started but need help finishing - I had to step back and go study
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

    # prepending and appending to main string
    finalStr = "userid=456;userdata=" + newStr + ";session-id=31337"

    # pad the final string (using PKCS#7)
    paddedStr = pad(finalStr, AES.block_size)

    # encrypt the padded string using AES-128-CBC
    # @ SPRU this all you! 
    cipher = AES.new(key, AES.MODE_CCB) 
    cipher.encrypt(paddedStr)
    cipher_text = ""
    # encryption part finish


    return cipher_text

def update(cipher_text):
    # need to find a way to modify the ciphertext in such a way that, after decryption?/
    # How do i do this?? 
    # need help
    cipher_text[16] ^= 1 
    return 

def verify(decryptStr):
    # decrypt string 
    # @ Spru put your decrypt stuff here
    cipher = AES.new(key, AES.MODE_ECB, iv)
    paddedStr = cipher.decrypt(decryptStr)
    # decrypt over 

    # Parse string for patterns 
    return ";admin=true;" in paddedStr
    # parse string for pattern: ";admin=true;"

if __name__ == "__main__":
    input = "You’re the man now, dog"
    cipher = submit(input)
    result = verify(input)
    print(result)   # should be false

    modified_ciper = update(cipher)
    result = verify(input)
    print(result)   # should be true
