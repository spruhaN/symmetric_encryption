from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes




# We will keep this key secret 
key = get_random_bytes(128) 
cipher = AES.new(key, AES.MODE_CBC)

# take in plaintext file 
# generate random key 
# general function area - take in file, make key
# before sending file + remove header 
# call function ECB or CBC 
# reapply header 
# output result 

# add padding as we loop through 




# traverse threw the plaintext using AES following 128 bit increments until the end 
# grab header to get meta data and to ensure no encryption of header
# re-append the plaintext BMP headers!)
# add padding 

# Function 1: ECB 

# Function 2: CBC 
# generate random IV (case of CBC )

# write encryption of plaintext into new file 