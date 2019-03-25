import requests
import sys
from Crypto.Hash import SHA1

def encrypt_string(string):
    sha_signature = SHA1.new()
    sha_signature.update(string.encode('utf-8'))
    return sha_signature.hexdigest().upper()

def check_password(psswd):
    #encrypt the password
    h_sha1 = encrypt_string(psswd)
    #send first 5 letters to api
    url = "https://api.pwnedpasswords.com/range/" + h_sha1[:5]
    #returned passwords do not take into account the first 5 letters since they are already matched so neither do we
    h_sha1 = h_sha1[5:]
    
    #convert the get request into a list
    hashes_list = []
    try:
        hashes_list = requests.get(url).text.splitlines()
    except Exception:
        return -1

    for i in hashes_list:
        #if returned hash matches our hash return it
        if(i.split(":")[0] == h_sha1):
            return i.split(":")[1]
    return 0 
        

def is_used(psswd):
    is_used = check_password(psswd)
    if(is_used ==  0):
        print("password: "+ psswd +" safe to use")
    elif(is_used == -1):
        #helpful error messages!
        print("something went wrong")
    else:
        print(psswd + " is currently in use: "+ is_used + " times")

    
if __name__ == "__main__":
    try:
        is_used(sys.argv[1])
    except IndexError:
        print("is_pass_safe.py [password]")
    sys.exit(0)
