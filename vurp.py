from pwn import *
import subprocess
import requests
import os
import json
import re

# This helps debugging to shutup pwntools
# context.log_level = 'ERROR'
# logging.disable(logging.CRITICAL)

# Access token for team to make api calls
access_token = open('ctfd_access_token', 'r').read().strip()

# URL of ctfd --
ctfd_url = "https://ace.ctfd.io"

# Headers needed for api calls
headers = {
    "Authorization": f"Token {access_token}",
    "Content-Type" : "application/json",
}

# Regex to help find flags in recvall
flag_pattern = r'flag\{[^}]+\}'

# ------------------------------------------------- #
# This is where your auto exploit code should be    #
# placed. This should craft the exploit locally to  #
# get the fake flag, send the exploit to the remote #
# binary, receive the flag, and submit the flag     #
# ------------------------------------------------- #

def exploit(binary, chal_id):
    # TODO: Everything
    print("Nothing here yet")


# ------------------------------------------------- #
# This function will send the payload to the remote #
# service running on that address and port          #
# ------------------------------------------------- #

def send_exploit(binary, payload, chal_id):
    url = f"ace-service-{binary}.chals.io"
    p = remote(url, 443, ssl=True, sni=url)
    p.recvuntil(">>>\n")     # Should all be the same (this will be clarified)
    p.sendline(payload)
    p.recvline()
    flag = re.findall(flag_pattern, p.recvall(timeout=0.2).decode())
    if flag:
        send_flag(flag, chal_id)
    else:
        # This comment is for Chandler <3
        print("Remote Exploit didn't work!")

# ------------------------------------------------- #
# This function will submit the flag to CTFd        #
# ------------------------------------------------- #

def send_flag(flag, chal_id):
    challenge_url = f"{ctfd_url}/api/v1/challenges/attempt"
    data = json.dumps({"challenge_id" : chal_id, "submission" : flag})
    response = requests.post(challenge_url, headers=headers, data=data)


# ------------------------------------------------- #
#                      MAIN                         #
# ------------------------------------------------- #

if __name__ == "__main__":


    # ----- Download Binary Repo ----- #
    while(1):
        try:
            subprocess.run("git clone https://github.com/tj-oconnor/ace-binaries.git", shell=True)
            os.chdir("ace-binaries/test-binaries") # CHANGE THIS EVENTUALLY
            break
        except Exception as e:
            print("Failed to clone git repo!")
    # -------------------------------- #


    # ----- Get the first chal id ---- #
    challenge_url = f"{ctfd_url}/api/v1/challenges"
    response = requests.get(challenge_url, headers=headers)
    json_data = json.loads(response.text).get("data", {})
    challenge_list = {i["name"]: int(i["id"]) for i in json_data}
    # -------------------------------- #

    # ----- Main Execution Loop! ----- #
    for binary in os.listdir():
        try:
            if binary != "flag.txt":
                # Call exploit with id of each challenge to submit flag
                exploit(binary, challenge_list[binary])
        except Exception as e:
            print(f"Failed to exploit {binary}: {e}")
    # -------------------------------- #

    print("Exploitation Complete!")
