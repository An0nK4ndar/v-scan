#!/usr/bin/env python
# Codename by An0nK4ndar 





import requests, argparse, sys, time
from concurrent.futures import ThreadPoolExecutor


ap = argparse.ArgumentParser(description="Multiple Scan Shell Backdoor")
ap.add_argument("--url", required=True, help="Set Domain Target")
ap.add_argument("--w", required=True, help="Set Wordlist")
ap.add_argument("--t", required=True, help="Threads")
args = vars(ap.parse_args())

def local_time():
    t = time.localtime()
    current_time = time.strftime("%H:%M:%S", t)
    return current_time
    
def exploit(url, list_password):
    host = "http://"+url+"/"+list_password
    
    req = requests.get(host).status_code
    if req == 200:
        print("\33[92m[+] \33[0m{:<55} status: \33[92m{:<20}".format(host, req))
    else:
        print("\33[91m[-] \33[0m{:<55} status: \33[91m{:<20}".format(host, req))

def brute(url):
   try:
       password = args["w"]
       with ThreadPoolExecutor(max_workers=int(args["t"])) as executor:
           with open(password, "r") as password_list:
               for list_password in password_list:
                   list_password = list_password.replace("\n", "")
                   executor.submit(exploit, url, list_password)
                   
   except requests.exceptions.ConnectionError as e:
       print("\33[91m[!] \33[0mUps, Connection Error")
   except Exception as e:
       print("\33[91m[!] \33[0mSomething Wrong")

def banner():
    ppp = """\33[92m
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\33[0m
┏━┓╻ ╻┏━╸╻  ╻     ┏┓ ┏━┓┏━╸╻┏ ╺┳┓┏━┓┏━┓┏━┓   ┏━┓┏━╸┏━┓┏┓╻┏┓╻┏━╸┏━┓
┗━┓┣━┫┣╸ ┃  ┃     ┣┻┓┣━┫┃  ┣┻┓ ┃┃┃ ┃┃ ┃┣┳┛   ┗━┓┃  ┣━┫┃┗┫┃┗┫┣╸ ┣┳┛
┗━┛╹ ╹┗━╸┗━╸┗━╸   ┗━┛╹ ╹┗━╸╹ ╹╺┻┛┗━┛┗━┛╹┗╸   ┗━┛┗━╸╹ ╹╹ ╹╹ ╹┗━╸╹┗╸\33[92m
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
╭───[ \33[93mCodename By An0nK4ndar\33[92m             ]
╰───[ \33[93mPriv8 Scanner Tempoyak\33[92m ]\33[0m

    """
    print(ppp)
    
def main():
    try:
        if len(sys.argv) < 2:
            print(parser.usage())
        else:
            print("\33[96m[#] \33[94mStarting scan on {}".format(local_time()))
            time.sleep(1)
            print("\33[96m[#] \33[94mWait a just few minutes\n")
            url = args["url"]
            brute(url)
            print("\n\33[96m[#] \33[94mScan completed on {}".format(local_time()))
            time.sleep(1)
            print("\33[96m[#] \33[94mHave a nice day :)\33[0m")
    except KeyboardInterrupt as e:
        print("\33[91m[!] \33[0mExit program")
        
if __name__ == '__main__':
   banner()
   main()
