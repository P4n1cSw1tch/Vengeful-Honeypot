import socket
import time
import datetime
import subprocess

######################################
LOGFILENAME = "intrusion.log"  # Enter output filename
MODE = 1  # Mode 1: Active | Mode 0: Passive

#Mail Notifications Configuration
MAILNOTIFY = 0 # Mode 0: Off | Mode 1: On
TO = ''
SUBJECT = 'Vengeful HoneyPot'
GMAIL_SENDER = ''
GMAIL_PASSWD = ''
SMTP_SERVER = 'smtp.gmail.com'
SMTP_PORT = 587
########################################
	
prevIP = "0.0.0.0"  # Do not change


def main():
    banner()
    menu()
    seperator()
    while True:
        pot()


def notifymail(TEXT):
    import smtplib

    server = smtplib.SMTP(SMTP_SERVER, SMTP_PORT)
    server.ehlo()
    server.starttls()
    try:
        server.login(GMAIL_SENDER, GMAIL_PASSWD)
    except:
        print("error logging into email")

    BODY = '\r\n'.join(['To: %s' % TO,
                        'From: %s' % GMAIL_SENDER,
                        'Subject: %s' % SUBJECT,
                        '', TEXT])

    try:
        server.sendmail(GMAIL_SENDER, [TO], BODY)
        print('email sent')
    except:
        print('error sending mail')

    server.quit()


def bindsocket():
    while True:
        try:
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            s.bind(("", Lport))
            print("Status: Awaiting Instrusion On Port:",Lport)
            s.listen(1)
            conn, addr = s.accept()
            break

        except:
            print("ERROR: binding or client connection")
            time.sleep(5)
            print(closeseperator())
            main()

    return conn, addr


def closesocket(conn):
    conn.close()


def pot():
    global s
    global prevIP

    s = socket.socket()
    conn, addr = bindsocket()

    warning = ("Intrusion From: " + str(addr[0]) + ":" + str(addr[1]) + " (" + timestamp() + ") ")
    print(warning)
    closesocket(conn)
    log(addr)

    if MAILNOTIFY == 1 and prevIP != addr[0]:
          notifymail(warning)

    if MODE == 1 and prevIP != addr[0]:
        prevIP = addr[0]
        scan(addr[0])

    print(closeseperator())


def log(addr):
    try:
        logFile = open(LOGFILENAME, "a")

    except:
        logFile = open(LOGFILENAME, "w")

    finally:
        logFile.write("Intrusion On Port: " + str(Lport) + " From: %s:%d" % (addr[0], addr[1]) + " " + "(" + timestamp() + ")" + "\n")
        logFile.close()


def logscan(scanFileName, ip):
    try:
        scanFile = open(scanFileName, "r")
        scanResult = scanFile.read()
        scanFile.close()
        logFile = open(LOGFILENAME, "a")

    except:
        print("File Error")
        return

    finally:
        logFile.write(closeseperator() + "\n")
        logFile.write("nmap scan for IP: " + str(ip) + " " + "(" + timestamp() + ")" + "\n")
        logFile.write(scanResult)
        logFile.write(closeseperator() + "\n")

    logFile.close()
    return


def timestamp():
    return datetime.datetime.fromtimestamp(time.time()).strftime('%Y-%m-%d %H:%M:%S')


def scan(ip):
    scanFileName = "lastscan.dat"
    myCmd = ("nmap -Pn -sV -T4 -O -F --version-light -oN " + scanFileName + " " + ip)

    print("Starting Scan On IP:", ip, "(" + timestamp() + ")")
    subprocess.check_output(myCmd, shell=True)
    logscan(scanFileName, ip)


def seperator():
    print("HoneyPot v1.0")
    print(closeseperator())


def closeseperator():
    return "-------------------------------------------------------------------------------"


def menu():

    global Lport
    Lport = 0

    print("##############")
    print("# 1. Telnet  #")
    print("# 2. HTTP    #")
    print("# 3. HTTPS   #")
    print("# 4. RDP     #")
    print("# 5. SSH     #")
    print("# 6. Other   #")
    print("##############")

    cmd = int(input("Choose: "))
    while cmd < 1 or cmd > 6:
        cmd = int(input("Choose: "))

    if cmd == 1:
        Lport = 23
    elif cmd == 2:
        Lport = 80
    elif cmd == 3:
        Lport = 443
    elif cmd == 4:
        Lport = 3389
    elif cmd == 5:
        Lport = 22
    elif cmd == 6:
        Lport = int(input("Enter Port Number: "))

    #  clear()


def banner():
    print(r"""	
 _   _                        __       _    
| | | |                      / _|     | |   
| | | | ___ _ __   __ _  ___| |_ _   _| |   
| | | |/ _ \ '_ \ / _` |/ _ \  _| | | | |   
\ \_/ /  __/ | | | (_| |  __/ | | |_| | |   
 \___/ \___|_| |_|\__, |\___|_|__\__,_|_|   
| | | |            __/ |     | ___ \   | |  
| |_| | ___  _ __ |___/ _   _| |_/ /__ | |_ 
|  _  |/ _ \| '_ \ / _ \ | | |  __/ _ \| __|
| | | | (_) | | | |  __/ |_| | | | (_) | |_ 
\_| |_/\___/|_|_|_|\___|\__, \_|  \___/ \__|
       /  | |  _  |      __/ |              
__   __`| | | |/' |     |___/               
\ \ / / | | |  /| |                         
 \ V / _| |_\ |_/ /                         
  \_/  \___(_)___/                          
                                            
                """)


main()