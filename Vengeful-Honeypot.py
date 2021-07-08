#!/usr/bin/python
# -*- coding: utf-8 -*-
# Author: Github: sonicCrypt0r (https://github.com/sonicCrypt0r)
# Description: This Script Is For Creating a Honeypot

# Global Imports
from sys import stdout
sprint = stdout.write

import socket
import time
import datetime
import subprocess

######################################
VERSION = 0.01
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
    checkUpdate()
    menu()
    seperator()
    while True:
        pot()


def checkUpdate():
# This function checks for updates from Github
    import requests
    import os
    import sys
    # Disable no SSL verification console log
    from requests.packages.urllib3.exceptions import InsecureRequestWarning
    requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

    curScriptName = sys.argv[0]
    newScriptName = sys.argv[0].split(".py")[0] + "_new.py"

    # Remove 'Cisco-Device-Analyzer_new.py' and 'updater.bat' which may be from previous updates
    try:
        os.remove(newScriptName)
    except:
        nothing = 'nothing'

    # Download newest version of 'Cisco-Device-Analyzer.py' from Github with the name 'Cisco-Device-Analyzer_new.py'
    url = \
        'https://raw.githubusercontent.com/sonicCrypt0r/Vengeful-Honeypot/main/VengefulHoneypot.py' #Location Where Updated Source Code Will Be
    sprint(pStatus('GOOD') + 'Checking For Updates... ')
    r = requests.get(url, verify=False)
    open(newScriptName, 'wb').write(r.content)

    # Find the version from 'Cisco-Device-Analyzer_new.py'
    phrase = 'VERSION ='
    line_number = 'Phrase not found'
    a_file = open(newScriptName, 'r')
    for (number, line) in enumerate(a_file):
        if phrase in line:
            line_number = number
            newVersion = float(line.split('=')[1].strip())
            sprint(pStatus('GOOD') + 'Newest Version Is: V'
                   + str(newVersion))
            break
    a_file.close()

    if newVersion > VERSION:
        os.remove(curScriptName)
        os.rename(newScriptName, curScriptName)
        if os.name == 'nt':
            os.system("python " + curScriptName)
        else:
            os.system("python3 " + curScriptName)
        sys.exit()
    else:
        os.remove(newScriptName) #remove the downloaded code from Github
    return


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


def pStatus(status):
    #This function is for fancy output throughout the program

    # Colors used for fancy output
    COLORS = {
        'WARN': '\033[93m',
        'GOOD': '\033[92m',
        'BAD': '\033[91m',
        'INPUT': '\033[96m',
        'ENDC': '\033[0m',
        'UP': '\033[F',
        }

    if status == 'GOOD':
        return '\n' + COLORS['ENDC'] + '[' + COLORS['GOOD'] + '+' \
            + COLORS['ENDC'] + '] '
    if status == 'BAD':
        return '\n' + COLORS['ENDC'] + '[' + COLORS['BAD'] + '+' \
            + COLORS['ENDC'] + '] '
    if status == 'WARN':
        return '\n' + COLORS['ENDC'] + '[' + COLORS['WARN'] + '+' \
            + COLORS['ENDC'] + '] '
    if status == 'INPUT':
        return '\n' + COLORS['ENDC'] + '[' + COLORS['INPUT'] + '+' \
            + COLORS['ENDC'] + '] '
    if status == 'UP':
        return COLORS['UP']


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
