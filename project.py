<<<<<<< HEAD
print("[+] Please wait...")
##Setup##
import os
import time

try:
    print("[*] Setting up the modules...")
    time.sleep(2)
    os.system('py -m pip install -r requirements.txt')
    os.system('cls')
    print("SETUP SUCCESSFULL...")
    time.sleep(2)
    os.system('cls')
    print("STARTING PEGASUSX....")
    time.sleep(2)
    os.system('cls')
except Exception as e:
    print("Failed to setup the necessary modules...")
    print(f"[-]ERROR : {e}")
    exit(0)

import lxml.etree as tree
from urllib.parse import urljoin
from pprint import pprint
from bs4 import BeautifulSoup as bs
from PyPDF2 import PdfReader
from zipfile import BadZipFile, ZipFile
from olefile import OleFileIO
import requests
import socket
import pyuac
import ctypes
import imaplib
import email
import ipinfo
import psutil
import platform
import dns.resolver
import whois
from os import path
import time
import random
from datetime import datetime
import wave
import pydub
from pydub import AudioSegment
from pydub.playback import play
import ffmpeg
import argparse
import sys
from datetime import datetime as dt
import subprocess
import keyboard
import threading
import librosa
import pyautogui
import getpass
import requests
from bs4 import BeautifulSoup
import selenium
from selenium import webdriver
from selenium.webdriver.common.keys import Keys
from selenium.webdriver.chrome.options import Options 
from PIL import Image
from PIL.ExifTags import TAGS
from winreg import *
from pathlib import Path
os.system('cls')

#check isAdmin
"""
if not pyuac.isUserAdmin():
    print("[!] Script requires administrator priveleges to function better!")
    time.sleep(2)
    print("[*] Re-launch the framework again as administrator!")
    time.sleep(2)
    exit(0)
"""  
#initializing ffmpeg
"""
pydub.AudioSegment.converter=r"D:\ffmpeg-n4.4-latest-win64-gpl-4.4\bin\ffmpeg.exe"
AudioSegment.converter=r"D:\ffmpeg-n4.4-latest-win64-gpl-4.4\bin\ffmpeg.exe"
AudioSegment.ffprobe=r"D:\ffmpeg-n4.4-latest-win64-gpl-4.4\bin\ffprobe.exe"
"""
#Files init
if path.exists('database.txt')==True:
    pass
else:
    with open("database.txt",'w') as file:
        file.write('kcck')
        file.close()
        
if path.exists('video-files.txt')==True:
    pass
else:
    file=open('video-files.txt','w')
    file.close()
    
if path.exists('image-files.txt')==True:
    pass
else:
    file=open('image-files.txt','w')
    file.close()
    
if path.exists('audio-files.txt')==True:
    pass
else:
    file=open('audio-files.txt','w')
    file.close()

if path.exists('text-files.txt')==True:
    pass
else:
    file=open('text-files.txt','w')
    file.close()
########END########       

###FUNCTIONS####
#open protonVPN
def proto(wsl):
    print(f"[+]Enter the password for the {wsl}-wsl")
    passwd=input("[+]password>>")
    
    try:
        subprocess.Popen(['start','cmd','/k',wsl],shell=True,stdin=subprocess.PIPE,stdout=subprocess.PIPE,text=True)
        time.sleep(15)
        pyautogui.moveTo(300,300)
        pyautogui.click()
        pyautogui.typewrite("sudo /etc/init.d/xrdp start")
        pyautogui.press('enter')
        pyautogui.click(300,300)
        time.sleep(2)
        keyboard.write(passwd)
        time.sleep(2)
        pyautogui.press('enter')
        keyboard.write("ifconfig eth0 | grep -w inet | awk '{print $2}'")
        pyautogui.press('enter')
        time.sleep(2)
        keyboard.press_and_release('win+R')
        pyautogui.moveTo(100,500)
        keyboard.write('mstsc')
        pyautogui.press('enter')
    except Exception as e:
        print("[-]Failed due to {}".format(e))
    except OSError as ose:
        print("[-]Failed due to {}".format(ose))
    except KeyboardInterrupt:
        print("[-]Keyboard Interrupt...")

#whois lookup - domain
def is_registered(domain_name):
    try:
        w = whois.whois(domain_name)
    except Exception as e:
        return False
    else:
        return bool(w.domain_name)

#get metadata from file
def compMetaData(file_path):
    now = dt.now()
    file_name = getFileName(file_path)
    '''Get common document metadata, takes 2 arguments, file_path and save (boolean, default is True)'''
    metadata = "Time: %d/%d/%d %d : %d : %d. Found the following metadata for the file %s:\n\n" % (now.year, now.month,
                                                                                                   now.day, now.hour, now.minute,
                                                                                                   now.second, file_name[:-4])
    try:
        f = ZipFile(file_path)
        doc = tree.fromstring(f.read("docProps/core.xml"))

        ns = {'dc': 'http://purl.org/dc/elements/1.1/'}
        ns2 = {'dcterms': 'http://purl.org/dc/terms/'}
        ns3 = {'cp' : 'http://schemas.openxmlformats.org/package/2006/metadata/core-properties'}

        creator = doc.xpath('//dc:creator', namespaces=ns)[0].text
        last_modifier = doc.xpath('//cp:lastModifiedBy', namespaces=ns3)[0].text
        creation_time = doc.xpath('//dcterms:created', namespaces=ns2)[0].text
        xml_mod_time = doc.xpath('//dcterms:modified', namespaces=ns2)[0].text

    except BadZipFile:
        creator = "Could not get creator... File format not supported!"
        last_modifier = "Could not get last modifier... File format not supported!"
        creation_time = "Could not get creation time... File format not supported!"
        xml_mod_time = "Could not get xml modification time... File format not supported!"

    stats = os.stat(file_path)
    c_time = dt.fromtimestamp(stats.st_ctime)
    last_access_time = dt.fromtimestamp(stats.st_atime)
    last_mod_time = dt.fromtimestamp(stats.st_mtime)
    owner_user_id = stats.st_uid

    metadata += """Creator: %s\nLast Modified By: %s\nOwner User ID: %s\nLast metadata mod Time: %s\nCreation Time: %s
Last Modification Time: %s\nXML Modification Time: %s\nLast Access Time: %s""" % (creator, last_modifier, owner_user_id,
                                                                                  c_time, creation_time,
                                                                                  last_mod_time, xml_mod_time,
                                                                                  last_access_time)
    try:
        print(metadata)
    except UnicodeEncodeError:
        print("Console encoding can't decode the result. Enter chcp 65001 in the console and rerun the script.")

#ownership data for files
def oleMetaData(file_path):
    now = dt.now()
    file_name = getFileName(file_path)
    metadata = "Time: %d/%d/%d %d : %d : %d. Found the following metadata for file %s:\n\n" % (now.year, now.month,
                                                                                               now.day, now.hour, now.minute,
                                                                                               now.second, file_name[:-4])
    try:
        ole = OleFileIO(file_path)
        meta = ole.get_metadata()
        ole.close()
        author = meta.author.decode("latin-1")
        creation_time = meta.create_time.ctime()
        last_author = meta.last_saved_by.decode("latin-1")
        last_edit_time = meta.last_saved_time.ctime()
        last_printed = meta.last_printed.ctime()
        revisions = meta.revision_number.decode("latin-1")
        company = meta.company.decode("latin-1")
        creating_app = meta.creating_application.decode("latin-1")

        metadata += "Original Author: %s\nCreation Time: %s\nLast Author: %s\n" % (author, creation_time, last_author) \
                    + "Last Modification Time: %s\nLast Printed at: %s\Total Revisions: %s\n" % (last_edit_time, last_printed, revisions) \
                    + "Created with: %s\nCompany: %s" % (creating_app, company)

        try:
            print(metadata)
        except UnicodeEncodeError:
            print("Console encoding can't decode the result. Enter chcp 65001 in the console and rerun the script.")
            
    except OSError as e1:
        print("[-] File not supported: %s" % e1)
    except FileNotFoundError:
        print("[-] Specified file could not be found")

def pretifyPyPDF2Time(key, val):
    '''Make PyPDF2 time code more readable'''
    if "D:" in val and "Date" in key:
        temp = list(val)
        temp.insert(6, "-")
        temp.insert(9, "-")
        temp.insert(12, "  ")
        temp.insert(15, ":")
        temp.insert(18, ":")
        return "".join(temp)
    else:
        return val

#pdf metadata
def pdfMetaData(file_path):
    '''Get PDF document metadata, takes 2 arguments, file_path and save (boolean, default is True)'''
    pdf_doc = PdfReader(open(file_path, "rb"))

    if pdf_doc.is_encrypted:
        try:
            if pdf_doc.decrypt("") != 1:
                sys.exit("[!] Target pdf document is encrypted... exiting...")
                time.sleep(2)
        except:
            sys.exit("[!] Target pdf document is encrypted with an unsupported algorithm... exiting...")
            time.sleep(2)

    doc_info = pdf_doc.metadata
    stats = os.stat(file_path)
    now = dt.now()
    file_name = Path(file_path).name
    metadata = "\n[+] Time: %d/%d/%d %d : %d : %d. \n[+] Found the following metadata for file %s:\n\n" % (now.year, now.month,
                                                                                               now.day, now.hour, now.minute,
                                                                                               now.second, file_name[:-4])
    try:
        for md in doc_info:
            metadata += '[+] ' + str(md[1:]) + " : " + pretifyPyPDF2Time(str(md[1:]) ,str(doc_info[md])) + "\n"
    except TypeError:
        sys.exit("[-] Couldn't read document info! Make sure target is a valid pdf document...")
        time.sleep(3)

    metadata += "[+] Last metadata mod Date: %s\n[+] Last Mod Date: %s\n[+] Last Access Date: %s\n[+] Owner User ID: %s" %(dt.fromtimestamp(stats.st_ctime),
                                                                                                           dt.fromtimestamp(stats.st_mtime),
                                                                                                           dt.fromtimestamp(stats.st_atime),
                                                                                                           stats.st_uid)
    try:
        print(metadata)
    except UnicodeEncodeError:
        print("[-] Console encoding can't decode the result. Enter chcp 65001 in the console and rerun the script.")
    
#convert size to human-readable
def get_size(bytes, suffix="B"):
    """
    Scale bytes to its proper format
    e.g:
        1253656 => '1.20MB'
        1253656678 => '1.17GB'
    """
    factor = 1024
    for unit in ["", "K", "M", "G", "T", "P"]:
        if bytes < factor:
            return f"{bytes:.2f}{unit}{suffix}"
        bytes /= factor

#port scanner module
def portscan(port):
                    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    s.settimeout(1)
                    try:
                        con = s.connect((site,port))
                        print('[+] Port :',port," is open.")
                        con.close()
                    except: 
                        pass

#caesar cipher encryption algorithm
def caesar(txt,s):
    result=""
    for i in range(len(txt)):
        char=txt[i]
        if char.isupper():
            result+=chr((ord(char)+s-65)%26+65)
        if char.isspace():
            result+=char
        if char.isdigit():
            result+=char
        if char.islower():
            result+=chr((ord(char)+s-97)%26+97)
    return result

#AES encryption algorithm
def aes(txt,ch):
    char_pool=''
    char_pool_basic='abcdefghijklmnopqrstuvwxzzABCDEFGHIJKLMNOPQRSTUVWXYZ<>,./\[]{}'
    key=''   
    
    if ch==1:
        for i in range(128//8):
            key+=char_pool_basic[random.randint(0,len(char_pool_basic)-1)]
        print("your key ",key)
        key_index=0
        max_index=(128//8)-1
        encrypted_msg=''
        for char in txt:
            xoring=ord(char)^ord(key[key_index])
            encrypted_msg+=chr(xoring)
            if key_index>=max_index:
                key_index=0
            else:
                key_index+=1
        return encrypted_msg

    if ch==2:
        max_index=0
        for i in range(0x00,0xff):
            char_pool+=chr(i)
        for i in range(256//8):
            key+=random.choice(char_pool)
        print("your key ",key)
        encrypted_msg=''
        key_index=0
        for char in txt:
            xoring=ord(char)^ord(key[key_index])
            encrypted_msg+=chr(xoring)
            if key_index>=max_index:
                key_index=0
            else:
                key_index+=1
        return encrypted_msg

#image forensics module
def getExif(image_file):
    if not os.path.isfile(image_file):
        sys.exit("%s is not a valid image file!"%(image_file))
    now=datetime.now()
    data = "Time: %d/%d/%d %d : %d : %d. Found the following Exif data for the image %s:\n\n" % (now.year, now.month,
                                                                                                 now.day, now.hour, now.minute,
                                                                                                 now.second,image_file)
    img = Image.open(image_file)
    info = img._getexif()
    exif_data = {}
    if info:
        for (tag, value) in info.items():
            decoded = TAGS.get(tag, tag)
            if type(value) is bytes:
                try:
                    exif_data[decoded] = value.decode("utf-8")
                except:
                    pass
            else:
                exif_data[decoded] = value
        for key in exif_data:
            data += "{}    :   {}\n".format(key, exif_data[key])

        print("Found the following exif data:\n")
        time.sleep(3)
        print("+-----------------------------------------------------------------------------+")
        print("|                          Image Metadata                                     |")
        print("+-----------------------------------------------------------------------------+")
        print(data)
        print("+-----------------------------------------------------------------------------+")
    else:
        print("[-] NO EXIF DATA FOUND!")
        time.sleep(2)

#ransomware module - test
def ransom(file,key):
    try:
        key_index=0
        max_index=len(key)-1
        encrypted_data=''
        with open(file, 'rb') as f:
            data=f.read()
        with open(file, 'w') as f:
            f.write(' ')
        for byte in data:
            xoring=byte^ord(key[key_index])
            with open(file, 'ab') as f:
                f.write(xoring.to_bytes(1, 'little'))
            if key_index>=max_index:
                key_index=0
            else:
                key_index+=0
    except:
        print("OOps...seems like an error :(....you are lucky")

#morse code obfuscation algorithm
def morse(message,no):
    morse_code={'A':'.-','B':'-...','C':'-.-.','D':'-..','E':'.','F':'..-.',
            'G':'--.','H':'....','I':'..','J':'.---','K':'-.-','L':'.-..',
            'M':'--','N':'--.-','O':'---','P':'.--.','Q':'--.-','R':'.-.',
            'S':'...','T':'-','U':'..-','V':'...-','W':'.--','X':'-..-',
            'Y':'-.--','Z':'--..','1':'.----','2':'..---','3':'...--',
            '4':'....-','5':'.....','6':'-....','7':'--...','8':'---..',
            '9':'----.','0':'-----',',':'--..--','.':'.-.-.-','?':'..--..',
            '/':'-..-.','-':'-....-','(':'-.--.', ')':'-.--.-'}
    morse_decode = {v: k for k, v in morse_code.items()}

    a=message.split()
    if no== '1':
        cipher=''
        for letter in message:
            if letter != ' ':
                cipher+=morse_code[letter]+' '
            else:
                cipher+=' '
        return cipher
    if no=='2':
        key_list=list(morse_code.keys())
        val_list=list(morse_code.values())
        decipher=''
        n=""
        for chrs in message:
            if chrs!=" ":
                decipher+=chrs
                space_found=0
            else:
                space_found+=1
                if space_found==2:
                    n+=" "
                else:
                    n=n+key_list[val_list.index(decipher)]
                    decipher=""
        return n              

#one-time-pad cipher
def otp(plain,key):
    result=""
    try:
        for i in range(len(plain)): 
            ch=plain[i]
            result+=chr((ord(ch)-97 +ord(key[i])-97)%26 +97)

        return result
    except:
        pass
           
#file encryption module
def encrypt(filename,key):
    file=open(filename,'rb')
    dat=file.read()
    file.close()
    dat=bytearray(dat)
    for index,value in enumerate(dat):
        dat[index]=value ^ key  #performs an bitwise XOR operation
    file=open(filename,'wb')
    file.write(dat)
    file.close()
        
#file decryption module
def decrypt(filename,key):
    file=open(filename,'rb')
    dat=file.read()
    file.close()
    dat=bytearray(dat)
    for index,value in enumerate(dat):
        dat[index]=value ^ key  #performs an bitwise XOR operation
        
    file=open(filename, "wb")
    file.write(dat)
    file.close()

#obtain data of url
def getdata(url):
    r=requests.get(url)
    return(r.text)

#rot-13 obfuscation algorithm
def rot(string):
    rot={"a":"n","b":"o","c":"p","d":"q","e":"r","f":"s","g":"t","h":"u","i":"v","j":"w","k":"x","l":"y","m":"z",'n':'a','o':'b','p':'c','q':'d','r':'e','s': 'f', 't': 'g', 'u': 'h', 'v': 'i', 'w': 'j', 'x': 'k', 'y': 'l', 'z': 'm'}
    a=""
    r=a.join([rot.get(i,i) for i in string])
    return r

#update exit in log file
def ex():
    with open("log.txt",'a') as lg:
        datim=datetime.now()
        dat=datim.strftime("%d/%m/%y %H:%M:%S")
        log=f"\n[+]closed at {dat}"+" status(closed)"
        lg.write(log)

#base64 encoding and decoding
class base64:
    def encode(input_string):
        base64_chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+*"
        binary_data = ''.join(format(ord(char), '08b') for char in input_string)
        while len(binary_data) % 6 != 0:
            binary_data += '0'
        encoded_data = ''
        for i in range(0, len(binary_data), 6):
            chunk = binary_data[i:i+6]
            index = int(chunk, 2)
            encoded_data += base64_chars[index]
        while len(encoded_data) % 4 != 0:
            encoded_data += '-'
        return encoded_data
        
    
    def decode(data):
        base64_chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+*"
        encoded_string = data.rstrip('-')
        binary_data = ''.join(format(base64_chars.index(char), '06b') for char in data)
        decoded_data = ''
        for i in range(0, len(binary_data), 8):
            chunk = binary_data[i:i+8]
            decoded_data += chr(int(chunk, 2))
        return decoded_data
    
#SQL INJECTION SCANNER MODULES
s = requests.Session()
s.headers["User-Agent"] = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/83.0.4103.106 Safari/537.36"

def get_all_forms(url):
    """Given a `url`, it returns all forms from the HTML content"""
    soup = bs(s.get(url).content, "html.parser")
    return soup.find_all("form")


def get_form_details(form):
    """
    This function extracts all possible useful information about an HTML `form`
    """
    details = {}
  
    try:
        action = form.attrs.get("action").lower()
    except:
        action = None
   
    method = form.attrs.get("method", "get").lower()
   
    inputs = []
    for input_tag in form.find_all("input"):
        input_type = input_tag.attrs.get("type", "text")
        input_name = input_tag.attrs.get("name")
        input_value = input_tag.attrs.get("value", "")
        inputs.append({"type": input_type, "name": input_name, "value": input_value})

    details["action"] = action
    details["method"] = method
    details["inputs"] = inputs
    return details
def is_vulnerable(response):
    errors = {
        # MySQL
        "SQL syntax.*?MySQL",
        "MySqlException",
        "you have an error in your sql syntax;",
        "warning: mysql",
        #postgresql
        "PostgreSQL.*?ERROR",
        "Warning.*?\Wpg_",
        "PostgreSQL query failed",
        "ERROR:\s\ssyntax error at or near",
        # SQL Server
        "unclosed quotation mark after the character string",
        "ODBC SQL Server Driver",
        r"Microsoft SQL Native Client error '[0-9a-fA-F]{8}",
        "ODBC SQL Server Driver"
        # Oracle
        "quoted string not properly terminated",
        "OracleException",
        "SQL command not properly ended",
        "Oracle error",
        #cache
        "encountered after end of query"
        "A comparison operator is required here"
    }
    for error in errors:
        if error in response.content.decode().lower():
            return True
    # no error detected
    return False

def scan_sql_injection(url):
    for c in "\"'":
        new_url = f"{url}{c}"
        print("[!] Trying", new_url)
        res = s.get(new_url)
        if is_vulnerable(res):
            print("[+] SQL Injection vulnerability detected, link:", new_url)
            time.sleep(3)
            return
    forms = get_all_forms(url)
    print(f"[+] Detected {len(forms)} forms on {url}.")
    for form in forms:
        form_details = get_form_details(form)
        for c in "\"'":
            data = {}
            for input_tag in form_details["inputs"]:
                if input_tag["type"] == "hidden" or input_tag["value"]:
                    try:
                        data[input_tag["name"]] = input_tag["value"] + c
                    except:
                        pass
                elif input_tag["type"] != "submit":
                    data[input_tag["name"]] = f"test{c}"
            url = urljoin(url, form_details["action"])
            if form_details["method"] == "post":
                res = s.post(url, data=data)
            elif form_details["method"] == "get":
                res = s.get(url, params=data)
            if is_vulnerable(res):
                print("[+] SQL Injection vulnerability detected, link:", url)
                print("[+] Form:")
                pprint(form_details)
                time.sleep(3)
                break

#XSS Vulnerability
def Get_all_forms(url):
    """Given a `url`, it returns all forms from the HTML content"""
    soup = bs(requests.get(url).content, "html.parser")
    return soup.find_all("form")

def Get_form_details(form):
    details = {}
    # get the form action (target url)
    action = form.attrs.get("action", "").lower()
    # get the form method (POST, GET, etc.)
    method = form.attrs.get("method", "get").lower()
    # get all the input details such as type and name
    inputs = []
    for input_tag in form.find_all("input"):
        input_type = input_tag.attrs.get("type", "text")
        input_name = input_tag.attrs.get("name")
        inputs.append({"type": input_type, "name": input_name})
    # put everything to the resulting dictionary
    details["action"] = action
    details["method"] = method
    details["inputs"] = inputs
    return details

def Submit_form(form_details, url, value):

    # construct the full URL (if the url provided in action is relative)
    target_url = urljoin(url, form_details["action"])
    # get the inputs
    inputs = form_details["inputs"]
    data = {}
    for input in inputs:
        # replace all text and search values with `value`
        if input["type"] == "text" or input["type"] == "search":
            input["value"] = value
        input_name = input.get("name")
        input_value = input.get("value")
        if input_name and input_value:
            # if input name and value are not None, 
            # then add them to the data of form submission
            data[input_name] = input_value

    print(f"[+] Submitting malicious payload to {target_url}")
    print(f"[+] Data: {data}")
    if form_details["method"] == "post":
        return requests.post(target_url, data=data)
    else:
        # GET request
        return requests.get(target_url, params=data)
    
def scan_xss(url):
    # get all the forms from the URL
    forms = Get_all_forms(url)
    print(f"[+] Detected {len(forms)} forms on {url}.")
    time.sleep(2)
    js_script = "<Script>alert('hi')</scripT>"
    is_vulnerable = False
    # iterate over all forms
    for form in forms:
        form_details = Get_form_details(form)
        content = Submit_form(form_details, url, js_script).content.decode()
        if js_script in content:
            print(f"[+] XSS Detected on {url}")
            print(f"[*] Form details:")
            pprint(form_details)
            is_vulnerable = True
            time.sleep(3)
            # won't break because we want to print available vulnerable forms
    if(is_vulnerable):
        print("[*] Vulerable to XSS vulnerability..")
        time.sleep(2)
    else:
        print("[-] Not Vulnerble to XSS vulnerability..")
        time.sleep(2)
        
#get BSID's
def get_WIFIs():
    wlans = r'SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkList' \
            + r'\Signatures\Unmanaged'
    key = OpenKey(HKEY_LOCAL_MACHINE, wlans)
    data = ""
    num = 0
    for i in range(1000000):
        try:
            attempt = EnumKey(key, i)
            wlan_key = OpenKey(key, str(attempt))
            (n, addr, t) = EnumValue(wlan_key, 5)
            (n, name, t) = EnumValue(wlan_key, 4)
            res, mac_address = val2addr(addr)
            wlan_name = str(name)
            print("+------------------------------------+")
            print(f"| BSSID :{wlan_name}                 ")
            print(f"| MAC :{mac_address}                 ")
            print("+------------------------------------+")
            CloseKey(wlan_key)
            num += 1
        except Exception as e:
            break

#logging module
def log():
    datim=datetime.now()
    dat=datim.strftime("%d/%m/%y %H:%M:%S")
    log=f"\n[+]Logged at {dat}"+" status(Running)"
    with open("log.txt",'a') as lg:
        lg.write(log)
log()
###############END###############

print("Enter the Access code")

with open("database.txt",'r') as f:
    r=f.read()

plain=' '.join(input("Enter password: ").lower().split())
key=' '.join(input("Enter key: ").lower().split())

if len(key)!=len(plain):
    print("[-]Invalid Key!!")

else:
    out_of_pass_limit=False
    guess=""
    pass_limit=3
    pass_count=0
    while otp(plain,key)!=r and not(out_of_pass_limit):
        if pass_count<pass_limit:
            pass_count+=1
            plain=' '.join(input("Enter password: ").lower().split())
            key=' '.join(input("Enter key: ").lower().split())
            
        else:
            out_of_pass_limit=True

    if out_of_pass_limit==True:
        print("Permission Denied")
    else:
        time.sleep(2)
        print("Permission Granted")
        time.sleep(2)
        while True:
            print(r"""
            =x=x=x=x=x=x=x=x=x=x=x=x=x=x=x=x=x=x=x=x=x=x=x=x=x=x=x=x=x=x=x=x=x=x=x=x=x=x=x=x=x=x=x=x  _/\__ 
                     @$%&&#$ @#$#%$%@ #$%^%#@@@$  #$#%$%  #$%$#%#^%  #$     #$  #$@#$#$@#$           /    \\                                
                     @     # @        #          #      # @          #$     #$  @                    |.    \/\                              
                     @##$%$% @$%@$%$# #   ##%%#% ##$#$%$# @4@$%$%$%  #$     #$  @#$%$%#$%$           |  )   \\\                               
                     @       @        #        # #      #         @  #$     #$           @           \_/ |  //|\\                    
                     @       @#$#%$%% ##$%#$@$#$ #      # #$%$%#$%%  #$#$%$%#$  @#$$%%$@$%              /   \\\/\\\            
            =x=x=x=x=x=x=x=x=x=x=x=x=x=x=x=x=x=x=x=x=x=x=x=x=x=x=x=x=x=x=x=x=x=x=x=x=x=x=x=x=x=x=x=x   / 
                                      ENCRYPTION AND SECURITY FRAMEWORK
            =x=x=x=x=x=x=x=x=x=x=x=x=x=x=x=x=x=x=x=x=x=x=x=x=x=x=x=x=x=x=x=x=x=x=x=x=x=x=x=x=x=x=x=x
                                               >>Windows Version<< 
                                      *****SECURITY EXISTS PEGASUS EXISTS******
            +----------------------------------------------------------------------------------------------------------+      
            |    NOTE!!                                                                                                |                                          
            |    -->Type exit or quit to exit and type clear to clear the previous commands                            |                                         
            |    -->Encrypted Messages will be stored in Encrypted Message.txt.                                        |
            |      So, it will be overwritten so save it to another file before you use other encryption modules!      |                                                                                                              |
            |    -->Decrypted Messages will be stored in Decrypted Message.txt.                                        |
            +----------------------------------------------------------------------------------------------------------+
        
+-------------------------------+-----------------------------+------------------------------------+----------------------------+-------------------------+                 
|      >>ANONYMIZATION<<        |      >>RECONAISSANCE<<      |    >>WEB-PENETRATION-SCANNNERS<<   |      >>DDOS-ATTACKS<<      |     >>FORENSICS<<       |   
+-------------------------------+-----------------------------+------------------------------------+----------------------------+-------------------------+
| [1.1] TEXT ENCRYPTION         | [2.1] DOMAIN RECON          | [3.1] SQL-INJECTION SCANNER        | [4.1] SMS-DDOS             | [5.1] IMAGE FORENSICS   |
| [1.2] TEXT OBFUSCATION        | [2.2] DNS ENUMERATION       | [3.2] XSS VULNERABILITY SCANNER    |                            | [5.2] E-MAIL FORENSICS  |
| [1.3] FILE ENCRYPTION         | [2.3] IP ADDR ENUMERATION   | [3.3] SUB-DOMAIN DISCOVERY         |                            | [5.3] NETWORK FORENSICS |               
| [1.4] FILE SHREDDER           |                             | [3.4] PORT SCANNER                 |                            | [5.4] FILE FORENSICS    |
| [1.5] IMAGE STEGANOGRAPHY     |
| [1.6] AUDIO STEGANOGRAPHY     |
| [1.7] VIDEO STEGANOGRAPHY     |
| [1.8] NETWORK STEGANOGRAPHY   |
| [1.9] MAC-ADDR ANONYMIZATION  |                  
+-------------------------------+-----------------------------+------------------------------------+----------------------------+----------------------+
|     >>WEB-PENETRATION<<       |   >>NETWORK-PENETRATION<<   |    >>MALWARE/PAYLOADS<<            | >>PASSWORD_CRACKER<< |
+-------------------------------+-----------------------------+------------------------------------+----------------------------+----------------------+
|                              
|                              
|                          
|                           
+------------------------------+-----------------------------+------------------------------------+----------------------------+----------------------+

GENERAL COMMANDS:
    wav_converter  -> convert mp3 to wav
    audio_recorder -> record audio in .mp3 format
    clear          -> clears the shell
    change_password-> change password of framework
    exit/quit      -> exit the framework
    sys_info       -> display intensive report on system specifications
    clear_logs     -> clears the log file
    setup          -> basic setup of tools
    destroy        -> a worm used to test your system's potential
            """)

            inp=input("PegasusX>>").lower()

            if inp=='1.1':
                os.system('cls')
                print("""
                        <0> Return to main menu
                        <1> Encrypt a text
                        <2> Encrypt a text file (USE THIS FOR LARGER TEXTS)
                        <3> Decrypt a text
                        <4> Decrypt a text file (USE THIS FOR LARGER TEXTS)
                """)
                ch=input("PegasusX>>")

                if ch=='1':
                    print("[+] Enter the text")
                    text=input("PegasusX>>")
                    print("[+] Choose an algorithm for encryption")
                    print("""\n
                        <1> CAESAR CIPHER ALGORITHM
                    """)
                    algo_ch = input("PegasusX>>")

                    if(algo_ch=='1'):
                        try:
                            print("""
                                <1> Specify the shift value
                                <2> Randomly generate a shift value
                            """)
                            s_ch = input("PegasusX>>")
                            if(s_ch=='1'):
                                shift_key=int(input("Pegasus>>"))
                            else:
                                print("[*]Randomly generating a shift value...")
                                shift_key = random.randint(1,25)
                                print("[+]REMEMBER SHIFT KEY FOR DECRYPTION")
                                print(f"[!]SHIFT-KEY : {shift_key}")
                                time.sleep(3)

                            output=caesar(text,shift_key)
                            with open('Encrypted Message.txt','w') as f:
                                f.write(output)
                            print("[+]Encrypted Message stored in 'Encrypted Message.txt' file")
                            time.sleep(3)
                        except Exception as e:
                            print(f"[-]Failed due to {e}")

                elif ch=='2':
                    print("[+]Choose an algorithm for encryption")
                    print("""\n
                        <1> CAESAR CIPHER ALGORITHM 
                    """)
                    algo_ch = input("PegasusX>>")

                    if algo_ch=='1':
                        try:
                            print("[+]Enter the path to text file")
                            file_path = input("PegasusX>>")
                            print("""
                                <1> Specify the shift value
                                <2> Randomly generate a shift value
                            """)
                            s_ch = input("PegasusX>>")
                            if(s_ch=='1'):
                                shift_value=int(input("Pegasus>>"))
                            else:
                                print("[*]Randomly generating a shift value...")
                                shift_value = random.randint(1,25)

                                print("[+]REMEMBER SHIFT KEY FOR DECRYPTION")
                                print(f"[!]SHIFT-KEY : {shift_value}")
                                time.sleep(3)

                            f = open(file_path,'r')
                            text = f.read()
                            o=caesar(text,shift_value)
                            with open(file_path,'w') as file:
                                file.write(o)
                            print(f"[+]Encrypted {file_path} successfully...")
                            time.sleep(3)
                        except FileNotFoundError:
                            print(f"[!] Invalid File path/name !")
                            time.sleep(2)
                        except Exception as e:
                            print(f"[-]Failed due to {e}")
                            time.sleep(2)

                elif ch=='3':
                    print("[+]Choose an algorithm for decryption")
                    print("""\n
                        <1> CAESAR CIPHER ALGORITHM
                        <2> NONE OF THE ABOVE
                    """)
                    algo_ch = input("PegasusX>>")

                    if algo_ch=='1':
                        print("[+]Enter the text")
                        text = input("PegasusX>>")
                        print("[+]Enter shift value")
                        shift_key = int(input("PegasusX>>"))
                        try:
                            output=caesar(text,26-shift_key)
                            print(f"Decrypting with shift vale:{shift_key}")
                            print(f"Output message : {output}")
                            time.sleep(1)
                            print("[+] Completed....")
                            time.sleep(2)
                        except Exception as e:
                            print(f"[-]Failed to due to {e}")

                    if algo_ch=='2':
                        print("[-]Sorry to hear that, but we currently only support these algorithms...")
                        time.sleep(2) 
                
                elif ch=='4':
                    print("[+]Choose an algorithm for decryption")
                    print("""\n
                        <1> CAESAR CIPHER ALGORITHM
                        <2> NONE OF THE ABOVE
                    """)
                    algo_ch = input("PegasusX>>")
                    if(algo_ch=='1'):
                        print("[+] Enter path to file")
                        file_path = input("PegasusX>>")
                        print("[+] Enter shift value")
                        shift_key = int(input("PegasusX>>"))

                        try:
                            f = open(file_path,'r')
                            text = f.read()
                            o=caesar(text,26-shift_key)        
                            with open(file_path,'w') as file:
                                file.write(o)
                            print("[+]File decrypted successfully")
                            time.sleep(3)
                        except FileNotFoundError:
                            print(f"[!] Invalid File path/name !")
                            time.sleep(2)
                        except Exception as e:
                            print("[-]failed due to the exception : ",e)
                            time.sleep(2)

                    if algo_ch=='2':
                        print("[-]Sorry to hear that, but we currently only support these algorithms...")
                        time.sleep(2)

#####END OF MODULE-1.1########
                        
            if inp=='1.2':
                os.system('cls')
                print("[+] Please refer manual to understand obfuscation and deobfuscation better or google it!")
                time.sleep(3)

                print("""
                        <1> Obfuscate a text
                        <2> Obfuscate a text file (USE THIS FOR LARGER TEXTS)
                        <3> Deobfuscate a text
                        <4> Deobfuscate a text file (USE THIS FOR LARGER TEXTS)
                    """)
                ch = input("PegasusX>>")

                if(ch=='1'):
                    print("[+] Select a text obfuscation technique")
                    print("""
                      <1> MORSE-CODE OBFUSCATION
                      <2> ROT-13 OBFUSCATION
                      <3> REVERSE TEXT OBFUSCATION
                      <4> BASE64 OBFUSCATION
                    """)
                    obf_ch = input("PegasusX>>")

                    if(obf_ch=='1'):
                        print("[+] Enter the text...")
                        try:
                            txt = input("PegasusX>>")
                            en=morse(txt.upper(),'1')
                            with open('Obfuscated Message.txt','w') as f:
                                f.write(en)
                            print("[+] Obfuscated successfully...")
                            print("[+] Please check the Obfuscated Message.txt file for the obfuscated text")
                            time.sleep(3)
                        except Exception as e:
                            print(f"[-] Failed due to {e}")

                    if(obf_ch=='2'):
                        print("[+] Enter the text...")
                        try:
                            wrd=input("PegasusX>>")  
                            out=rot(wrd)
                            with open("Obfuscated Message.txt",'w') as f: 
                                f.write(out)
                            print("[+] Obfuscated successfully")
                            print("[+] Please check the Obfuscated Message.txt file for the obfuscated text")
                            time.sleep(3)
                        except Exception as e:
                            print(f"[-] Failed due to {e}")
                            time.sleep(2)

                    if(obf_ch=='3'):
                        print("[+] Enter the text...")
                        try:
                            txt = input("PegasusX>>")
                            rev_text = ''
                            i = len(txt) - 1
                            while i >= 0:
                                rev_text = rev_text + txt[i]
                                i = i - 1
                            with open("Obfuscated Message.txt",'w') as f:
                                f.write(rev_text)
                            print("[+] Obfuscated Successfully")
                            print("[+] Please check the Obfuscated Message.txt file for the obfuscated text")
                            time.sleep(3)
                        
                        except Exception as e:
                            print(f"[-] Failed due to {e}")
                            time.sleep(2)
                        
                    if(obf_ch=='4'):
                        print("[+] Enter the text...")
                        try:
                            txt = input("PegasusX>>")
                            data = base64.encode(txt)
                            with open("Obfuscated Message.txt",'w') as f:
                                f.write(data)
                            print("[+] Obfuscated successfully")
                            print("[+] Please check the Obfuscated Message.txt file for the obfuscated text")
                            time.sleep(3)
                        except Exception as e:
                            print(f"[-] Failed due to {e}")
                            time.sleep(2)


                if ch=='2':
                    print("[+] Select a text obfuscation technique")
                    print("""
                      <1> MORSE-CODE OBFUSCATION
                      <2> ROT-13 OBFUSCATION
                      <3> REVERSE TEXT OBFUSCATION
                      <4> BASE64 OBFUSCATION
                    """)
                    obf_ch = input("PegasusX>>")

                    if(obf_ch=='1'):
                        print("[+] Enter the path to file...")
                        try:
                            file_path = input("PegasusX>>")
                            file = open(file_path,'r')
                            txt = file.read()

                            output=morse(txt.upper(),'1')
                            with open(file_path,'w') as f:
                                f.write(output)
                            print("[+] Obfuscated successfully...")
                            print(f"[+] Please check the {file_path} file for the obfuscated text")
                            time.sleep(3)
                        except FileNotFoundError:
                            print(f"[!] Please check the file path/name once again!")
                            time.sleep(2)
                        except Exception as e:
                            print(f"[-] Failed due to {e}")
                            time.sleep(2)

                    if(obf_ch=='2'):
                        print("[+] Enter the path to file...")
                        try:
                            file_path = input("PegasusX>>")
                            file = open(file_path,'r')
                            txt = file.read()

                            out=rot(txt)
                            with open(file_path,'w') as f: 
                                f.write(out)
                            print("[+] Obfuscated successfully")
                            print(f"[+] Please check the {file_path} file for the obfuscated text")
                            time.sleep(3)
                        except FileNotFoundError:
                            print(f"[!] Please check the file path/name once again!")
                            time.sleep(2)
                        except Exception as e:
                            print(f"[-] Failed due to {e}")
                            time.sleep(2)

                    if(obf_ch=='3'):
                        print("[+] Enter the path to file...")
                        try:
                            file_path = input("PegasusX>>")
                            file = open(file_path,'r')
                            txt = file.read()
                        
                            rev_text = ''
                            i = len(txt) - 1
                            while i >= 0:
                                rev_text = rev_text + txt[i]
                                i = i - 1
                            with open(file_path,'w') as f:
                                f.write(rev_text)
                            print("[+] Obfuscated Successfully")
                            print(f"[+] Please check the {file_path} file for the obfuscated text")
                            time.sleep(3)
                        except FileNotFoundError:
                            print(f"[!] Please check the file path/name once again!")
                            time.sleep(2)
                        except Exception as e:
                            print(f"[-] Failed due to {e}")
                            time.sleep(2)

                    if(obf_ch=='4'):
                        print("[+] Enter the path to file...")
                        try:
                            file_path = input("PegasusX>>")
                            file = open(file_path,'r')
                            txt = file.read()
                        
                            data = base64.encode(txt)
                            with open(file_path,'w') as f:
                                f.write(data)
                            print("[+] Obfuscated successfully")
                            print(f"[+] Please check the {file_path} file for the obfuscated text")
                            time.sleep(3)
                        except FileNotFoundError:
                            print(f"[!] Please check the file path/name once again!")
                            time.sleep(2)
                        except Exception as e:
                            print(f"[-] Failed due to {e}")
                            time.sleep(2)

                if(ch=='3'):
                    print("[+] Select a text deobfuscation technique")
                    print("""
                      <1> MORSE-CODE OBFUSCATION
                      <2> ROT-13 OBFUSCATION
                      <3> REVERSE TEXT OBFUSCATION
                      <4> BASE64 OBFUSCATION
                    """)
                    obf_ch = input("PegasusX>>")

                    if(obf_ch=='1'):
                        print("[+] Enter the encoded morse code...")
                        mor=input("PegasusX>>")
                        en=morse(mor.upper(),'2')
                    
                        time.sleep(3)
                        with open('Deobfuscated Message.txt','w') as file:
                            file.write(en)
                            file.close()
                        print("[+] Deobfuscated Successfully...")
                        print("[+] Check out the Deobfuscated Message.txt file")
                        time.sleep(3)
                        
                    if(obf_ch=='2'):
                        print("[+] Enter the encoded rot-13 code...")
                        txt = input("PegasusX>>")
                        
                        out=rot(wrd)
                        with open("Deobfuscated Message.txt",'w') as e:
                            e.write(out)
                        print("[+] Deobfuscated successfully")
                        print("[+] Please check the Deobfuscated Message.txt file for the deobfuscated text")
                        time.sleep(3)

                    if(obf_ch=='3'):
                        print("[+] Enter the encoded reverse text...")
                        txt = input("PegasusX>>")
                        rev_text = ''
                        i = len(txt) - 1
                        while i >= 0:
                            rev_text = rev_text + txt[i]
                            i = i - 1
                        with open("Deobfuscated Message.txt",'w') as f:
                            f.write(rev_text)
                        print("[+] Deobfuscated Successfully")
                        print("[+] Please check the Deobfuscated Message.txt file for the Deobfuscated text")
                        time.sleep(3)

                    if(obf_ch=='4'):
                        print("[+] Enter the encoded base64 text...")
                        txt = input("PegasusX>>")
                        data = base64.decode(txt)
                        with open("Deobfuscated Message.txt",'w') as f:
                            f.write(data)
                        print("[+] Deobfuscated successfully")
                        print("[+] Please check the Deobfuscated Message.txt file for the Deobfuscated text")
                        time.sleep(3)


                if(ch=='4'):
                    print("[+] Select a text deobfuscation technique")
                    print("""
                      <1> MORSE-CODE DEOBFUSCATION
                      <2> ROT-13 DEOBFUSCATION
                      <3> REVERSE TEXT DEOBFUSCATION
                      <4> BASE64 DEOBFUSCATION
                    """)
                    obf_ch = input("PegasusX>>")

                    if(obf_ch=='1'):
                        print("[+] Enter the path to file...")
                        try:
                            file_path = input("PegasusX>>")
                            file = open(file_path,'r')
                            txt = file.read()

                            output=morse(txt.upper(),'2')
                            with open(file_path,'w') as f:
                                f.write(output)
                            print("[+] Deobfuscated successfully...")
                            print(f"[+] Please check the {file_path} file for the deobfuscated text")
                            time.sleep(3)
                        except FileNotFoundError:
                            print(f"[!] Please check the file path/name once again!")
                            time.sleep(2)
                        except Exception as e:
                            print(f"[-] Failed due to {e}")
                            time.sleep(2)

                    if(obf_ch=='2'):
                        print("[+] Enter the path to file...")
                        try:
                            file_path = input("PegasusX>>")
                            file = open(file_path,'r')
                            txt = file.read()

                            out=rot(txt)
                            with open(file_path,'w') as f: 
                                f.write(out)
                            print("[+] Deobfuscated successfully")
                            print(f"[+] Please check the {file_path} file for the deobfuscated text")
                            time.sleep(3)
                        except FileNotFoundError:
                            print(f"[!] Please check the file path once again!")
                            time.sleep(2)
                        except Exception as e:
                            print(f"[-] Failed due to {e}")
                            time.sleep(2)

                    if(obf_ch=='3'):
                        print("[+] Enter the path to file...")
                        try:
                            file_path = input("PegasusX>>")
                            file = open(file_path,'r')
                            txt = file.read()
                        
                            rev_text = ''
                            i = len(txt) - 1
                            while i >= 0:
                                rev_text = rev_text + txt[i]
                                i = i - 1
                            with open(file_path,'w') as f:
                                f.write(rev_text)
                            print("[+] Deobfuscated Successfully")
                            print(f"[+] Please check the {file_path} file for the Deobfuscated text")
                            time.sleep(3)
                        except FileNotFoundError:
                            print(f"[!] Please check the file path once again!")
                            time.sleep(2)
                        except Exception as e:
                            print(f"[-] Failed due to {e}")
                            time.sleep(2)

                    if(obf_ch=='4'):
                        print("[+] Enter the path to file...")
                        try:
                            file_path = input("PegasusX>>")
                            file = open(file_path,'r')
                            txt = file.read()
                        
                            data = base64.encode(txt)
                            with open(file_path,'w') as f:
                                f.write(data)
                            print("[+] Deobfuscated successfully")
                            print(f"[+] Please check the {file_path} file for the Deobfuscated text")
                            time.sleep(3)
                        except FileNotFoundError:
                            print(f"[!] Please check the file path once again!")
                            time.sleep(2)
                        except Exception as e:
                            print(f"[-] Failed due to {e}")
                            time.sleep(2)
#### END OF MODULE - 1.2 #####           
            
            if inp=='1.3':
                print("[+] What do you want to do?")
                print("""
                    <1> File Encryption
                    <2> File Decryption
                """)
                ch = input("PegasusX>>")

                if(ch=='1'):
                    print("[+]Please create a private key(digits in range 1-256)")
                    print("[!]Remember your key, without the key your data will be encrypted forever")
                    key=int(input("PegasusX>>"))
                    print("[+]Now Enter the file location")
                    filename=input("PegasusX>>")

                    if '*' in filename:
                        try:
                            ch=input("[!]Are you using wildcard?[y|n]>>").lower()
                            if ch=='n':
                                if path.exists(filename)==True:
                                    print(f"Encrypting {filename}...it may take time if the file is too big!!")
                                    encrypt(filename, key)
                                    print("[*]File Encrypted successfully")
                                    time.sleep(2)
                                else:
                                    print("[-]File cannot be encrypted....Please check the name")
                                    time.sleep(2)
                            if ch=='y':
                                print("[+]Encrypting....")
                                os.system(f'dir {filename} /b > file_data.txt')
                                c=0
                                time.sleep(2)
                                with open('file_data.txt','r') as file:
                                    a=file.readlines()
                                for i in range(0,len(a)):
                                    f_data=a[i]
                                    files=f_data.strip('\n')
                                    encrypt(files,key)
                                print("[+]Encrypted All the files....")
                                pass
                            else:
                                print("[-] Invalid Choice....")
                        except FileNotFoundError:
                            print(f"[!] Please check the file path once again!")
                            time.sleep(2)
                        except Exception as e:
                            print(f"[-] Failed due to {e}")
                            time.sleep(2)
                        
                    else:
                        try:
                            if path.exists(filename)==True:
                                print(f"Encrypting {filename}...it may take time if the file is too big!!")
                                encrypt(filename, key)
                                print("[*]File Encrypted successfully")
                                time.sleep(2)
                            else:
                                print("[-]File cannot be decrypted....Please check the name")
                                time.sleep(2)
                        except FileNotFoundError:
                            print(f"[!] Please check the file path once again!")
                            time.sleep(2)
                        except Exception as e:
                            print(f"[-] Failed due to {e}")
                            time.sleep(2)
                    
                if ch=='2':
                    print("[+]Enter the private key(digits in range 0-256)")
                    key=int(input("PegasusX>>"))
                    print("[+]Enter the file location")
                    filename=input("PegasusX>>")
                    if '*' in filename:
                        try:
                            print("Are u using wildcard?")
                            ch = input("yes|no>>").lower()
                            if ch=='n':
                                if path.exists(filename)==True:
                                    decrypt(filename,key)
                                    print("[*] File Decrypted successfully")
                                    time.sleep(2)
                                else:
                                    print("[-] File cannot be decrypted....Please check the name")
                                    time.sleep(2)
                            if ch=='y':
                                print("[+] Decrypting....")
                                os.system(f'dir {filename} /b > file_data.txt')
                                c=0
                                time.sleep(2)
                                with open('file_data.txt','r') as file:
                                    a=file.readlines()
                                for i in range(0,len(a)):
                                    f_data=a[i]
                                    files=f_data.strip('\n')
                                    decrypt(files,key)
                                print("[+] Decrypted all the files...")
                                pass
                            else:
                                print("[-] Invalid Choice....")
                        except FileNotFoundError:
                            print(f"[!] Please check the file path once again!")
                            time.sleep(2)
                        except Exception as e:
                            print(f"[-] Failed due to {e}")
                            time.sleep(2)

                    else:
                        try:
                            if path.exists(filename)==True:
                                decrypt(filename,key)
                                print("[*] File Decrypted successfully")
                                time.sleep(2)
                            else:
                                print("[-] File cannot be decrypted....Please check the name")
                                time.sleep(2) 
                        except FileNotFoundError:
                            print(f"[!] Please check the file path once again!")
                            time.sleep(2)
                        except Exception as e:
                            print(f"[-] Failed due to {e}")
                            time.sleep(2)
#### END OF MODULE - 1.3 ####     
                            
            if inp=='1.4':
                print("[+] File Shredder is used to make the data in the deleted file unrecoverable")
                time.sleep(2)
                print("[+] It first corrupts the file and then deletes it,making it meaningless to recover!!")
                print("[+] Use this option if you want to feel safe after deleting a sensitive file!!")
                time.sleep(3)
                print("[+] NOTE : PLEASE don't abort(CTRL+C) in between the shredding process...it's pointless!")
                print("[*] CONFIRM YOUR CHOICE!!")
                time.sleep(2)
                ch=input("yes|no >>").lower()

                if ch=='yes' or ch=='y':
                    print("[+] Enter path to file...")
                    file_path = input("PegasusX>>")
    
                    try:
                        print("[+] SHREDDING STARTED...")
                        print("[+] File will be shredded twice to make recovery impossible!")
                        time.sleep(2)
                        print("[+]Initialising....")
                        key_char="abcdefghijklmnopqrstuvwxzzABCDEFGHIJKLMNOPQRSTUVWXYZ<>/\[]{}@#$&%!"
                        rkey=""
                        for i in range(512//8):
                            rkey+=key_char[random.randint(0,len(key_char)-1)]
                        key1 = random.randint(1,256)
                        key2 = random.randint(1,256)
                        while(key1==key2):
                            key1 = random.randint(1,256)
                        print("[+]The process is now irreversible...")
                        time.sleep(2)
                        
                        encrypt(file_path,key1)
                        encrypt(file_path,key2)
                        os.system(f"del {file_path}")
                        print("[+] SHREDDING COMPLETED...")
                        time.sleep(3)

                    except FileNotFoundError:
                        print("[-] INVALID PATH : Check the file path/name again!")
                        time.sleep(3)
                    except Exception as e:
                        print("[-] Failed due to {}".format(e))
                        time.sleep(3)
                    except OSError:
                        print("[-] Failed due to OS ERROR")
                    except KeyboardInterrupt:
                        print("[+] Aborting due to keyboardInterrupt....")
                        time.sleep(3)
                        print("[!] This will lead to corrupt files..")
                        time.sleep(3)
                else:
                    pass           

#### END OF MODULE - 1.4 ####
                
            if inp=='1.5':
                print("[*] What do you want to do?")
                print("""
                      <1> STEGANOGRAPHIC ENCODE
                      <2> STEGANOGRAPHIC DECODE
                """)
                ch = input("PegasusX>>")

                if(ch=='1'):
                    print("[+] Enter the secret message")
                    txt=input("PegasusX>>")
                    print("[+] Enter the file name to which you want to hide your message")
                    file=input("PegasusX>>")
                    if path.exists(file)==False:
                        print("[!] File does not exists")
                        time.sleep(2)
                    else:
                        try:
                            with open(f'{file}','ab') as f:
                                f.write(txt.encode('UTF-8'))
                            f.close()
                            print("[+] Message Encoded...")
                            time.sleep(2)
                        except Exception as e:
                            print("[-] failed due to ",e)
                            time.sleep(2)
                    
                if(ch=='2'):
                    print("[+] Enter the file name or file path")
                    path=input("PegasusX>>")
                    with open(f'{path}','rb') as file:
                        data=file.readlines()
                    lastline=data[-1]
                    print("[+] This section appears to have the hidden message")
                    print("-"*165)
                    print(lastline)
                    print("-"*165)
                    time.sleep(2)

#### END OF MODULE - 1.5 ####
                
            if inp=='1.6':
                print("[!] Under development...")
                time.sleep(2)
        
#### END OF MODULE - 1.6 ####
            
            if inp=='1.7':
                print("[!] Under development...")
                time.sleep(2)

#### END OF MODULE - 1.7 ####
                
            if inp=='1.8':
                print("[!] Under development...")
                time.sleep(2)

#### END OF MODULE - 1.8 ####
            
            if inp=='1.9':
                print("[!] Under development...")
                time.sleep(2)

#### END OF MODULE - 1.9 ####
                
            if inp=='2.1':
                print("[+] Enter domain name...")
                try:
                    domain = input("PegasusX>>")
                    if is_registered(domain):
                        print(f"[+] {domain} is registered!")
                        time.sleep(2)
                        print("\n")
                        print("[*] Initiating recon....")
                        whois_info = whois.whois(domain)
                        print("\n")
                        print(f"[*] DOMAIN NAME      : {whois_info.domain_name}")
                        print(f"[*] DOMAIN REGISTRAR : {whois_info.registrar}")
                        print(f"[*] WHOIS SERVER     : {whois_info.whois_server}")
                        print(f"[*] REFERRAL URL     : {whois_info.referral_url}")
                        print(f"[*] DATE OF CREATION : {whois_info.creation_date}")
                        print(f"[*] UPDATION DATE    : {whois_info.update_data}")
                        print(f"[*] DATE OF EXPIRY   : {whois_info.expiration_date}")
                        print(f"[*] ORGANIZATION     : {whois_info.organization}")
                        print(f"[*] COUNTRY          : {whois_info.country}")
                        print(f"[*] CITY             : {whois_info.city}")
                        print(f"[*] STATE            : {whois_info.state}")
                        print(f"[*] ADDRESS          : {whois_info.address}")
                        print(f"[*] DNS SECURITY     : {whois_info.dnssec}")
                        print(f"[*] EMAILS           : {whois_info.emails}")

                        try:
                            ns=whois_info.name_servers
                            print("[*] NAME SERVERS      :")
                            for i in range(0,len(ns)):
                                print(ns[i],end="\n")
                        except Exception as e:
                            print(f"[-] Failed due to {e}")
                    else:
                        print(f"[!] {domain} is not registered")
                        time.sleep(2)

                except Exception as e:
                    print(f"[-] Failed due to {e}")
                    time.sleep(2)

#### END OF MODULE - 2.1 ####
                    
            if inp=='2.2':
                print("[+] Enter domain name...")
                target_domain=input("PegasusX>>")
                try:
                    record_types = ["A", "AAAA", "CNAME", "MX", "NS", "SOA", "TXT"]
                    resolver = dns.resolver.Resolver()
                    for record_type in record_types:
                        try:
                            answers = resolver.resolve(target_domain, record_type)
                        except dns.resolver.NoAnswer:
                            continue
                        print("+------------------------------------------------+")
                        print(f"{record_type} records for {target_domain}:")
                        print("+------------------------------------------------+")
                        for rdata in answers:
                            print(f">{rdata}")
                except Exception as e:
                    print(f"[-] Failed due to {e}")
                    time.sleep(3)

#### END OF MODULE - 2.2 ####
                
            if inp=='2.3':
                print("[+] Enter IP address to enumerate..")
                ip_address=input("PegasusX>>")
                access_token = '993ed731b49c6a'
                print("\n")
                try:
                    handler = ipinfo.getHandler(access_token)
                    details = handler.getDetails(ip_address)
                    for key, value in details.all.items():
                        print(f"[*] {key.upper()} : {value}")
                        time.sleep(2)
                    print("\n")
                except Exception as e:
                    print(f"[-] Failed due to {e}")
                    time.sleep(2)
                
#### END OF MODULE - 2.3 ####
                    
            if inp=='3.1':
                print("[+] Enter target domain(ex: google.com)...")
                site = input("PegasusX>>")
                try:
                    print("[+] Checking for SQL injections...")
                    scan_sql_injection(f"http://{site}/")
                except Exception as e:
                    print(f"[-] Failed due to {e}")
            
#### END OF MODULE - 3.1 ####
                    
            if inp=='3.2':
                print("[+] Enter target url...")
                site = input("PegasusX>>")
                try:
                    print("[+] Checking for XSS vulnerability...")
                    print(scan_xss(f"http://{site}/"))
                except Exception as e:
                    print(f"[-] Failed due to {e}")

#### END OF MODULE - 3.2 ####
            
            if inp=='3.3':
                print("[+] Enter target domain...")
                site = input("PegasusX>>")
                print("[+] Do you want to use a heavy subdomain wordlist(takes time)")
                ch = input("yes|no >>").lower()
                print("[+] Discovering subdomains...")

                if(ch=='y' or ch=='yes'):
                    print("[!] ESTIMATED TIME : 3 MINS")
                    try:
                        file = open("subdomains-10k.txt")
                        content = file.read()
                        subdomains = content.splitlines()
                        discovered_subdomains = []
                        for subdomain in subdomains:
                            url = f"http://{subdomain}.{site}"
                            try:
                                requests.get(url)
                            except requests.ConnectionError:
                                pass
                            else:
                                print("[+] Discovered subdomain:", url)
                                discovered_subdomains.append(url)
                        print("[*] DISCOVERY COMPLETED...")
                        time.sleep(2)
                    except KeyboardInterrupt:
                        print("[+] Storing results in discovered_subdomains.txt file")
                        with open("discovered_subdomains.txt", "w") as f:
                            for subdomain in discovered_subdomains:
                                print(subdomain, file=f)
                        time.sleep(2)
                else:
                    print("[!] ESTIMATED TIME : 10 MINS")
                    try:
                        file = open("subdomains-1k.txt")
                        content = file.read()
                        subdomains = content.splitlines()
                        discovered_subdomains = []
                        
                        for subdomain in subdomains:
                            url = f"http://{subdomain}.{site}"
                            try:
                                requests.get(url)
                            except requests.ConnectionError:
                                pass
                            else:
                                print("[+] Discovered subdomain:", url)
                                discovered_subdomains.append(url)
                        print("[*] DISCOVERY COMPLETED...")
                        time.sleep(2)
                    except KeyboardInterrupt:
                        print("[+] Storing results in discovered_subdomains.txt file")
                        with open("discovered_subdomains.txt", "w") as f:
                            for subdomain in discovered_subdomains:
                                print(subdomain, file=f)
                        time.sleep(2)

#### END OF MODULE - 3.3 ####
                        
            if inp=='3.4':
                print("[+] Enter target domain...")
                site = input("PegasusX>>")
                print("[+] Starting scan...")
                time.sleep(2)
                ip = socket.gethostbyname(site)
                print(f"IP : {ip}")

                for port in range(1,100):
                    portscan(port)

#### END OF MODULE - 3.4 ####
                    
            if inp=='5.1':
                try:
                    print("[+] Enter path of image file...")
                    path = input("PegasusX>>")
                    getExif(path)
                except Exception as e:
                    print(f"[-] Failed due to : {e}")
                    time.sleep(2)

#### END OF MODULE - 5.1 ####
                    
            if inp=='5.3':
                try:
                    print("[+] Stored/Saved Passwords Connections...")
                    get_WIFIs()        
                    output = subprocess.check_output(['netsh', 'wlan', 'show', 'profiles']) 
                    data = output.decode('utf-8').split('\n')
                    profiles = []
                    for d in data:
                        if "All User" in d:
                            profiles.append(d.split(":")[1].replace('\r','').strip())
                    gold = [] 
                    for profile in profiles: 
                        command = ["netsh", "wlan", "show", "profile", profile, "key=clear"]
                        output = subprocess.check_output(command)
                        data = output.decode('utf-8').split('\n')
                        for d in data:
                            if "Key Content" in d:
                                password = d.split(":")[1].replace('\r','').strip()
                                gold.append([profile,password])

                    for g in gold:
                        print("+--------------------------+")
                        print("Username: " +g[0] + "\nPassword: " + g[1])
                        print("+--------------------------+")
                        time.sleep(3)
                except Exception as e:
                    print(f"[-] Failed due to {e}")
                    time.sleep(2)

#### END OF MODULE - 5.3 ####
                    
            if inp=='5.4':
                print("[+] Enter file path...")
                path = input("PegasusX>>")
                print("[+] scanning for metadata...")
                time.sleep(2)
                if not path:
                    print("please provide the path to the document!")
                if any(path.endswith(ext) for ext in (".docx", ".pptx", ".xlsx", ".vsdx", "thmx", "xltx", ".potx", ".vtx", ".ppsx", ".pub", ".zip")):
                    compMetaData(path)
                elif path.endswith(".pdf"):
                    pdfMetaData(path)
                elif any(path.endswith(ext) for ext in (".doc", ".ppt", ".xls", ".pps")):
                    oleMetaData(path)
                else:
                    print("File extension not supported/recognized... Make sure the file has the correct extension...")
                time.sleep(3)
                    
### END OF MODULE - 5.4 ####
                    
            if inp=='clear_logs':
                try:
                    with open("log.txt",'w') as log:  
                        log.write(' ')
                    print("[+]Successfully Cleared the log file!!")
                except:
                    print("[!]OOPS..ran into an error.. :(")

            if inp=='change_password':
                print("[!]verification required!!")
                print("[+]Enter your current/old password and key...")
                with open("database.txt",'r') as f:
                    r=f.read()
                    f.close()

                plain=' '.join(input("Enter password: ").lower().split())
                key=' '.join(input("Enter key: ").lower().split())

                if len(key)!=len(plain):
                    print("[-]Invalid Key!!")

                else:
                    out_of_pass_limit=False
                    guess=""
                    pass_limit=3
                    pass_count=0
                    while otp(plain,key)!=r and not(out_of_pass_limit):
                        if pass_count<pass_limit:
                            pass_count+=1
                            plain=' '.join(input("Enter password: ").lower().split())
                            key=' '.join(input("Enter key: ").lower().split())
            
                        else:
                            out_of_pass_limit=True

                    if out_of_pass_limit==True:
                        print("Permission Denied")
                    else:
                        time.sleep(2)
                        print("Permission Granted")
                        print("[!]Enter new password and key")
                        pas=input("Enter new password>>")
                        key=input("Enter new key>>")
                        cipher=otp(pas,key)
                        with open("database.txt",'w') as file:
                            file.write(cipher)
                            file.close()
                        print("[+]CREDENTIALS UPDATED SUCCESSFULLY...")
                        time.sleep(2)

            if inp=='destroy':
                print("[+] Use this to check the potential of your system...")
                print("[+] SCRIPT WILL RUN UNTIL THE SYSTEM CRASHES!")
                time.sleep(2)
                print("[+] The script acts like a self-replicating worm(malware) but harmless")
                print("[+] If system crashes just reboot the system...")
                time.sleep(2)
                ch=input("yes|no >>").lower()
                if ch=='y' or ch=='yes':
                    print("[+] Malware is running...")
                    time.sleep(2)
                    print("[!] Eating up memory and system's disk space")
                    try:
                        for i in range(50):
                            s="\nhi there this is self replicating virus be careful it can fill up space quickly\nit's main purpose is to fill up the RAM"*100000000
                            with open(f"demo{i}.txt",'w') as f:
                                f.write(s)
                        print("[*] Malware executed successfully...")
                        print("[*] CONGRATS!! YOUR SYSTEM IS POWERFULL")
                        time.sleep(2)
                    except Exception as e:
                        print("[-]Failed due to the exception : ",e) 
                        time.sleep(2)
                elif ch=='n' or ch=='no':
                    pass
                else:
                    print("[-] Incorrect option..")         
                

            if inp=='audio_recorder':
                try:
                    print("Duration for recording...")
                    seconds=int(input("pegasus>>"))
                    chunk=1024
                    sample_format=pyaudio.paInt16
                    chn=1
                    frame_rate=44400
                    filename=input("Enter a file name for storage>>")
                    py=pyaudio.PyAudio()
                    stream=py.open(format=sample_format,channels=chn,rate=frame_rate,input=True,
                                   frames_per_buffer=chunk)
                    try:
                        print('[*]Recording.....')
                        frames=[]
                        for i in range(0,int(frame_rate/chunk*seconds)):
                            data=stream.read(chunk)
                            frames.append(data)
                        stream.stop_stream()
                        stream.close()
                        py.terminate()
                        print("[+]Recording completed...")
                        time.sleep(2)
                        print("[+]saving....")
                        with wave.open(filename,'wb') as file:
                            file.setnchannels(chn)
                            file.setsampwidth(py.get_sample_size(sample_format))
                            file.setframerate(frame_rate)
                            file.writeframes(b''.join(frames))
                    except KeyboardInterrupt:
                        print("[!]saving the files....")
                        with wave.open(filename,'wb') as file:
                            file.setnchannels(chn)
                            file.setsampwidth(py.get_sample_size(sample_format))
                            file.setframerate(frame_rate)
                            file.writeframes(b''.join(frames))
                            file.close()
    
                except KeyboardInterrupt:
                    pass

            
            if 'wav_converter' in inp:
                print("""
                        1.convert a file
                        2.convert a list of files
                        """)
                ch=input("pegasus>>")
                if ch=='1':
                    print("[*]enter the filename")
                    file=input("pegasus>>")
                    fname=file.split('.mp3')
                    if path.exists(file)==True:
                        try:
                            print(f"[+]Converting {file} to {fname[0]}.wav")
                            os.system(f'cmd /c "ffmpeg -i {file} {fname[0]}.wav"')
                            print("[+]Converted.......")
                        except Exception as e:
                            print(f"[-]Failed due to {e}")
                            time.sleep(2)
                    else:
                        print("[-]Please check the name of your file")

                if ch=='2':
                    print("[*]Enter the names of mp3 files separated by comma")
                    file=input("pegasus>>")
                    fname=file.split(',')
                    if '*' in file:
                        inp=input("are you using wildcard??[y|n]>>").lower()
                        if inp=='y':
                            try:
                                os.system('dir /b *.mp3 > mp3_files.txt')
                                with open('mp3_files.txt','r') as file:
                                    fread=file.readlines()
                                    print(f"[*]Total no of files to be converted:{len(fread)}")
                                    for i in range(0,len(fread)):
                                        f_name=fread[i].split(',')
                                        f_name=fread[i].split('\n')
                                        f_name=fread[i].split('.mp3')
                                        try:
                                            print(f"[+]Converting {fread[i]} to {f_name[0]}.wav")
                                            os.system(f"ffmpeg -i {fread[i]} {f_name[0]}.wav")
                                            print(f"[+]Converter {fread[i]} ...")
                                            time.sleep(2)
                                        except Exception as e:
                                            print(f"[-]Failed due to {e}")
                                            time.sleep(2)
                            except KeyboardInterrupt:
                                print("[!]Warning :Keyboard Interrupt")
                            except Exception as e:
                                print(f"[-]Failed due to {e}")
                        if inp=='n':
                            print("[-]Please check the file name/path")

                    else:        
                        for i in range(0,len(fname)):
                            f_name=fname[i].split('.mp3')
                            try:
                                print(f"[+]Converting {fname[i]} to {f_name[0]}.wav")
                                os.system(f'cmd /c "ffmpeg -i {fname[i]} {f_name[0]}.wav"')
                                print(f"[+]Converted {fname[i]} ....")
                                time.sleep(2)
                            except Exception as e:
                                print(f"[-]Failed due to {e}")
                                time.sleep(2)
                            except KeyboardInterrupt:
                                print("[!]Warning :Keyboard Interrupt")
                                pass
                

            if inp=="rename_file":
                print("""
                        1.Rename a file
                        2.Rename multiple files at once
                        """)
                print("[+]Enter your choice")
                ch=input("pegasus>>")
                if ch=='1':
                    print("[*]Enter the name of file you want to rename(with extension)")
                    f=input("pegasus>>")
                    print("[*]Enter the new name for your file(with extension)")
                    name=input("pegasus>>")
                    try:
                        os.system(f"ren {f} {name}")
                        print(f"[+]Renamed {f} to {name}")
                    except Exception as e:
                        print("[-]Failed due to",e)

                if ch=='2':
                    print("[*]Enter the name of files to rename seperated by comma")
                    inp=input("pegasus>>")
                    ext=inp.split('.')
                    if '*' in inp:
                        print("[?]are you using wildcard|y|n|")
                        ch=input("pegasus>>").lower()
                        if ch=='y':
                            print("[*]Enter the new common name for your files")
                            name=input("pegasus>>")
                            print(f"""[!]all your files will now be renamed in the following pattern like {name}-0,{name}-1,.....""")
                            print("[+]Converting the below files")
                            os.system(f"dir /b '{inp}' > files.txt")
                            with open('files.txt','r') as file:
                                a=file.readlines()
                                for i in range(0,len(a)):
                                    print(a[i])
                            try:
                                with open('files.txt','r') as file:
                                    f=file.readlines()
                                    for i in range(0,len(f)):
                                        f_new=f[i].split(',')
                                        f_new=f[i].split('\n')
                                        f_new=f[i].split(f'.{ext[1]}')
                                        print(f"[+]converting {f[i].strip()}")
                                        os.system(f"ren {f[i].strip()} {name}-{i}.{ext[1]}")
                            except Exception as e:
                                print("[+]Failed due to",e) 
                            
            
            

            if inp=='4.2':
                print("[+]Please enter the keys correctly....wrong values will lead to data corruption")
                time.sleep(2)
                print("[+]This is done in order to protect the encrypted files from being susceptible to brute-froce attack...")
                time.sleep(3)
                print("[+]Please enter the value of KEY-I")
                k1=int(input("pegasus>>"))
                print("[+]Please enter the value of KEY-II")
                k2=int(input("pegasus>>"))
                print("[+]Please enter the value of Text-KEY")
                rkey=input("pegasus>>")
                try:
                    with open("image-files.txt",'r') as file:
                        f=file.readlines()
                        for i in range(0,len(f)):
                            f_data=f[i]
                            files=f_data.strip('\n')
                            decrypt(files,k2)
                            decrypt(files,k1)

                    with open("audio-files.txt",'r') as file:
                        f=file.readlines()
                        for i in range(0,len(f)):
                            f_data=f[i]
                            files=f_data.strip('\n')
                            decrypt(files,k2)
                            decrypt(files,k1)

                    with open("video-files.txt",'r') as file:
                        f=file.readlines()
                        for i in range(0,len(f)):
                            f_data=f[i]
                            files=f_data.strip('\n')
                            decrypt(files,k2)
                            decrypt(files,k1)
                    
                    with open("text-files.txt",'r') as file:
                        f=file.readlines()
                        for i in range(0,len(f)):
                            f_data=f[i]
                            files=f_data.strip('\n')
                            if files in ['audio-files.txt','image-files.txt','video-files.txt','text-files.txt','database.txt']:
                                pass
                            else:
                                ransom(files,rkey)
                    print("[+]UNSHREDDING COMPLETED....")
                    time.sleep(2)

                except Exception as e:
                    print("[-]Failed due to {}".format(e))
                except OSError:
                    print("[-]Failed due to OS ERROR")
                except KeyboardInterrupt:
                    print("[+]Aborting due to keyboardInterrupt....")
                    time.sleep(3)
                    print("[!]This will lead to corrupt files..")
                    time.sleep(3)

            if inp=="5.2":
                print("[+] YOU CAN PERFORM EMAIL FORENSICS IF COMPROMISED...")
                print("[!] When asked for password enter app password")
                print("[*] You can get it from myaccount.google.com/appasswords")
                time.sleep(3)
                target_id = input("Target id >>")
                passwd = input("Password(app password) >>")
                host_server = input("Host Server(Ex:gmail) >>")
                
                print("[+] Logging in....")
                try:
                    mail=imaplib.IMAP4_SSL(f"imap.{host_server}.com")
                    resp_code,response=mail.login(target_id,passwd)
                except Exception as e:
                    print("[-]Failed due to ",e)
                
                print("Response Code : {}".format(resp_code))
                print("Response  : {}".format(response))
                time.sleep(3)
                
                print("#########################################")
                mail.select("INBOX")
                _,data=mail.search(None,'ALL')
                print(f"[+]Number of INBOX messages :{len(data[0].split())}")
                mail.login(target_id,passwd)
                
                _,data=mail.search(None,'ALL')
                print(f"Number of SENT messages : {len(data[0].split())}")

                
                print("=============INBOX===========")
                ch=input(f"Do you want to expand all {len(data[0].split())} >>")
                if(ch=='y' or ch=='yes'):
                    for cont in data[0].split():
                        print("x-x-x-x-x-x-x-x-x-x-x-x-x-x-x-x")
                        _,mail_data=mail.fetch(cont, '(RFC822)')
                        byte_data=mail_data[0][1]
                        msg=email.message_from_bytes(byte_data)
                        print(f"Subject : {msg['subject']}")
                        print(f"To : {msg['to']}")
                        print(f"From :",{msg["from"]})
                        print(f"Date :",{msg['date']})
                        for part in msg.walk():
                            if part.get_content_type()=="text/plain" or part.get_content_type=="text/html":
                                message=part.get_payload(decode=True)
                                print("Message :\n",message.decode())
                                break
                else:
                    pass
                

            if inp=="setup":
                print("[+]Initiating the setup...")
                time.sleep(2)
                print("[!]This may take some time....")
                time.sleep(2)
                driver=webdriver.Edge()
                try:
                    print("[+]Downloading audacity...")
                    driver.get("https://github.com/audacity/audacity/releases/download/Audacity-3.2.4/audacity-win-3.2.4-x64.exe")
                    time.sleep(10)
                    print("[+]Successfully downloaded audacity")
                    
                except Exception as e:
                    print("[-]Failued to download due to",e)

                try:
                    print("[+]Downloading bleachbit...")
                    driver.get("https://www.bleachbit.org/download/file/t?file=BleachBit-4.4.2-setup.exe")
                    time.sleep(10)
                    print("Successully downloaded bleachbit")
                    
                except Exception as e:
                    print("[-]Failed due to ",e)

                try:
                    print("[+]Downloading deepsound...")
                    driver.get("https://www.majorgeeks.com/mg/getmirror/deepsound,1.html")
                    time.sleep(10)
                    print("[+]Successfully downloaded deepsound")
                except Exception as e:
                    print("[-]Failed due to",e)

                try:
                    print("[+]Downloading Maltego...")
                    driver.get("https://maltego-downloads.s3.us-east-2.amazonaws.com/windows/MaltegoSetup.JRE64.v4.3.1.exe")
                    time.sleep(10)
                    print("[+]Successfully downloaded maltego")
                except Exception as e:
                    print("[-]Failed due to ",e)

                try:
                    print("[+]Downloading VisualStudioCode...")
                    driver.get("https://code.visualstudio.com/sha/download?build=stable&os=win32-x64-user")
                    time.sleep(10)
                except Exception as e:
                    print("[-]Failed due to ",e)
                
                try:
                    print("[+]Downloading wireshark....")
                    driver.get("https://1.as.dl.wireshark.org/win64/Wireshark-win64-4.0.3.exe")
                    time.sleep(10)
                except Exception as e:
                    print("[-]Failed due to ",e)
                
                try:
                    print("[+]Downloading putty...")
                    driver.get("https://the.earth.li/~sgtatham/putty/latest/w64/putty-64bit-0.78-installer.msi")
                    time.sleep(10)
                except Exception as e:
                    print("[-]Failed due to ",e)

                try:
                    print("[+]Downloading balenaEtcher...")
                    driver.get("https://en.softonic.com/download/balenaetcher/windows/post-download")
                    time.sleep(10)
                except Exception as e:
                    print("[-]Failed due to ",e)

                try:
                    print("[+]Downloading oracle virtualbox....")
                    driver.get("https://download.virtualbox.org/virtualbox/7.0.6/VirtualBox-7.0.6-155176-Win.exe")
                    time.sleep(10)
                    driver.get("https://download.virtualbox.org/virtualbox/7.0.6/Oracle_VM_VirtualBox_Extension_Pack-7.0.6a-155176.vbox-extpack")
                    time.sleep(8)
                except Exception as e:
                    print("[-]Failed due to ",e)

                try:
                    print("[+]Downloading Coagula Light.....")
                    driver.get("https://ec.ccm2.net/ccm.net/download/files/CoagulaLight1666-1.666.zip")
                    time.sleep(10)
                except Exception as e:
                    print("[-]Failed due to ",e)

                time.sleep(50)
                driver.close()
                print("[*]SETUP COMPLETED.......")
                time.sleep(4)

            if inp=="sys_info":
                print("="*40, "System Information", "="*40)
                uname = platform.uname()
                print(f"System: {uname.system}")
                print(f"Node Name: {uname.node}")
                print(f"Release: {uname.release}")
                print(f"Version: {uname.version}")
                print(f"Machine: {uname.machine}")
                print(f"Processor: {uname.processor}")

                print("="*40, "Boot Time", "="*40)
                boot_time_timestamp = psutil.boot_time()
                bt = datetime.fromtimestamp(boot_time_timestamp)
                print(f"Boot Time: {bt.year}/{bt.month}/{bt.day} {bt.hour}:{bt.minute}:{bt.second}")

                print("="*40, "CPU Info", "="*40)
                # number of cores
                print("Physical cores:", psutil.cpu_count(logical=False))
                print("Total cores:", psutil.cpu_count(logical=True))
                # CPU frequencies
                cpufreq = psutil.cpu_freq()
                print(f"Max Frequency: {cpufreq.max:.2f}Mhz")
                print(f"Min Frequency: {cpufreq.min:.2f}Mhz")
                print(f"Current Frequency: {cpufreq.current:.2f}Mhz")

                # CPU usage
                print("CPU Usage Per Core:")
                for i, percentage in enumerate(psutil.cpu_percent(percpu=True, interval=1)):
                    print(f"Core {i}: {percentage}%")
                    print(f"Total CPU Usage: {psutil.cpu_percent()}%")

                # Memory Information
                print("="*40, "Memory Information", "="*40)
                # get the memory details
                svmem = psutil.virtual_memory()
                print(f"Total: {get_size(svmem.total)}")
                print(f"Available: {get_size(svmem.available)}")
                print(f"Used: {get_size(svmem.used)}")
                print(f"Percentage: {svmem.percent}%")
                print("="*20, "SWAP", "="*20)

                # get the swap memory details (if exists)
                swap = psutil.swap_memory()
                print(f"Total: {get_size(swap.total)}")
                print(f"Free: {get_size(swap.free)}")
                print(f"Used: {get_size(swap.used)}")
                print(f"Percentage: {swap.percent}%")

                # Disk Information
                print("="*40, "Disk Information", "="*40)
                print("Partitions and Usage:")
                # get all disk partitions
                partitions = psutil.disk_partitions()
                for partition in partitions:
                    print(f"=== Device: {partition.device} ===")
                    print(f"  Mountpoint: {partition.mountpoint}")
                    print(f"  File system type: {partition.fstype}")
                    try:
                        partition_usage = psutil.disk_usage(partition.mountpoint)
                    except PermissionError:
                        # this can be catched due to the disk that
                        # isn't ready
                        continue
                    print(f"  Total Size: {get_size(partition_usage.total)}")
                    print(f"  Used: {get_size(partition_usage.used)}")
                    print(f"  Free: {get_size(partition_usage.free)}")
                    print(f"  Percentage: {partition_usage.percent}%")

                # get IO statistics since boot
                disk_io = psutil.disk_io_counters()
                print(f"Total read: {get_size(disk_io.read_bytes)}")
                print(f"Total write: {get_size(disk_io.write_bytes)}")

                # Network information
                print("="*40, "Network Information", "="*40)
                # get all network interfaces (virtual and physical)
                if_addrs = psutil.net_if_addrs()
                for interface_name, interface_addresses in if_addrs.items():
                    for address in interface_addresses:
                        print(f"=== Interface: {interface_name} ===")
                        if str(address.family) == 'AddressFamily.AF_INET':
                            print(f"  IP Address: {address.address}")
                            print(f"  Netmask: {address.netmask}")
                            print(f"  Broadcast IP: {address.broadcast}")
                        elif str(address.family) == 'AddressFamily.AF_PACKET':
                            print(f"  MAC Address: {address.address}")
                            print(f"  Netmask: {address.netmask}")
                            print(f"  Broadcast MAC: {address.broadcast}")
                # get IO statistics since boot
                net_io = psutil.net_io_counters()
                print(f"Total Bytes Sent: {get_size(net_io.bytes_sent)}")
                print(f"Total Bytes Received: {get_size(net_io.bytes_recv)}")   


            if inp=="clear":
                os.system('cls')
                pass
            
            if inp=="exit" or inp=="quit":
                ex()
                break
        
=======
print("[+] Please wait...")
##Setup##
import os
import time

try:
    print("[*] Setting up the modules...")
    time.sleep(2)
    os.system('py -m pip install -r requirements.txt')
    os.system('cls')
    print("SETUP SUCCESSFULL...")
    time.sleep(2)
    os.system('cls')
    print("STARTING PegasusX....")
    time.sleep(2)
    os.system('cls')
except Exception as e:
    print("Failed to setup the necessary modules...")
    print(f"[-]ERROR : {e}")
    exit(0)

import lxml.etree as tree
from urllib.parse import urljoin
from pprint import pprint
from bs4 import BeautifulSoup as bs
from PyPDF2 import PdfReader
from zipfile import BadZipFile, ZipFile
from olefile import OleFileIO
import requests
import socket
import pyuac
import ctypes
import imaplib
import email
import ipinfo
import psutil
import platform
import dns.resolver
import whois
from os import path
import time
import random
from datetime import datetime
import wave
import pydub
from pydub import AudioSegment
from pydub.playback import play
import ffmpeg
import argparse
import sys
from datetime import datetime as dt
import subprocess
import keyboard
import threading
import librosa
import pyautogui
import getpass
import requests
from bs4 import BeautifulSoup
import selenium
from selenium import webdriver
from selenium.webdriver.common.keys import Keys
from selenium.webdriver.chrome.options import Options 
from PIL import Image
from PIL.ExifTags import TAGS
from winreg import *
from pathlib import Path
os.system('cls')

#check isAdmin
"""
if not pyuac.isUserAdmin():
    print("[!] Script requires administrator priveleges to function better!")
    time.sleep(2)
    print("[*] Re-launch the framework again as administrator!")
    time.sleep(2)
    exit(0)
"""  
#initializing ffmpeg
"""
pydub.AudioSegment.converter=r"D:\ffmpeg-n4.4-latest-win64-gpl-4.4\bin\ffmpeg.exe"
AudioSegment.converter=r"D:\ffmpeg-n4.4-latest-win64-gpl-4.4\bin\ffmpeg.exe"
AudioSegment.ffprobe=r"D:\ffmpeg-n4.4-latest-win64-gpl-4.4\bin\ffprobe.exe"
"""
#Files init
if path.exists('database.txt')==True:
    pass
else:
    with open("database.txt",'w') as file:
        file.write('kcck')
        file.close()
        
if path.exists('video-files.txt')==True:
    pass
else:
    file=open('video-files.txt','w')
    file.close()
    
if path.exists('image-files.txt')==True:
    pass
else:
    file=open('image-files.txt','w')
    file.close()
    
if path.exists('audio-files.txt')==True:
    pass
else:
    file=open('audio-files.txt','w')
    file.close()

if path.exists('text-files.txt')==True:
    pass
else:
    file=open('text-files.txt','w')
    file.close()
########END########       

###FUNCTIONS####
#steganography module - level 1
def stegMod(ch):

    if(ch=='1'):
        print("[+] Enter the secret message...")
        txt=input("[PegasusX]>>")
        print("[+] Enter the file name to which you want to hide your message")
        file=input("[PegasusX]>>")
        if path.exists(file)==False:
            print("[!] File does not exists")
            time.sleep(2)
        else:
            try:
                with open(f'{file}','ab') as f:
                    f.write(txt.encode('UTF-8'))
                f.close()
                print("[+] Message Encoded...")
                time.sleep(2)
            except Exception as e:
                print("[-] failed due to ",e)
                time.sleep(2)
                    
    if(ch=='2'):
        print("[*] Decoding is possible only if encoding was done in the same way")
        time.sleep(2)
        print("[+] Enter the file name or file path")
        p=input("[[PegasusX]]>>")
        with open(f'{p}','rb') as file:
            data=file.readlines()
        lastline=data[-1]
        print("[+] This section appears to have the hidden message")
        print("-"*165)
        print(lastline)
        print("-"*165)
        time.sleep(2)

#open protonVPN
def proto(wsl):
    print(f"[+]Enter the password for the {wsl}-wsl")
    passwd=input("[+]password>>")
    
    try:
        subprocess.Popen(['start','cmd','/k',wsl],shell=True,stdin=subprocess.PIPE,stdout=subprocess.PIPE,text=True)
        time.sleep(15)
        pyautogui.moveTo(300,300)
        pyautogui.click()
        pyautogui.typewrite("sudo /etc/init.d/xrdp start")
        pyautogui.press('enter')
        pyautogui.click(300,300)
        time.sleep(2)
        keyboard.write(passwd)
        time.sleep(2)
        pyautogui.press('enter')
        keyboard.write("ifconfig eth0 | grep -w inet | awk '{print $2}'")
        pyautogui.press('enter')
        time.sleep(2)
        keyboard.press_and_release('win+R')
        pyautogui.moveTo(100,500)
        keyboard.write('mstsc')
        pyautogui.press('enter')
    except Exception as e:
        print("[-]Failed due to {}".format(e))
    except OSError as ose:
        print("[-]Failed due to {}".format(ose))
    except KeyboardInterrupt:
        print("[-]Keyboard Interrupt...")

#whois lookup - domain
def is_registered(domain_name):
    try:
        w = whois.whois(domain_name)
    except Exception as e:
        return False
    else:
        return bool(w.domain_name)

#get metadata from file
def compMetaData(file_path):
    now = dt.now()
    file_name = getFileName(file_path)
    '''Get common document metadata, takes 2 arguments, file_path and save (boolean, default is True)'''
    metadata = "Time: %d/%d/%d %d : %d : %d. Found the following metadata for the file %s:\n\n" % (now.year, now.month,
                                                                                                   now.day, now.hour, now.minute,
                                                                                                   now.second, file_name[:-4])
    try:
        f = ZipFile(file_path)
        doc = tree.fromstring(f.read("docProps/core.xml"))

        ns = {'dc': 'http://purl.org/dc/elements/1.1/'}
        ns2 = {'dcterms': 'http://purl.org/dc/terms/'}
        ns3 = {'cp' : 'http://schemas.openxmlformats.org/package/2006/metadata/core-properties'}

        creator = doc.xpath('//dc:creator', namespaces=ns)[0].text
        last_modifier = doc.xpath('//cp:lastModifiedBy', namespaces=ns3)[0].text
        creation_time = doc.xpath('//dcterms:created', namespaces=ns2)[0].text
        xml_mod_time = doc.xpath('//dcterms:modified', namespaces=ns2)[0].text

    except BadZipFile:
        creator = "Could not get creator... File format not supported!"
        last_modifier = "Could not get last modifier... File format not supported!"
        creation_time = "Could not get creation time... File format not supported!"
        xml_mod_time = "Could not get xml modification time... File format not supported!"

    stats = os.stat(file_path)
    c_time = dt.fromtimestamp(stats.st_ctime)
    last_access_time = dt.fromtimestamp(stats.st_atime)
    last_mod_time = dt.fromtimestamp(stats.st_mtime)
    owner_user_id = stats.st_uid

    metadata += """Creator: %s\nLast Modified By: %s\nOwner User ID: %s\nLast metadata mod Time: %s\nCreation Time: %s
Last Modification Time: %s\nXML Modification Time: %s\nLast Access Time: %s""" % (creator, last_modifier, owner_user_id,
                                                                                  c_time, creation_time,
                                                                                  last_mod_time, xml_mod_time,
                                                                                  last_access_time)
    try:
        print(metadata)
    except UnicodeEncodeError:
        print("Console encoding can't decode the result. Enter chcp 65001 in the console and rerun the script.")

#ownership data for files
def oleMetaData(file_path):
    now = dt.now()
    file_name = getFileName(file_path)
    metadata = "Time: %d/%d/%d %d : %d : %d. Found the following metadata for file %s:\n\n" % (now.year, now.month,
                                                                                               now.day, now.hour, now.minute,
                                                                                               now.second, file_name[:-4])
    try:
        ole = OleFileIO(file_path)
        meta = ole.get_metadata()
        ole.close()
        author = meta.author.decode("latin-1")
        creation_time = meta.create_time.ctime()
        last_author = meta.last_saved_by.decode("latin-1")
        last_edit_time = meta.last_saved_time.ctime()
        last_printed = meta.last_printed.ctime()
        revisions = meta.revision_number.decode("latin-1")
        company = meta.company.decode("latin-1")
        creating_app = meta.creating_application.decode("latin-1")

        metadata += "Original Author: %s\nCreation Time: %s\nLast Author: %s\n" % (author, creation_time, last_author) \
                    + "Last Modification Time: %s\nLast Printed at: %s\Total Revisions: %s\n" % (last_edit_time, last_printed, revisions) \
                    + "Created with: %s\nCompany: %s" % (creating_app, company)

        try:
            print(metadata)
        except UnicodeEncodeError:
            print("Console encoding can't decode the result. Enter chcp 65001 in the console and rerun the script.")
            
    except OSError as e1:
        print("[-] File not supported: %s" % e1)
    except FileNotFoundError:
        print("[-] Specified file could not be found")

def pretifyPyPDF2Time(key, val):
    '''Make PyPDF2 time code more readable'''
    if "D:" in val and "Date" in key:
        temp = list(val)
        temp.insert(6, "-")
        temp.insert(9, "-")
        temp.insert(12, "  ")
        temp.insert(15, ":")
        temp.insert(18, ":")
        return "".join(temp)
    else:
        return val

#pdf metadata
def pdfMetaData(file_path):
    '''Get PDF document metadata, takes 2 arguments, file_path and save (boolean, default is True)'''
    pdf_doc = PdfReader(open(file_path, "rb"))

    if pdf_doc.is_encrypted:
        try:
            if pdf_doc.decrypt("") != 1:
                sys.exit("[!] Target pdf document is encrypted... exiting...")
                time.sleep(2)
        except:
            sys.exit("[!] Target pdf document is encrypted with an unsupported algorithm... exiting...")
            time.sleep(2)

    doc_info = pdf_doc.metadata
    stats = os.stat(file_path)
    now = dt.now()
    file_name = Path(file_path).name
    metadata = "\n[+] Time: %d/%d/%d %d : %d : %d. \n[+] Found the following metadata for file %s:\n\n" % (now.year, now.month,
                                                                                               now.day, now.hour, now.minute,
                                                                                               now.second, file_name[:-4])
    try:
        for md in doc_info:
            metadata += '[+] ' + str(md[1:]) + " : " + pretifyPyPDF2Time(str(md[1:]) ,str(doc_info[md])) + "\n"
    except TypeError:
        sys.exit("[-] Couldn't read document info! Make sure target is a valid pdf document...")
        time.sleep(3)

    metadata += "[+] Last metadata mod Date: %s\n[+] Last Mod Date: %s\n[+] Last Access Date: %s\n[+] Owner User ID: %s" %(dt.fromtimestamp(stats.st_ctime),
                                                                                                           dt.fromtimestamp(stats.st_mtime),
                                                                                                           dt.fromtimestamp(stats.st_atime),
                                                                                                           stats.st_uid)
    try:
        print(metadata)
    except UnicodeEncodeError:
        print("[-] Console encoding can't decode the result. Enter chcp 65001 in the console and rerun the script.")
    
#convert size to human-readable
def get_size(bytes, suffix="B"):
    """
    Scale bytes to its proper format
    e.g:
        1253656 => '1.20MB'
        1253656678 => '1.17GB'
    """
    factor = 1024
    for unit in ["", "K", "M", "G", "T", "P"]:
        if bytes < factor:
            return f"{bytes:.2f}{unit}{suffix}"
        bytes /= factor

#port scanner module
def portscan(port):
                    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    s.settimeout(1)
                    try:
                        con = s.connect((site,port))
                        print('[+] Port :',port," is open.")
                        con.close()
                    except: 
                        pass

#caesar cipher encryption algorithm
def caesar(txt,s):
    result=""
    for i in range(len(txt)):
        char=txt[i]
        if char.isupper():
            result+=chr((ord(char)+s-65)%26+65)
        if char.isspace():
            result+=char
        if char.isdigit():
            result+=char
        if char.islower():
            result+=chr((ord(char)+s-97)%26+97)
    return result

#AES encryption algorithm
def aes(txt,ch):
    char_pool=''
    char_pool_basic='abcdefghijklmnopqrstuvwxzzABCDEFGHIJKLMNOPQRSTUVWXYZ<>,./\[]{}'
    key=''   
    
    if ch==1:
        for i in range(128//8):
            key+=char_pool_basic[random.randint(0,len(char_pool_basic)-1)]
        print("your key ",key)
        key_index=0
        max_index=(128//8)-1
        encrypted_msg=''
        for char in txt:
            xoring=ord(char)^ord(key[key_index])
            encrypted_msg+=chr(xoring)
            if key_index>=max_index:
                key_index=0
            else:
                key_index+=1
        return encrypted_msg

    if ch==2:
        max_index=0
        for i in range(0x00,0xff):
            char_pool+=chr(i)
        for i in range(256//8):
            key+=random.choice(char_pool)
        print("your key ",key)
        encrypted_msg=''
        key_index=0
        for char in txt:
            xoring=ord(char)^ord(key[key_index])
            encrypted_msg+=chr(xoring)
            if key_index>=max_index:
                key_index=0
            else:
                key_index+=1
        return encrypted_msg

#image forensics module
def getExif(image_file):
    if not os.path.isfile(image_file):
        sys.exit("%s is not a valid image file!"%(image_file))
    now=datetime.now()
    data = "Time: %d/%d/%d %d : %d : %d. Found the following Exif data for the image %s:\n\n" % (now.year, now.month,
                                                                                                 now.day, now.hour, now.minute,
                                                                                                 now.second,image_file)
    img = Image.open(image_file)
    info = img._getexif()
    exif_data = {}
    if info:
        for (tag, value) in info.items():
            decoded = TAGS.get(tag, tag)
            if type(value) is bytes:
                try:
                    exif_data[decoded] = value.decode("utf-8")
                except:
                    pass
            else:
                exif_data[decoded] = value
        for key in exif_data:
            data += "{}    :   {}\n".format(key, exif_data[key])

        print("Found the following exif data:\n")
        time.sleep(3)
        print("+-----------------------------------------------------------------------------+")
        print("|                          Image Metadata                                     |")
        print("+-----------------------------------------------------------------------------+")
        print(data)
        print("+-----------------------------------------------------------------------------+")
    else:
        print("[-] NO EXIF DATA FOUND!")
        time.sleep(2)

#ransomware module - test
def ransom(file,key):
    try:
        key_index=0
        max_index=len(key)-1
        encrypted_data=''
        with open(file, 'rb') as f:
            data=f.read()
        with open(file, 'w') as f:
            f.write(' ')
        for byte in data:
            xoring=byte^ord(key[key_index])
            with open(file, 'ab') as f:
                f.write(xoring.to_bytes(1, 'little'))
            if key_index>=max_index:
                key_index=0
            else:
                key_index+=0
    except:
        print("OOps...seems like an error :(....you are lucky")

#morse code obfuscation algorithm
def morse(message,no):
    morse_code={'A':'.-','B':'-...','C':'-.-.','D':'-..','E':'.','F':'..-.',
            'G':'--.','H':'....','I':'..','J':'.---','K':'-.-','L':'.-..',
            'M':'--','N':'--.-','O':'---','P':'.--.','Q':'--.-','R':'.-.',
            'S':'...','T':'-','U':'..-','V':'...-','W':'.--','X':'-..-',
            'Y':'-.--','Z':'--..','1':'.----','2':'..---','3':'...--',
            '4':'....-','5':'.....','6':'-....','7':'--...','8':'---..',
            '9':'----.','0':'-----',',':'--..--','.':'.-.-.-','?':'..--..',
            '/':'-..-.','-':'-....-','(':'-.--.', ')':'-.--.-'}
    morse_decode = {v: k for k, v in morse_code.items()}

    a=message.split()
    if no== '1':
        cipher=''
        for letter in message:
            if letter != ' ':
                cipher+=morse_code[letter]+' '
            else:
                cipher+=' '
        return cipher
    if no=='2':
        key_list=list(morse_code.keys())
        val_list=list(morse_code.values())
        decipher=''
        n=""
        for chrs in message:
            if chrs!=" ":
                decipher+=chrs
                space_found=0
            else:
                space_found+=1
                if space_found==2:
                    n+=" "
                else:
                    n=n+key_list[val_list.index(decipher)]
                    decipher=""
        return n              

#one-time-pad cipher
def otp(plain,key):
    result=""
    try:
        for i in range(len(plain)): 
            ch=plain[i]
            result+=chr((ord(ch)-97 +ord(key[i])-97)%26 +97)

        return result
    except:
        pass
           
#file encryption module
def encrypt(filename,key):
    file=open(filename,'rb')
    dat=file.read()
    file.close()
    dat=bytearray(dat)
    for index,value in enumerate(dat):
        dat[index]=value ^ key  #performs an bitwise XOR operation
    file=open(filename,'wb')
    file.write(dat)
    file.close()
        
#file decryption module
def decrypt(filename,key):
    file=open(filename,'rb')
    dat=file.read()
    file.close()
    dat=bytearray(dat)
    for index,value in enumerate(dat):
        dat[index]=value ^ key  #performs an bitwise XOR operation
        
    file=open(filename, "wb")
    file.write(dat)
    file.close()

#obtain data of url
def getdata(url):
    r=requests.get(url)
    return(r.text)

#rot-13 obfuscation algorithm
def rot(string):
    rot={"a":"n","b":"o","c":"p","d":"q","e":"r","f":"s","g":"t","h":"u","i":"v","j":"w","k":"x","l":"y","m":"z",'n':'a','o':'b','p':'c','q':'d','r':'e','s': 'f', 't': 'g', 'u': 'h', 'v': 'i', 'w': 'j', 'x': 'k', 'y': 'l', 'z': 'm'}
    a=""
    r=a.join([rot.get(i,i) for i in string])
    return r

#update exit in log file
def ex():
    with open("log.txt",'a') as lg:
        datim=datetime.now()
        dat=datim.strftime("%d/%m/%y %H:%M:%S")
        log=f"\n[+]closed at {dat}"+" status(closed)"
        lg.write(log)

#base64 encoding and decoding
class base64:
    def encode(input_string):
        base64_chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+*"
        binary_data = ''.join(format(ord(char), '08b') for char in input_string)
        while len(binary_data) % 6 != 0:
            binary_data += '0'
        encoded_data = ''
        for i in range(0, len(binary_data), 6):
            chunk = binary_data[i:i+6]
            index = int(chunk, 2)
            encoded_data += base64_chars[index]
        while len(encoded_data) % 4 != 0:
            encoded_data += '-'
        return encoded_data
        
    
    def decode(data):
        base64_chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+*"
        data = data.rstrip('-')
        binary_data = ''.join(format(base64_chars.index(char), '06b') for char in data)
        decoded_data = ''
        for i in range(0, len(binary_data), 8):
            chunk = binary_data[i:i+8]
            decoded_data += chr(int(chunk, 2))
        return decoded_data
    
#SQL INJECTION SCANNER MODULES
s = requests.Session()
s.headers["User-Agent"] = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/83.0.4103.106 Safari/537.36"

def get_all_forms(url):
    """Given a `url`, it returns all forms from the HTML content"""
    soup = bs(s.get(url).content, "html.parser")
    return soup.find_all("form")


def get_form_details(form):
    """
    This function extracts all possible useful information about an HTML `form`
    """
    details = {}
  
    try:
        action = form.attrs.get("action").lower()
    except:
        action = None
   
    method = form.attrs.get("method", "get").lower()
   
    inputs = []
    for input_tag in form.find_all("input"):
        input_type = input_tag.attrs.get("type", "text")
        input_name = input_tag.attrs.get("name")
        input_value = input_tag.attrs.get("value", "")
        inputs.append({"type": input_type, "name": input_name, "value": input_value})

    details["action"] = action
    details["method"] = method
    details["inputs"] = inputs
    return details

def is_vulnerable(response):
    errors = {
        # MySQL
        "SQL syntax.*?MySQL",
        "MySqlException",
        "you have an error in your sql syntax;",
        "warning: mysql",
        #postgresql
        "PostgreSQL.*?ERROR",
        "Warning.*?\Wpg_",
        "PostgreSQL query failed",
        "ERROR:\s\ssyntax error at or near",
        # SQL Server
        "unclosed quotation mark after the character string",
        "ODBC SQL Server Driver",
        r"Microsoft SQL Native Client error '[0-9a-fA-F]{8}",
        "ODBC SQL Server Driver"
        # Oracle
        "quoted string not properly terminated",
        "OracleException",
        "SQL command not properly ended",
        "Oracle error",
        #cache
        "encountered after end of query"
        "A comparison operator is required here"
    }
    for error in errors:
        if error in response.content.decode().lower():
            return True
    # no error detected
    return False

def scan_sql_injection(url):
    for c in "\"'":
        new_url = f"{url}{c}"
        print("[!] Trying", new_url)
        res = s.get(new_url)
        if is_vulnerable(res):
            print("[+] SQL Injection vulnerability detected, link:", new_url)
            time.sleep(3)
            return
    forms = get_all_forms(url)
    print(f"[+] Detected {len(forms)} forms on {url}.")
    for form in forms:
        form_details = get_form_details(form)
        for c in "\"'":
            data = {}
            for input_tag in form_details["inputs"]:
                if input_tag["type"] == "hidden" or input_tag["value"]:
                    try:
                        data[input_tag["name"]] = input_tag["value"] + c
                    except:
                        pass
                elif input_tag["type"] != "submit":
                    data[input_tag["name"]] = f"test{c}"
            url = urljoin(url, form_details["action"])
            if form_details["method"] == "post":
                res = s.post(url, data=data)
            elif form_details["method"] == "get":
                res = s.get(url, params=data)
            if is_vulnerable(res):
                print("[+] SQL Injection vulnerability detected, link:", url)
                print("[+] Form:")
                pprint(form_details)
                time.sleep(3)
                break

#XSS Vulnerability
def Get_all_forms(url):
    """Given a `url`, it returns all forms from the HTML content"""
    soup = bs(requests.get(url).content, "html.parser")
    return soup.find_all("form")

def Get_form_details(form):
    details = {}
    # get the form action (target url)
    action = form.attrs.get("action", "").lower()
    # get the form method (POST, GET, etc.)
    method = form.attrs.get("method", "get").lower()
    # get all the input details such as type and name
    inputs = []
    for input_tag in form.find_all("input"):
        input_type = input_tag.attrs.get("type", "text")
        input_name = input_tag.attrs.get("name")
        inputs.append({"type": input_type, "name": input_name})
    # put everything to the resulting dictionary
    details["action"] = action
    details["method"] = method
    details["inputs"] = inputs
    return details

def Submit_form(form_details, url, value):

    # construct the full URL (if the url provided in action is relative)
    target_url = urljoin(url, form_details["action"])
    # get the inputs
    inputs = form_details["inputs"]
    data = {}
    for input in inputs:
        # replace all text and search values with `value`
        if input["type"] == "text" or input["type"] == "search":
            input["value"] = value
        input_name = input.get("name")
        input_value = input.get("value")
        if input_name and input_value:
            # if input name and value are not None, 
            # then add them to the data of form submission
            data[input_name] = input_value

    print(f"[+] Submitting malicious payload to {target_url}")
    print(f"[+] Data: {data}")
    if form_details["method"] == "post":
        return requests.post(target_url, data=data)
    else:
        # GET request
        return requests.get(target_url, params=data)
    
def scan_xss(url):
    # get all the forms from the URL
    forms = Get_all_forms(url)
    print(f"[+] Detected {len(forms)} forms on {url}.")
    time.sleep(2)
    js_script = "<Script>alert('hi')</scripT>"
    is_vulnerable = False
    # iterate over all forms
    for form in forms:
        form_details = Get_form_details(form)
        content = Submit_form(form_details, url, js_script).content.decode()
        if js_script in content:
            print(f"[+] XSS Detected on {url}")
            print(f"[*] Form details:")
            pprint(form_details)
            is_vulnerable = True
            time.sleep(3)
            # won't break because we want to print available vulnerable forms
    if(is_vulnerable):
        print("[*] Vulerable to XSS vulnerability..")
        time.sleep(2)
    else:
        print("[-] Not Vulnerble to XSS vulnerability..")
        time.sleep(2)
        
#get BSID's
def get_WIFIs():
    wlans = r'SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkList' \
            + r'\Signatures\Unmanaged'
    key = OpenKey(HKEY_LOCAL_MACHINE, wlans)
    data = ""
    num = 0
    for i in range(1000000):
        try:
            attempt = EnumKey(key, i)
            wlan_key = OpenKey(key, str(attempt))
            (n, addr, t) = EnumValue(wlan_key, 5)
            (n, name, t) = EnumValue(wlan_key, 4)
            res, mac_address = val2addr(addr)
            wlan_name = str(name)
            print("+------------------------------------+")
            print(f"| BSSID :{wlan_name}                 ")
            print(f"| MAC :{mac_address}                 ")
            print("+------------------------------------+")
            CloseKey(wlan_key)
            num += 1
        except Exception as e:
            break

#logging module
def log():
    datim=datetime.now()
    dat=datim.strftime("%d/%m/%y %H:%M:%S")
    log=f"\n[+]Logged at {dat}"+" status(Running)"
    with open("log.txt",'a') as lg:
        lg.write(log)
log()
###############END###############

print("Enter the Access code")

with open("database.txt",'r') as f:
    r=f.read()

plain=' '.join(input("Enter password: ").lower().split())
key=' '.join(input("Enter key: ").lower().split())

if len(key)!=len(plain):
    print("[-]Invalid Key!!")

else:
    out_of_pass_limit=False
    guess=""
    pass_limit=3
    pass_count=0
    while otp(plain,key)!=r and not(out_of_pass_limit):
        if pass_count<pass_limit:
            pass_count+=1
            plain=' '.join(input("Enter password: ").lower().split())
            key=' '.join(input("Enter key: ").lower().split())
            
        else:
            out_of_pass_limit=True

    if out_of_pass_limit==True:
        print("Permission Denied")
    else:
        time.sleep(2)
        print("Permission Granted")
        time.sleep(2)
        while True:
            print(r"""
            =x=x=x=x=x=x=x=x=x=x=x=x=x=x=x=x=x=x=x=x=x=x=x=x=x=x=x=x=x=x=x=x=x=x=x=x=x=x=x=x=x=x=x=x  _/\__ 
                     @$%&&#$ @#$#%$%@ #$%^%#@@@$  #$#%$%  #$%$#%#^%  #$     #$  #$@#$#$@#$           /    \\                                
                     @     # @        #          #      # @          #$     #$  @                    |.    \/\                              
                     @##$%$% @$%@$%$# #   ##%%#% ##$#$%$# @4@$%$%$%  #$     #$  @#$%$%#$%$           |  )   \\\                               
                     @       @        #        # #      #         @  #$     #$           @           \_/ |  //|\\                    
                     @       @#$#%$%% ##$%#$@$#$ #      # #$%$%#$%%  #$#$%$%#$  @#$$%%$@$% v1.0.0          /   \\\/\\\            
            =x=x=x=x=x=x=x=x=x=x=x=x=x=x=x=x=x=x=x=x=x=x=x=x=x=x=x=x=x=x=x=x=x=x=x=x=x=x=x=x=x=x=x=x   / 
                                      ENCRYPTION AND SECURITY FRAMEWORK
            =x=x=x=x=x=x=x=x=x=x=x=x=x=x=x=x=x=x=x=x=x=x=x=x=x=x=x=x=x=x=x=x=x=x=x=x=x=x=x=x=x=x=x=x
            @Author: dave
            @License: MIT
                                               >>Windows Version<< 
                                      *****SECURITY EXISTS PEGASUS EXISTS******
            +-----------------------------------------------------------------------------------------------------------+      
            |    NOTE!!                                                                                                 |                                          
            |    <!> Type exit or quit to exit and type clear to clear the previous commands                            |                                         
            |    <!> Encrypted Messages will be stored in Encrypted Message.txt.                                        |
            |    <!> So, it will be overwritten so save it to another file before you use other encryption modules!     |                           
            |    <!> Decrypted Messages will be stored in Decrypted Message.txt.                                        |
            +-----------------------------------------------------------------------------------------------------------+
                    
            +-------------------------------+---------------------------------------+-----------------------------------+                 
            |         >>SHIELDS<<           |     >>WEB-PENETRATION-SCANNNERS<<     |           >>FORENSICS<<           |   
            +-------------------------------+---------------------------------------+-----------------------------------+
            | [1.1] TEXT ENCRYPTION         | [2.1] DOMAIN RECON                    | [3.1] IMAGE FORENSICS             |
            | [1.2] TEXT OBFUSCATION        | [2.2] DNS ENUMERATION                 | [3.2] E-MAIL FORENSICS            |
            | [1.3] FILE ENCRYPTION         | [2.3] IP ADDR ENUMERATION             | [3.3] NETWORK FORENSICS           |               
            | [1.4] FILE SHREDDER           | [2.4] SQL-INJECTION SCANNER           | [3.4] FILE FORENSICS              |
            | [1.5] MULTI-FILE SHREDDER     | [2.5] XSS VULNERABILITY SCANNER       |                                   |
            | [1.6] IMAGE STEGANOGRAPHY     | [2.6] SUB-DOMAIN DISCOVERY            |                                   |       
            | [1.7] VIDEO STEGANOGRAPHY     | [2.7] PORT SCANNER                    |                                   |
            | [1.8] NETWORK STEGANOGRAPHY   |                                       |                                   |
            | [1.9] DOCUMENT STEGANOGRAPHY  |                                       |                                   |
            +-------------------------------+---------------------------------------+-----------------------------------+

            GENERAL COMMANDS:
                wav_converter  -> convert mp3 to wav
                audio_recorder -> record audio in .mp3 format
                clear          -> clears the shell
                change_password-> change password of framework
                exit/quit      -> exit the framework
                sys_info       -> display intensive report on system specifications
                clear_logs     -> clears the log file
                setup          -> will download popular pentesting application for windows like maltego, wireshark
                destroy        -> a worm used to test your system's potential
                        """)
            inp=input("[PegasusX]>>").lower()

            if inp=='1.1':
                os.system('cls')
                print("""
                        <0> Return to main menu
                        <1> Encrypt a text
                        <2> Encrypt a text file (USE THIS FOR LARGER TEXTS)
                        <3> Decrypt a text
                        <4> Decrypt a text file (USE THIS FOR LARGER TEXTS)
                """)
                ch=input("[PegasusX]>>")

                if ch=='1':
                    print("[+] Enter the text")
                    text=input("[PegasusX]>>")
                    print("[+] Choose an algorithm for encryption")
                    print("""\n
                        [ More algorithms soon... :) ]
                        <1> CAESAR CIPHER ALGORITHM
                    """)
                    algo_ch = input("[PegasusX]>>")

                    if(algo_ch=='1'):
                        try:
                            print("""
                                <1> Specify the shift value
                                <2> Randomly generate a shift value
                            """)
                            s_ch = input("[PegasusX]>>")
                            if(s_ch=='1'):
                                shift_key=int(input("Pegasus>>"))
                            else:
                                print("[*]Randomly generating a shift value...")
                                shift_key = random.randint(1,25)
                                print("[+]REMEMBER SHIFT KEY FOR DECRYPTION")
                                print(f"[!]SHIFT-KEY : {shift_key}")
                                time.sleep(3)

                            output=caesar(text,shift_key)
                            with open('Encrypted Message.txt','w') as f:
                                f.write(output)
                            print("[+]Encrypted Message stored in 'Encrypted Message.txt' file")
                            time.sleep(3)
                        except Exception as e:
                            print(f"[-]Failed due to {e}")

                elif ch=='2':
                    print("[+]Choose an algorithm for encryption")
                    print("""\n
                        [ More algorithms soon... :) ]
                        <1> CAESAR CIPHER ALGORITHM 
                    """)
                    algo_ch = input("[PegasusX]>>")

                    if algo_ch=='1':
                        try:
                            print("[+]Enter the path to text file")
                            file_path = input("[PegasusX]>>")
                            print("""
                                <1> Specify the shift value
                                <2> Randomly generate a shift value
                            """)
                            s_ch = input("[PegasusX]>>")
                            if(s_ch=='1'):
                                shift_value=int(input("Pegasus>>"))
                            else:
                                print("[*]Randomly generating a shift value...")
                                shift_value = random.randint(1,25)

                                print("[+]REMEMBER SHIFT KEY FOR DECRYPTION")
                                print(f"[!]SHIFT-KEY : {shift_value}")
                                time.sleep(3)

                            f = open(file_path,'r')
                            text = f.read()
                            o=caesar(text,shift_value)
                            with open(file_path,'w') as file:
                                file.write(o)
                            print(f"[+]Encrypted {file_path} successfully...")
                            time.sleep(3)
                        except FileNotFoundError:
                            print(f"[!] Invalid File path/name !")
                            time.sleep(2)
                        except Exception as e:
                            print(f"[-]Failed due to {e}")
                            time.sleep(2)

                elif ch=='3':
                    print("[+]Choose an algorithm for decryption")
                    print("""\n
                        [ More algorithms soon... :) ]
                        <1> CAESAR CIPHER ALGORITHM
                        <2> NONE OF THE ABOVE
                    """)
                    algo_ch = input("[PegasusX]>>")

                    if algo_ch=='1':
                        print("[+]Enter the text")
                        text = input("[PegasusX]>>")
                        print("[+]Enter shift value")
                        shift_key = int(input("[PegasusX]>>"))
                        try:
                            output=caesar(text,26-shift_key)
                            print(f"Decrypting with shift vale:{shift_key}")
                            print(f"Output message : {output}")
                            time.sleep(1)
                            print("[+] Completed....")
                            time.sleep(2)
                        except Exception as e:
                            print(f"[-]Failed to due to {e}")

                    if algo_ch=='2':
                        print("[-]Sorry to hear that, but we currently only support these algorithms...")
                        time.sleep(2) 
                
                elif ch=='4':
                    print("[+]Choose an algorithm for decryption")
                    print("""\n
                        [ More algorithms soon... :) ]
                        <1> CAESAR CIPHER ALGORITHM
                        <2> NONE OF THE ABOVE
                    """)
                    algo_ch = input("[PegasusX]>>")
                    if(algo_ch=='1'):
                        print("[+] Enter the absolute path to file")
                        file_path = input("[PegasusX]>>")
                        print("[+] Enter shift value")
                        shift_key = int(input("[PegasusX]>>"))

                        try:
                            f = open(file_path,'r')
                            text = f.read()
                            o=caesar(text,26-shift_key)        
                            with open(file_path,'w') as file:
                                file.write(o)
                            print("[+]File decrypted successfully")
                            time.sleep(3)
                        except FileNotFoundError:
                            print(f"[!] Invalid File path/name !")
                            time.sleep(2)
                        except Exception as e:
                            print("[-]failed due to the exception : ",e)
                            time.sleep(2)

                    if algo_ch=='2':
                        print("[-]Sorry to hear that, but currently only these algorithms are available :(")
                        time.sleep(2)

#####END OF MODULE-1.1########
                        
            if inp=='1.2':
                os.system('cls')
                print("[+] Please refer manual to understand obfuscation and deobfuscation better or google it!")
                time.sleep(3)

                print("""
                        <1> Obfuscate a text
                        <2> Obfuscate a text file (USE THIS FOR LARGER TEXTS)
                        <3> Deobfuscate a text
                        <4> Deobfuscate a text file (USE THIS FOR LARGER TEXTS)
                    """)
                ch = input("[PegasusX]>>")

                if(ch=='1'):
                    print("[+] Select a text obfuscation technique")
                    print("""
                      <1> MORSE-CODE OBFUSCATION
                      <2> ROT-13 OBFUSCATION
                      <3> REVERSE TEXT OBFUSCATION
                      <4> BASE64 OBFUSCATION
                    """)
                    obf_ch = input("[PegasusX]>>")

                    if(obf_ch=='1'):
                        print("[+] Enter the text...")
                        try:
                            txt = input("[PegasusX]>>")
                            en=morse(txt.upper(),'1')
                            with open('Obfuscated Message.txt','w') as f:
                                f.write(en)
                            print("[+] Obfuscated successfully...")
                            print("[+] Please check the Obfuscated Message.txt file for the obfuscated text")
                            time.sleep(3)
                        except Exception as e:
                            print(f"[-] Failed due to {e}")

                    if(obf_ch=='2'):
                        print("[+] Enter the text...")
                        try:
                            wrd=input("[PegasusX]>>")  
                            out=rot(wrd)
                            with open("Obfuscated Message.txt",'w') as f: 
                                f.write(out)
                            print("[+] Obfuscated successfully")
                            print("[+] Please check the Obfuscated Message.txt file for the obfuscated text")
                            time.sleep(3)
                        except Exception as e:
                            print(f"[-] Failed due to {e}")
                            time.sleep(2)

                    if(obf_ch=='3'):
                        print("[+] Enter the text...")
                        try:
                            txt = input("[PegasusX]>>")
                            rev_text = ''
                            i = len(txt) - 1
                            while i >= 0:
                                rev_text = rev_text + txt[i]
                                i = i - 1
                            with open("Obfuscated Message.txt",'w') as f:
                                f.write(rev_text)
                            print("[+] Obfuscated Successfully")
                            print("[+] Please check the Obfuscated Message.txt file for the obfuscated text")
                            time.sleep(3)
                        
                        except Exception as e:
                            print(f"[-] Failed due to {e}")
                            time.sleep(2)
                        
                    if(obf_ch=='4'):
                        print("[+] Enter the text...")
                        try:
                            txt = input("[PegasusX]>>")
                            data = base64.encode(txt)
                            with open("Obfuscated Message.txt",'w') as f:
                                f.write(data)
                            print("[+] Obfuscated successfully")
                            print("[+] Please check the Obfuscated Message.txt file for the obfuscated text")
                            time.sleep(3)
                        except Exception as e:
                            print(f"[-] Failed due to {e}")
                            time.sleep(2)


                if ch=='2':
                    print("[+] Select a text obfuscation technique")
                    print("""
                      <1> MORSE-CODE OBFUSCATION
                      <2> ROT-13 OBFUSCATION
                      <3> REVERSE TEXT OBFUSCATION
                      <4> BASE64 OBFUSCATION
                    """)
                    obf_ch = input("[PegasusX]>>")

                    if(obf_ch=='1'):
                        print("[+] Enter the path(absolute) to file...")
                        try:
                            file_path = input("[PegasusX]>>")
                            file = open(file_path,'r')
                            txt = file.read()

                            output=morse(txt.upper(),'1')
                            with open(file_path,'w') as f:
                                f.write(output)
                            print("[+] Obfuscated successfully...")
                            print(f"[+] Please check the {file_path} file for the obfuscated text")
                            time.sleep(3)
                        except FileNotFoundError:
                            print(f"[!] Please check the file path/name once again!")
                            time.sleep(2)
                        except Exception as e:
                            print(f"[-] Failed due to {e}")
                            time.sleep(2)

                    if(obf_ch=='2'):
                        print("[+] Enter the path(absolute) to file...")
                        try:
                            file_path = input("[PegasusX]>>")
                            file = open(file_path,'r')
                            txt = file.read()

                            out=rot(txt)
                            with open(file_path,'w') as f: 
                                f.write(out)
                            print("[+] Obfuscated successfully")
                            print(f"[+] Please check the {file_path} file for the obfuscated text")
                            time.sleep(3)
                        except FileNotFoundError:
                            print(f"[!] Please check the file path/name once again!")
                            time.sleep(2)
                        except Exception as e:
                            print(f"[-] Failed due to {e}")
                            time.sleep(2)

                    if(obf_ch=='3'):
                        print("[+] Enter the path(absolute) to file...")
                        try:
                            file_path = input("[PegasusX]>>")
                            file = open(file_path,'r')
                            txt = file.read()
                            rev_text = ''
                            i = len(txt) - 1
                            while i >= 0:
                                rev_text = rev_text + txt[i]
                                i = i - 1
                            with open(file_path,'w') as f:
                                f.write(rev_text)
                            print("[+] Obfuscated Successfully")
                            print(f"[+] Please check the {file_path} file for the obfuscated text")
                            time.sleep(3)
                        except FileNotFoundError:
                            print(f"[!] Please check the file path/name once again!")
                            time.sleep(2)
                        except Exception as e:
                            print(f"[-] Failed due to {e}")
                            time.sleep(2)

                    if(obf_ch=='4'):
                        print("[+] Enter the path(absolute) to file...")
                        try:
                            file_path = input("[PegasusX]>>")
                            file = open(file_path,'r')
                            txt = file.read()
                        
                            data = base64.encode(txt)
                            with open(file_path,'w') as f:
                                f.write(data)
                            print("[+] Obfuscated successfully")
                            print(f"[+] Please check the {file_path} file for the obfuscated text")
                            time.sleep(3)
                        except FileNotFoundError:
                            print(f"[!] Please check the file path/name once again!")
                            time.sleep(2)
                        except Exception as e:
                            print(f"[-] Failed due to {e}")
                            time.sleep(2)

                if(ch=='3'):
                    print("[+] Select a text deobfuscation technique")
                    print("""
                      <1> MORSE-CODE OBFUSCATION
                      <2> ROT-13 OBFUSCATION
                      <3> REVERSE TEXT OBFUSCATION
                      <4> BASE64 OBFUSCATION
                    """)
                    obf_ch = input("[PegasusX]>>")

                    if(obf_ch=='1'):
                        print("[+] Enter the encoded morse code...")
                        mor=input("[PegasusX]>>")
                        en=morse(mor.upper(),'2')
                    
                        time.sleep(3)
                        with open('Deobfuscated Message.txt','w') as file:
                            file.write(en)
                            file.close()
                        print("[+] Deobfuscated Successfully...")
                        print("[+] Check out the Deobfuscated Message.txt file")
                        time.sleep(3)
                        
                    if(obf_ch=='2'):
                        print("[+] Enter the encoded rot-13 code...")
                        txt = input("[PegasusX]>>")
                        
                        out=rot(wrd)
                        with open("Deobfuscated Message.txt",'w') as e:
                            e.write(out)
                        print("[+] Deobfuscated successfully")
                        print("[+] Please check the Deobfuscated Message.txt file for the deobfuscated text")
                        time.sleep(3)

                    if(obf_ch=='3'):
                        print("[+] Enter the encoded reverse text...")
                        txt = input("[PegasusX]>>")
                        rev_text = ''
                        i = len(txt) - 1
                        while i >= 0:
                            rev_text = rev_text + txt[i]
                            i = i - 1
                        with open("Deobfuscated Message.txt",'w') as f:
                            f.write(rev_text)
                        print("[+] Deobfuscated Successfully")
                        print("[+] Please check the Deobfuscated Message.txt file for the Deobfuscated text")
                        time.sleep(3)

                    if(obf_ch=='4'):
                        print("[+] Enter the encoded base64 text...")
                        txt = input("[PegasusX]>>")
                        data = base64.decode(txt)
                        with open("Deobfuscated Message.txt",'w') as f:
                            f.write(data)
                        print("[+] Deobfuscated successfully")
                        print("[+] Please check the Deobfuscated Message.txt file for the Deobfuscated text")
                        time.sleep(3)


                if(ch=='4'):
                    print("[+] Select a text deobfuscation technique")
                    print("""
                      <1> MORSE-CODE DEOBFUSCATION
                      <2> ROT-13 DEOBFUSCATION
                      <3> REVERSE TEXT DEOBFUSCATION
                      <4> BASE64 DEOBFUSCATION
                    """)
                    obf_ch = input("[PegasusX]>>")

                    if(obf_ch=='1'):
                        print("[+] Enter the path(absolute) to file...")
                        try:
                            file_path = input("[PegasusX]>>")
                            file = open(file_path,'r')
                            txt = file.read()
                            output=morse(txt.upper(),'2')
                            with open(file_path,'w') as f:
                                f.write(output)
                            print("[+] Deobfuscated successfully...")
                            print(f"[+] Please check the {file_path} file for the deobfuscated text")
                            time.sleep(3)
                        except FileNotFoundError:
                            print(f"[!] Please check the file path/name once again!")
                            time.sleep(2)
                        except Exception as e:
                            print(f"[-] Failed due to {e}")
                            time.sleep(2)

                    if(obf_ch=='2'):
                        print("[+] Enter the path(absolute) to file...")
                        try:
                            file_path = input("[PegasusX]>>")
                            file = open(file_path,'r')
                            txt = file.read()

                            out=rot(txt)
                            with open(file_path,'w') as f: 
                                f.write(out)
                            print("[+] Deobfuscated successfully")
                            print(f"[+] Please check the {file_path} file for the deobfuscated text")
                            time.sleep(3)
                        except FileNotFoundError:
                            print(f"[!] Please check the file path once again!")
                            time.sleep(2)
                        except Exception as e:
                            print(f"[-] Failed due to {e}")
                            time.sleep(2)

                    if(obf_ch=='3'):
                        print("[+] Enter the path(absolute) to file...")
                        try:
                            file_path = input("[PegasusX]>>")
                            file = open(file_path,'r')
                            txt = file.read()
                        
                            rev_text = ''
                            i = len(txt) - 1
                            while i >= 0:
                                rev_text = rev_text + txt[i]
                                i = i - 1
                            with open(file_path,'w') as f:
                                f.write(rev_text)
                            print("[+] Deobfuscated Successfully")
                            print(f"[+] Please check the {file_path} file for the Deobfuscated text")
                            time.sleep(3)
                        except FileNotFoundError:
                            print(f"[!] Please check the file path once again!")
                            time.sleep(2)
                        except Exception as e:
                            print(f"[-] Failed due to {e}")
                            time.sleep(2)

                    if(obf_ch=='4'):
                        print("[+] Enter the path(absolute) to file...")
                        try:
                            file_path = input("[PegasusX]>>")
                            file = open(file_path,'r')
                            txt = file.read()
                        
                            data = base64.encode(txt)
                            with open(file_path,'w') as f:
                                f.write(data)
                            print("[+] Deobfuscated successfully")
                            print(f"[+] Please check the {file_path} file for the Deobfuscated text")
                            time.sleep(3)
                        except FileNotFoundError:
                            print(f"[!] Please check the file path once again!")
                            time.sleep(2)
                        except Exception as e:
                            print(f"[-] Failed due to {e}")
                            time.sleep(2)
#### END OF MODULE - 1.2 #####           
            
            if inp=='1.3':
                print("[+] What do you want to do?")
                print("""
                    <1> File Encryption
                    <2> File Decryption
                """)
                ch = input("[PegasusX]>>")

                if(ch=='1'):
                    print("[+]Please create a private key(digits in range 1-256)")
                    print("[!]Remember your key, without the key your data will be encrypted forever")
                    key=int(input("[PegasusX]>>"))
                    print("[+]Now Enter the file location(absolute)")
                    filename=input("[PegasusX]>>")

                    if '*' in filename:
                        try:
                            ch=input("[!]Are you using wildcard?[y|n]>>").lower()
                            if ch=='n':
                                if path.exists(filename)==True:
                                    print(f"Encrypting {filename}...it may take time if the file is too big!!")
                                    encrypt(filename, key)
                                    print("[*]File Encrypted successfully")
                                    time.sleep(2)
                                else:
                                    print("[-]File cannot be encrypted....Please check the name")
                                    time.sleep(2)
                            if ch=='y':
                                print("[+]Encrypting....")
                                os.system(f'dir {filename} /b > file_data.txt')
                                c=0
                                time.sleep(2)
                                with open('file_data.txt','r') as file:
                                    a=file.readlines()
                                for i in range(0,len(a)):
                                    f_data=a[i]
                                    files=f_data.strip('\n')
                                    encrypt(files,key)
                                print("[+]Encrypted All the files....")
                                pass
                            else:
                                print("[-] Invalid Choice....")
                        except FileNotFoundError:
                            print(f"[!] Please check the file path once again!")
                            time.sleep(2)
                        except Exception as e:
                            print(f"[-] Failed due to {e}")
                            time.sleep(2)
                        
                    else:
                        try:
                            if path.exists(filename)==True:
                                print(f"Encrypting {filename}...it may take time if the file is too big!!")
                                encrypt(filename, key)
                                print("[*]File Encrypted successfully")
                                time.sleep(2)
                            else:
                                print("[-]File cannot be decrypted....Please check the name")
                                time.sleep(2)
                        except FileNotFoundError:
                            print(f"[!] Please check the file path once again!")
                            time.sleep(2)
                        except Exception as e:
                            print(f"[-] Failed due to {e}")
                            time.sleep(2)
                    
                if ch=='2':
                    print("[+]Enter the private key(digits in range 0-256)")
                    key=int(input("[PegasusX]>>"))
                    print("[+]Enter the file location")
                    filename=input("[PegasusX]>>")
                    if '*' in filename:
                        try:
                            print("Are u using wildcard?")
                            ch = input("yes|no>>").lower()
                            if ch=='n':
                                if path.exists(filename)==True:
                                    decrypt(filename,key)
                                    print("[*] File Decrypted successfully")
                                    time.sleep(2)
                                else:
                                    print("[-] File cannot be decrypted....Please check the name")
                                    time.sleep(2)
                            if ch=='y':
                                print("[+] Decrypting....")
                                os.system(f'dir {filename} /b > file_data.txt')
                                c=0
                                time.sleep(2)
                                with open('file_data.txt','r') as file:
                                    a=file.readlines()
                                for i in range(0,len(a)):
                                    f_data=a[i]
                                    files=f_data.strip('\n')
                                    decrypt(files,key)
                                print("[+] Decrypted all the files...")
                                pass
                            else:
                                print("[-] Invalid Choice....")
                        except FileNotFoundError:
                            print(f"[!] Please check the file path once again!")
                            time.sleep(2)
                        except Exception as e:
                            print(f"[-] Failed due to {e}")
                            time.sleep(2)

                    else:
                        try:
                            if path.exists(filename)==True:
                                decrypt(filename,key)
                                print("[*] File Decrypted successfully")
                                time.sleep(2)
                            else:
                                print("[-] File cannot be decrypted....Please check the name")
                                time.sleep(2) 
                        except FileNotFoundError:
                            print(f"[!] Please check the file path once again!")
                            time.sleep(2)
                        except Exception as e:
                            print(f"[-] Failed due to {e}")
                            time.sleep(2)
                            
#### END OF MODULE - 1.3 ####     

            nview = 0                
            if inp=='1.4':
                if(nview < 2):
                    print("[+] File Shredder is used to make the data in the deleted file unrecoverable")
                    time.sleep(2)
                    print("[+] It first corrupts the file and then deletes it,making it meaningless to recover!!")
                    print("[+] Use this option if you want to feel safe after deleting a sensitive file!!")
                    time.sleep(3)
                    nview += 1
                print("[+] NOTE : PLEASE don't abort(CTRL+C) in between the shredding process...it's pointless!")
                print("[*] PROCESS : SHRED TWICE => DELETE")
                print("[*] CONFIRM YOUR CHOICE!!")
                time.sleep(2)
                ch=input("yes|no >>").lower()

                if ch=='yes' or ch=='y':
                    print("[+] Enter path to file(absolute)...")
                    file_path = input("[PegasusX]>>")
    
                    try:
                        print("[+] SHREDDING STARTED...")
                        print("[+] File will be shredded twice to make recovery impossible!")
                        time.sleep(2)
                        print("[+] Initialising....")
                        key_char="abcdefghijklmnopqrstuvwxzzABCDEFGHIJKLMNOPQRSTUVWXYZ<>/\[]{}@#$&%!"
                        rkey=""
                        for i in range(512//8):
                            rkey+=key_char[random.randint(0,len(key_char)-1)]
                        key1 = random.randint(1,256)
                        key2 = random.randint(1,256)
                        while(key1==key2):
                            key1 = random.randint(1,256)
                        print("[+] The process is now irreversible...")
                        time.sleep(2)
                        
                        encrypt(file_path,key1)
                        encrypt(file_path,key2)
                        os.system(f"del {file_path}")
                        print("[+] SHREDDING COMPLETED...")
                        time.sleep(3)

                    except FileNotFoundError:
                        print("[-] INVALID PATH : Check the file path/name again!")
                        time.sleep(3)
                    except Exception as e:
                        print("[-] Failed due to {}".format(e))
                        time.sleep(3)
                    except OSError:
                        print("[-] Failed due to OS ERROR")
                    except KeyboardInterrupt:
                        print("[+] Aborting due to keyboardInterrupt....")
                        time.sleep(3)
                        print("[!] This will lead to corrupt files..")
                        time.sleep(3)
                else:
                    pass           

#### END OF MODULE - 1.4 ####

            view = 0
            if inp=='1.5':
                if(view < 2):
                    view += 1
                    print("[+] File Shredder is used to shred/corrupt files before deleting it.")
                    print("[+] It's like tearing a sensitive document before throwing it into the bin!")
                    time.sleep(2)
                print("[!] WARNING: Use this module with care! Because it's irreversible")
                print("[*] PROCESS: SHRED ONCE => DELETE")
                print("[*] Confirm to proceed..")
                ch = input("yes|no >>").lower()
                if(ch == 'yes'):
                    print("[+] Please make sure to update the image-files.txt, text-files.txt, audio-files.txt, video-files.txt with absolute paths to each file")
                    time.sleep(2)

                    try:
                        with open("image-files.txt",'r') as file:
                            f=file.readlines()
                            for i in range(0,len(f)):
                                f_data=f[i]
                                files=f_data.strip('\n')
                                k1 = random.randint(1,254)
                                k2 = k1+1
                                encrypt(files,k1)
                                encrypt(files,k2)
                                os.system(f"del {files}")

                        with open("audio-files.txt",'r') as file:
                            f=file.readlines()
                            for i in range(0,len(f)):
                                f_data=f[i]
                                files=f_data.strip('\n')
                                k1 = random.randint(1,254)
                                k2 = k1+1
                                encrypt(files,k1)
                                encrypt(files,k2)
                                os.system(f"del {files}")

                        with open("video-files.txt",'r') as file:
                            f=file.readlines()
                            for i in range(0,len(f)):
                                f_data=f[i]
                                files=f_data.strip('\n')
                                k1 = random.randint(1,254)
                                k2 = k1+1
                                encrypt(files,k1)
                                encrypt(files,k2)
                                os.system(f"del {files}")
                        
                        with open("text-files.txt",'r') as file:
                            f=file.readlines()
                            for i in range(0,len(f)):
                                f_data=f[i]
                                files=f_data.strip('\n')
                                if files in ['audio-files.txt','image-files.txt','video-files.txt','text-files.txt','database.txt']:
                                    pass
                                else:
                                    k1 = random.randint(1,254)
                                    k2 = k1+1
                                    encrypt(files,k1)
                                    encrypt(files,k2)
                                    os.system(f"del {files}")

                        print("[+]SHREDDING COMPLETED....")
                        time.sleep(2)

                    except Exception as e:
                        print("[-]Failed due to {}".format(e))
                    except OSError:
                        print("[-]Failed due to OS ERROR")
                    except KeyboardInterrupt:
                        print("[+]Aborting due to keyboardInterrupt....")
                        time.sleep(3)
                        print("[!]This will lead to corrupt files..")
                        time.sleep(3)

#### END OF MODULE - 1.5 ####

            if inp=='1.6':
                if(novel_visit == 0):
                    print("[*] Method: Append steganography is a technique to hide data by appending in hex dump")
                    time.sleep(2)
                    print("[*] But it's not easily detectable until noticed/anticipated. Refer docs for more information!")
                    time.sleep(2)
                    print("[*] It supports all file formats!!")
                    time.sleep(2)
                print("[*] What do you want to do?")
                print("""
                      <1> STEGANOGRAPHIC ENCODE
                      <2> STEGANOGRAPHIC DECODE
                """)
                print("Enter path(absolute) to your image")
                ch = input("[PegasusX]>>")
                stegMod(ch)
        
#### END OF MODULE - 1.6 ####
            
            if inp=='1.7':
                if(novel_visit == 0):
                    print("[*] Method: Append steganography is a technique to hide data by appending in hex dump")
                    time.sleep(2)
                    print("[*] But it's not easily detectable until noticed/anticipated. Refer docs for more information!")
                    time.sleep(2)
                    print("[*] It supports all file formats!!")
                    time.sleep(2)
                print("[*] What do you want to do?")
                print("""
                      <1> STEGANOGRAPHIC ENCODE
                      <2> STEGANOGRAPHIC DECODE
                """)
                print("Enter path(absolute) to your video")
                ch = input("[PegasusX]>>")
                stegMod(ch)

#### END OF MODULE - 1.7 ####
                
            if inp=='1.8':
                print("[!] Under development...")
                time.sleep(2)

#### END OF MODULE - 1.8 ####

            novel_visit = 0
            if inp=='1.9':
                if(novel_visit == 0):
                    print("[*] Method: Append steganography is a technique to hide data by appending in hex dump")
                    time.sleep(2)
                    print("[*] But it's not easily detectable until noticed/anticipated. Refer docs for more information!")
                    time.sleep(2)
                    print("[*] It supports all file formats!!")
                    time.sleep(2)
                print("[*] What do you want to do?")
                print("""
                      <1> STEGANOGRAPHIC ENCODE
                      <2> STEGANOGRAPHIC DECODE
                """)
                print("Enter path(absolute) to your document")
                ch = input("[PegasusX]>>")
                stegMod(ch)

#### END OF MODULE - 1.9 ####
                
            if inp=='2.1':
                print("[+] Enter domain name...")
                try:
                    domain = input("[PegasusX]>>")
                    if is_registered(domain):
                        print(f"[+] {domain} is registered!")
                        time.sleep(2)
                        print("\n")
                        print("[*] Initiating recon....")
                        whois_info = whois.whois(domain)
                        print("\n")
                        print(f"[*] DOMAIN NAME      : {whois_info.domain_name}")
                        print(f"[*] DOMAIN REGISTRAR : {whois_info.registrar}")
                        print(f"[*] WHOIS SERVER     : {whois_info.whois_server}")
                        print(f"[*] REFERRAL URL     : {whois_info.referral_url}")
                        print(f"[*] DATE OF CREATION : {whois_info.creation_date}")
                        print(f"[*] UPDATION DATE    : {whois_info.update_data}")
                        print(f"[*] DATE OF EXPIRY   : {whois_info.expiration_date}")
                        print(f"[*] ORGANIZATION     : {whois_info.organization}")
                        print(f"[*] COUNTRY          : {whois_info.country}")
                        print(f"[*] CITY             : {whois_info.city}")
                        print(f"[*] STATE            : {whois_info.state}")
                        print(f"[*] ADDRESS          : {whois_info.address}")
                        print(f"[*] DNS SECURITY     : {whois_info.dnssec}")
                        print(f"[*] EMAILS           : {whois_info.emails}")

                        try:
                            ns=whois_info.name_servers
                            print("[*] NAME SERVERS      :")
                            for i in range(0,len(ns)):
                                print(ns[i],end="\n")
                        except Exception as e:
                            print(f"[-] Failed due to {e}")
                    else:
                        print(f"[!] {domain} is not registered")
                        time.sleep(2)

                except Exception as e:
                    print(f"[-] Failed due to {e}")
                    time.sleep(2)

#### END OF MODULE - 2.1 ####
                    
            if inp=='2.2':
                print("[+] Enter domain name...")
                target_domain=input("[PegasusX]>>")
                try:
                    record_types = ["A", "AAAA", "CNAME", "MX", "NS", "SOA", "TXT"]
                    resolver = dns.resolver.Resolver()
                    for record_type in record_types:
                        try:
                            answers = resolver.resolve(target_domain, record_type)
                        except dns.resolver.NoAnswer:
                            continue
                        print("+------------------------------------------------+")
                        print(f"{record_type} records for {target_domain}:")
                        print("+------------------------------------------------+")
                        for rdata in answers:
                            print(f">{rdata}")
                except Exception as e:
                    print(f"[-] Failed due to {e}")
                    time.sleep(3)

#### END OF MODULE - 2.2 ####
                
            if inp=='2.3':
                print("[+] Enter IP address to enumerate..")
                ip_address=input("[PegasusX]>>")
                access_token = '993ed731b49c6a'
                print("\n")
                try:
                    handler = ipinfo.getHandler(access_token)
                    details = handler.getDetails(ip_address)
                    for key, value in details.all.items():
                        print(f"[*] {key.upper()} : {value}")
                        time.sleep(2)
                    print("\n")
                except Exception as e:
                    print(f"[-] Failed due to {e}")
                    time.sleep(2)
                
#### END OF MODULE - 2.3 ####
                    
            if inp=='2.4':
                print("[+] Enter target domain(ex: google.com)...")
                site = input("[PegasusX]>>")
                try:
                    print("[+] Checking for SQL injections...")
                    scan_sql_injection(f"http://{site}/")
                except Exception as e:
                    print(f"[-] Failed due to {e}")
            
#### END OF MODULE - 3.1 ####
                    
            if inp=='2.5':
                print("[+] Enter target url...")
                site = input("[PegasusX]>>")
                try:
                    print("[+] Checking for XSS vulnerability...")
                    print(scan_xss(f"http://{site}/"))
                except Exception as e:
                    print(f"[-] Failed due to {e}")

#### END OF MODULE - 3.2 ####
            
            if inp=='2.6':
                print("[+] Enter target domain...")
                site = input("[PegasusX]>>")
                print("[+] Do you want to use a heavy subdomain wordlist(takes time)")
                ch = input("yes|no >>").lower()
                print("[+] Discovering subdomains...")

                if(ch=='y' or ch=='yes'):
                    print("[!] ESTIMATED TIME : 10 MINS")
                    try:
                        file = open("subdomains-10k.txt")
                        content = file.read()
                        subdomains = content.splitlines()
                        discovered_subdomains = []
                        for subdomain in subdomains:
                            url = f"http://{subdomain}.{site}"
                            try:
                                requests.get(url)
                            except requests.ConnectionError:
                                pass
                            else:
                                print("[+] Discovered subdomain:", url)
                                discovered_subdomains.append(url)
                        print("[*] DISCOVERY COMPLETED...")
                        time.sleep(2)
                    except KeyboardInterrupt:
                        print("[+] Storing results in discovered_subdomains.txt file")
                        with open("discovered_subdomains.txt", "w") as f:
                            for subdomain in discovered_subdomains:
                                print(subdomain, file=f)
                        time.sleep(2)
                else:
                    print("[!] ESTIMATED TIME : 3 MINS")
                    try:
                        file = open("subdomains-1k.txt")
                        content = file.read()
                        subdomains = content.splitlines()
                        discovered_subdomains = []
                        
                        for subdomain in subdomains:
                            url = f"http://{subdomain}.{site}"
                            try:
                                requests.get(url)
                            except requests.ConnectionError:
                                pass
                            else:
                                print("[+] Discovered subdomain:", url)
                                discovered_subdomains.append(url)
                        print("[*] DISCOVERY COMPLETED...")
                        time.sleep(2)
                    except KeyboardInterrupt:
                        print("[+] Storing results in discovered_subdomains.txt file")
                        with open("discovered_subdomains.txt", "w") as f:
                            for subdomain in discovered_subdomains:
                                print(subdomain, file=f)
                        time.sleep(2)

#### END OF MODULE - 3.3 ####
                        
            if inp=='2.7':
                print("[+] Enter target domain...")
                site = input("[PegasusX]>>")
                print("[+] Starting scan...")
                time.sleep(2)
                ip = socket.gethostbyname(site)
                print(f"IP : {ip}")

                for port in range(1,100):
                    portscan(port)

#### END OF MODULE - 3.4 ####
                    
            if inp=='3.1':
                try:
                    print("[+] Enter path of image file...")
                    path = input("[PegasusX]>>")
                    getExif(path)
                except Exception as e:
                    print(f"[-] Failed due to : {e}")
                    time.sleep(2)

#### END OF MODULE - 3.1 ####
                    
            if inp=='3.3':
                try:
                    print("[+] Stored/Saved Passwords Connections...")
                    get_WIFIs()        
                    output = subprocess.check_output(['netsh', 'wlan', 'show', 'profiles']) 
                    data = output.decode('utf-8').split('\n')
                    profiles = []
                    for d in data:
                        if "All User" in d:
                            profiles.append(d.split(":")[1].replace('\r','').strip())
                    gold = [] 
                    for profile in profiles: 
                        command = ["netsh", "wlan", "show", "profile", profile, "key=clear"]
                        output = subprocess.check_output(command)
                        data = output.decode('utf-8').split('\n')
                        for d in data:
                            if "Key Content" in d:
                                password = d.split(":")[1].replace('\r','').strip()
                                gold.append([profile,password])

                    for g in gold:
                        print("+--------------------------+")
                        print("Username: " +g[0] + "\nPassword: " + g[1])
                        print("+--------------------------+")
                        time.sleep(3)
                except Exception as e:
                    print(f"[-] Failed due to {e}")
                    time.sleep(2)

#### END OF MODULE - 3.3 ####
                    
            if inp=='3.4':
                print("[+] Enter file path...")
                path = input("[PegasusX]>>")
                print("[+] scanning for metadata...")
                time.sleep(2)
                if not path:
                    print("please provide the path to the document!")
                if any(path.endswith(ext) for ext in (".docx", ".pptx", ".xlsx", ".vsdx", "thmx", "xltx", ".potx", ".vtx", ".ppsx", ".pub", ".zip")):
                    compMetaData(path)
                elif path.endswith(".pdf"):
                    pdfMetaData(path)
                elif any(path.endswith(ext) for ext in (".doc", ".ppt", ".xls", ".pps")):
                    oleMetaData(path)
                else:
                    print("File extension not supported/recognized... Make sure the file has the correct extension...")
                time.sleep(3)
                    
### END OF MODULE - 3.4 ####
                    
            if inp=='clear_logs':
                try:
                    with open("log.txt",'w') as log:  
                        log.write(' ')
                    print("[+]Successfully Cleared the log file!!")
                except:
                    print("[!]OOPS..ran into an error.. :(")

            if inp=='change_password':
                print("[!]verification required!!")
                print("[+]Enter your current/old password and key...")
                with open("database.txt",'r') as f:
                    r=f.read()
                    f.close()

                plain=' '.join(input("Enter password: ").lower().split())
                key=' '.join(input("Enter key: ").lower().split())

                if len(key)!=len(plain):
                    print("[-]Invalid Key!!")

                else:
                    out_of_pass_limit=False
                    guess=""
                    pass_limit=3
                    pass_count=0
                    while otp(plain,key)!=r and not(out_of_pass_limit):
                        if pass_count<pass_limit:
                            pass_count+=1
                            plain=' '.join(input("Enter password: ").lower().split())
                            key=' '.join(input("Enter key: ").lower().split())
            
                        else:
                            out_of_pass_limit=True

                    if out_of_pass_limit==True:
                        print("Permission Denied")
                    else:
                        time.sleep(2)
                        print("Permission Granted")
                        print("[!]Enter new password and key")
                        pas=input("Enter new password>>")
                        key=input("Enter new key>>")
                        cipher=otp(pas,key)
                        with open("database.txt",'w') as file:
                            file.write(cipher)
                            file.close()
                        print("[+]CREDENTIALS UPDATED SUCCESSFULLY...")
                        time.sleep(2)

            if inp=='destroy':
                print("[+] Use this to check the potential of your system...")
                print("[+] Open up your task manager to monitor....")
                print("[+] SCRIPT WILL RUN UNTIL THE SYSTEM CRASHES!")
                time.sleep(2)
                print("[+] The script acts like a self-replicating worm(malware) but harmless")
                print("[+] If system crashes just reboot the system...")
                time.sleep(2)
                ch=input("yes|no >>").lower()
                if ch=='y' or ch=='yes':
                    print("[+] Malware is running...")
                    time.sleep(2)
                    print("[!] Eating up memory and system's disk space")
                    try:
                        for i in range(50):
                            s="\nhi there this is self replicating virus be careful it can fill up space quickly\nit's main purpose is to fill up the RAM"*100000000
                            with open(f"demo{i}.txt",'w') as f:
                                f.write(s)
                        print("[*] Malware executed successfully...")
                        print("[*] If you are seeing this, CONGRATS!! YOUR SYSTEM IS POWERFULL")
                        time.sleep(2)
                    except Exception as e:
                        print("[-]Failed due to the exception : ",e) 
                        time.sleep(2)
                elif ch=='n' or ch=='no':
                    pass
                else:
                    print("[-] Incorrect option..")         
                

            if inp=='audio_recorder':
                try:
                    print("Duration for recording...")
                    seconds=int(input("pegasus>>"))
                    chunk=1024
                    sample_format=pyaudio.paInt16
                    chn=1
                    frame_rate=44400
                    filename=input("Enter a file name for storage>>")
                    py=pyaudio.PyAudio()
                    stream=py.open(format=sample_format,channels=chn,rate=frame_rate,input=True,
                                   frames_per_buffer=chunk)
                    try:
                        print('[*]Recording.....')
                        frames=[]
                        for i in range(0,int(frame_rate/chunk*seconds)):
                            data=stream.read(chunk)
                            frames.append(data)
                        stream.stop_stream()
                        stream.close()
                        py.terminate()
                        print("[+]Recording completed...")
                        time.sleep(2)
                        print("[+]saving....")
                        with wave.open(filename,'wb') as file:
                            file.setnchannels(chn)
                            file.setsampwidth(py.get_sample_size(sample_format))
                            file.setframerate(frame_rate)
                            file.writeframes(b''.join(frames))
                    except KeyboardInterrupt:
                        print("[!]saving the files....")
                        with wave.open(filename,'wb') as file:
                            file.setnchannels(chn)
                            file.setsampwidth(py.get_sample_size(sample_format))
                            file.setframerate(frame_rate)
                            file.writeframes(b''.join(frames))
                            file.close()
    
                except KeyboardInterrupt:
                    pass

            
            if 'wav_converter' in inp:
                print("""
                        1.convert a file
                        2.convert a list of files
                        """)
                ch=input("pegasus>>")
                if ch=='1':
                    print("[*]enter the filename")
                    file=input("pegasus>>")
                    fname=file.split('.mp3')
                    if path.exists(file)==True:
                        try:
                            print(f"[+]Converting {file} to {fname[0]}.wav")
                            os.system(f'cmd /c "ffmpeg -i {file} {fname[0]}.wav"')
                            print("[+]Converted.......")
                        except Exception as e:
                            print(f"[-]Failed due to {e}")
                            time.sleep(2)
                    else:
                        print("[-]Please check the name of your file")

                if ch=='2':
                    print("[*]Enter the names of mp3 files separated by comma")
                    file=input("pegasus>>")
                    fname=file.split(',')
                    if '*' in file:
                        inp=input("are you using wildcard??[y|n]>>").lower()
                        if inp=='y':
                            try:
                                os.system('dir /b *.mp3 > mp3_files.txt')
                                with open('mp3_files.txt','r') as file:
                                    fread=file.readlines()
                                    print(f"[*]Total no of files to be converted:{len(fread)}")
                                    for i in range(0,len(fread)):
                                        f_name=fread[i].split(',')
                                        f_name=fread[i].split('\n')
                                        f_name=fread[i].split('.mp3')
                                        try:
                                            print(f"[+]Converting {fread[i]} to {f_name[0]}.wav")
                                            os.system(f"ffmpeg -i {fread[i]} {f_name[0]}.wav")
                                            print(f"[+]Converter {fread[i]} ...")
                                            time.sleep(2)
                                        except Exception as e:
                                            print(f"[-]Failed due to {e}")
                                            time.sleep(2)
                            except KeyboardInterrupt:
                                print("[!]Warning :Keyboard Interrupt")
                            except Exception as e:
                                print(f"[-]Failed due to {e}")
                        if inp=='n':
                            print("[-]Please check the file name/path")

                    else:        
                        for i in range(0,len(fname)):
                            f_name=fname[i].split('.mp3')
                            try:
                                print(f"[+]Converting {fname[i]} to {f_name[0]}.wav")
                                os.system(f'cmd /c "ffmpeg -i {fname[i]} {f_name[0]}.wav"')
                                print(f"[+]Converted {fname[i]} ....")
                                time.sleep(2)
                            except Exception as e:
                                print(f"[-]Failed due to {e}")
                                time.sleep(2)
                            except KeyboardInterrupt:
                                print("[!]Warning :Keyboard Interrupt")
                                pass
                

            if inp=="rename_file":
                print("""
                        1.Rename a file
                        2.Rename multiple files at once
                        """)
                print("[+]Enter your choice")
                ch=input("pegasus>>")
                if ch=='1':
                    print("[*]Enter the name of file you want to rename(with extension)")
                    f=input("pegasus>>")
                    print("[*]Enter the new name for your file(with extension)")
                    name=input("pegasus>>")
                    try:
                        os.system(f"ren {f} {name}")
                        print(f"[+]Renamed {f} to {name}")
                    except Exception as e:
                        print("[-]Failed due to",e)

                if ch=='2':
                    print("[*]Enter the name of files to rename seperated by comma")
                    inp=input("pegasus>>")
                    ext=inp.split('.')
                    if '*' in inp:
                        print("[?]are you using wildcard|y|n|")
                        ch=input("pegasus>>").lower()
                        if ch=='y':
                            print("[*]Enter the new common name for your files")
                            name=input("pegasus>>")
                            print(f"""[!]all your files will now be renamed in the following pattern like {name}-0,{name}-1,.....""")
                            print("[+]Converting the below files")
                            os.system(f"dir /b '{inp}' > files.txt")
                            with open('files.txt','r') as file:
                                a=file.readlines()
                                for i in range(0,len(a)):
                                    print(a[i])
                            try:
                                with open('files.txt','r') as file:
                                    f=file.readlines()
                                    for i in range(0,len(f)):
                                        f_new=f[i].split(',')
                                        f_new=f[i].split('\n')
                                        f_new=f[i].split(f'.{ext[1]}')
                                        print(f"[+]converting {f[i].strip()}")
                                        os.system(f"ren {f[i].strip()} {name}-{i}.{ext[1]}")
                            except Exception as e:
                                print("[+]Failed due to",e) 
                            
            
            if inp=="3.2":
                print("[+] YOU CAN PERFORM EMAIL FORENSICS IF COMPROMISED...")
                print("[!] When asked for password enter app password")
                print("[*] You can get it from myaccount.google.com/appasswords")
                time.sleep(3)
                target_id = input("Target id >>")
                passwd = input("Password(app password) >>")
                host_server = input("Host Server(Ex:gmail) >>")
                
                print("[+] Logging in....")
                try:
                    mail=imaplib.IMAP4_SSL(f"imap.{host_server}.com")
                    resp_code,response=mail.login(target_id,passwd)
                except Exception as e:
                    print("[-]Failed due to ",e)
                
                print("Response Code : {}".format(resp_code))
                print("Response  : {}".format(response))
                time.sleep(3)
                
                print("#########################################")
                mail.select("INBOX")
                _,data=mail.search(None,'ALL')
                print(f"[+]Number of INBOX messages :{len(data[0].split())}")
                mail.login(target_id,passwd)
                
                _,data=mail.search(None,'ALL')
                print(f"Number of SENT messages : {len(data[0].split())}")

                
                print("=============INBOX===========")
                ch=input(f"Do you want to expand all {len(data[0].split())} >>")
                if(ch=='y' or ch=='yes'):
                    for cont in data[0].split():
                        print("x-x-x-x-x-x-x-x-x-x-x-x-x-x-x-x")
                        _,mail_data=mail.fetch(cont, '(RFC822)')
                        byte_data=mail_data[0][1]
                        msg=email.message_from_bytes(byte_data)
                        print(f"Subject : {msg['subject']}")
                        print(f"To : {msg['to']}")
                        print(f"From :",{msg["from"]})
                        print(f"Date :",{msg['date']})
                        for part in msg.walk():
                            if part.get_content_type()=="text/plain" or part.get_content_type=="text/html":
                                message=part.get_payload(decode=True)
                                print("Message :\n",message.decode())
                                break
                else:
                    pass
                

            if inp=="setup":
                print("[+]Initiating the setup...")
                time.sleep(2)
                print("[!]This may take some time....")
                time.sleep(2)
                driver=webdriver.Edge()
                try:
                    print("[+]Downloading audacity...")
                    driver.get("https://github.com/audacity/audacity/releases/download/Audacity-3.2.4/audacity-win-3.2.4-x64.exe")
                    time.sleep(10)
                    print("[+]Successfully downloaded audacity")
                    
                except Exception as e:
                    print("[-]Failued to download due to",e)

                try:
                    print("[+]Downloading bleachbit...")
                    driver.get("https://www.bleachbit.org/download/file/t?file=BleachBit-4.4.2-setup.exe")
                    time.sleep(10)
                    print("Successully downloaded bleachbit")
                    
                except Exception as e:
                    print("[-]Failed due to ",e)

                try:
                    print("[+]Downloading deepsound...")
                    driver.get("https://www.majorgeeks.com/mg/getmirror/deepsound,1.html")
                    time.sleep(10)
                    print("[+]Successfully downloaded deepsound")
                except Exception as e:
                    print("[-]Failed due to",e)

                try:
                    print("[+]Downloading Maltego...")
                    driver.get("https://maltego-downloads.s3.us-east-2.amazonaws.com/windows/MaltegoSetup.JRE64.v4.3.1.exe")
                    time.sleep(10)
                    print("[+]Successfully downloaded maltego")
                except Exception as e:
                    print("[-]Failed due to ",e)

                try:
                    print("[+]Downloading VisualStudioCode...")
                    driver.get("https://code.visualstudio.com/sha/download?build=stable&os=win32-x64-user")
                    time.sleep(10)
                except Exception as e:
                    print("[-]Failed due to ",e)
                
                try:
                    print("[+]Downloading wireshark....")
                    driver.get("https://1.as.dl.wireshark.org/win64/Wireshark-win64-4.0.3.exe")
                    time.sleep(10)
                except Exception as e:
                    print("[-]Failed due to ",e)
                
                try:
                    print("[+]Downloading putty...")
                    driver.get("https://the.earth.li/~sgtatham/putty/latest/w64/putty-64bit-0.78-installer.msi")
                    time.sleep(10)
                except Exception as e:
                    print("[-]Failed due to ",e)

                try:
                    print("[+]Downloading balenaEtcher...")
                    driver.get("https://en.softonic.com/download/balenaetcher/windows/post-download")
                    time.sleep(10)
                except Exception as e:
                    print("[-]Failed due to ",e)

                try:
                    print("[+]Downloading oracle virtualbox....")
                    driver.get("https://download.virtualbox.org/virtualbox/7.0.6/VirtualBox-7.0.6-155176-Win.exe")
                    time.sleep(10)
                    driver.get("https://download.virtualbox.org/virtualbox/7.0.6/Oracle_VM_VirtualBox_Extension_Pack-7.0.6a-155176.vbox-extpack")
                    time.sleep(8)
                except Exception as e:
                    print("[-]Failed due to ",e)

                try:
                    print("[+]Downloading Coagula Light.....")
                    driver.get("https://ec.ccm2.net/ccm.net/download/files/CoagulaLight1666-1.666.zip")
                    time.sleep(10)
                except Exception as e:
                    print("[-]Failed due to ",e)

                time.sleep(50)
                driver.close()
                print("[*]SETUP COMPLETED.......")
                time.sleep(4)

            if inp=="sys_info":
                print("="*40, "System Information", "="*40)
                uname = platform.uname()
                print(f"System: {uname.system}")
                print(f"Node Name: {uname.node}")
                print(f"Release: {uname.release}")
                print(f"Version: {uname.version}")
                print(f"Machine: {uname.machine}")
                print(f"Processor: {uname.processor}")

                print("="*40, "Boot Time", "="*40)
                boot_time_timestamp = psutil.boot_time()
                bt = datetime.fromtimestamp(boot_time_timestamp)
                print(f"Boot Time: {bt.year}/{bt.month}/{bt.day} {bt.hour}:{bt.minute}:{bt.second}")

                print("="*40, "CPU Info", "="*40)
                # number of cores
                print("Physical cores:", psutil.cpu_count(logical=False))
                print("Total cores:", psutil.cpu_count(logical=True))
                # CPU frequencies
                cpufreq = psutil.cpu_freq()
                print(f"Max Frequency: {cpufreq.max:.2f}Mhz")
                print(f"Min Frequency: {cpufreq.min:.2f}Mhz")
                print(f"Current Frequency: {cpufreq.current:.2f}Mhz")

                # CPU usage
                print("CPU Usage Per Core:")
                for i, percentage in enumerate(psutil.cpu_percent(percpu=True, interval=1)):
                    print(f"Core {i}: {percentage}%")
                    print(f"Total CPU Usage: {psutil.cpu_percent()}%")

                # Memory Information
                print("="*40, "Memory Information", "="*40)
                # get the memory details
                svmem = psutil.virtual_memory()
                print(f"Total: {get_size(svmem.total)}")
                print(f"Available: {get_size(svmem.available)}")
                print(f"Used: {get_size(svmem.used)}")
                print(f"Percentage: {svmem.percent}%")
                print("="*20, "SWAP", "="*20)

                # get the swap memory details (if exists)
                swap = psutil.swap_memory()
                print(f"Total: {get_size(swap.total)}")
                print(f"Free: {get_size(swap.free)}")
                print(f"Used: {get_size(swap.used)}")
                print(f"Percentage: {swap.percent}%")

                # Disk Information
                print("="*40, "Disk Information", "="*40)
                print("Partitions and Usage:")
                # get all disk partitions
                partitions = psutil.disk_partitions()
                for partition in partitions:
                    print(f"=== Device: {partition.device} ===")
                    print(f"  Mountpoint: {partition.mountpoint}")
                    print(f"  File system type: {partition.fstype}")
                    try:
                        partition_usage = psutil.disk_usage(partition.mountpoint)
                    except PermissionError:
                        # this can be catched due to the disk that
                        # isn't ready
                        continue
                    print(f"  Total Size: {get_size(partition_usage.total)}")
                    print(f"  Used: {get_size(partition_usage.used)}")
                    print(f"  Free: {get_size(partition_usage.free)}")
                    print(f"  Percentage: {partition_usage.percent}%")

                # get IO statistics since boot
                disk_io = psutil.disk_io_counters()
                print(f"Total read: {get_size(disk_io.read_bytes)}")
                print(f"Total write: {get_size(disk_io.write_bytes)}")

                # Network information
                print("="*40, "Network Information", "="*40)
                # get all network interfaces (virtual and physical)
                if_addrs = psutil.net_if_addrs()
                for interface_name, interface_addresses in if_addrs.items():
                    for address in interface_addresses:
                        print(f"=== Interface: {interface_name} ===")
                        if str(address.family) == 'AddressFamily.AF_INET':
                            print(f"  IP Address: {address.address}")
                            print(f"  Netmask: {address.netmask}")
                            print(f"  Broadcast IP: {address.broadcast}")
                        elif str(address.family) == 'AddressFamily.AF_PACKET':
                            print(f"  MAC Address: {address.address}")
                            print(f"  Netmask: {address.netmask}")
                            print(f"  Broadcast MAC: {address.broadcast}")
                # get IO statistics since boot
                net_io = psutil.net_io_counters()
                print(f"Total Bytes Sent: {get_size(net_io.bytes_sent)}")
                print(f"Total Bytes Received: {get_size(net_io.bytes_recv)}")   


            if inp=="clear":
                os.system('cls')
                pass
            
            if inp=="exit" or inp=="quit":
                ex()
                break
        
>>>>>>> c45df12 (release v1.0.0)
