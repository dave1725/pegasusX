#imported modules
import threading
import time
from os import path
import os
import base64
import sys, os, optparse
from PIL import Image
from PIL.ExifTags import TAGS
from common_tools import *
import datetime
from datetime import datetime
import sys
from winreg import *
from common_methods import *
import subprocess
from zipfile import BadZipFile, ZipFile
from olefile import OleFileIO
import os, sys, optparse
import lxml.etree as tree
from datetime import datetime as dt
from common_methods import *
from PyPDF2 import PdfFileReader
from urllib.parse import urljoin
from pprint import pprint
from bs4 import BeautifulSoup as bs
import requests
import socket
##END

#libraries

#login encryption algorithm
def otp(plain,key):
    result=""
    try:
        for i in range(len(plain)): 
            ch=plain[i]
            result+=chr((ord(ch)-97 +ord(key[i])-97)%26 +97)

        return result
    except:
        pass

#morse code cipher algorithm
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

#rot-13 algorithm
def rot(string):
    rot={"a":"n","b":"o","c":"p","d":"q","e":"r","f":"s","g":"t","h":"u","i":"v","j":"w","k":"x","l":"y","m":"z",'n':'a','o':'b','p':'c','q':'d','r':'e','s': 'f', 't': 'g', 'u': 'h', 'v': 'i', 'w': 'j', 'x': 'k', 'y': 'l', 'z': 'm'}
    a=""
    r=a.join([rot.get(i,i) for i in string])
    return r

#caesar cipher encryption algorithm
def caesar(txt,s):
    result=""
    for i in range(len(txt)):
        char=txt[i]
        if char==" ":
            result+=char
        elif char.isupper():
            result+=chr((ord(char)+s-65)%26+65)
        else:
            result+=chr((ord(char)+s-97)%26+97)
    return result

#caesar cipher decryption algorithm
def chacker(msg):
    for i in range(0,26):
        print("key{i}:",caesar(msg,i))

#file encryption algorithm
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
        
#file decryption algorithm
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

#Exif-data module - imag forensics
def getExif(image_file):
    '''Get image file EXIF metadata'''
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
    else:
        sys.exit("No EXIF data found!")

    for key in exif_data:
        data += "{}    :   {}\n".format(key, exif_data[key])

    print("Found the following exif data:\n")
    time.sleep(3)
    print("+------------------------------------------------------------------------+")
    print("|                          Image Metadata                                |")
    print("+------------------------------------------------------------------------+")
    print(data)
    print("+------------------------------------------------------------------------+")

#valid addrs
def val2addr(val):
    if val:
        addr = ""
        for char in val:
            try:
                addr += ("%02x " % ord(char))
            except:
                addr += ("%02x " % ord(chr(char)))
        addr = addr.strip(" ").replace(" ", ":")[:17]
        return True, addr
    else:
        addr = "No data found for this network"
        return False, addr

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
        print("File not supported: %s" % e1)
    except FileNotFoundError:
        print("Specified file could not be found")

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
    pdf_doc = PdfFileReader(open(file_path, "rb"))

    if pdf_doc.isEncrypted:
        try:
            if pdf_doc.decrypt("") != 1:
                sys.exit("target pdf document is encrypted... exiting...")
        except:
            sys.exit("target pdf document is encrypted with an unsupported algorithm... exiting...")

    doc_info = pdf_doc.getDocumentInfo()
    stats = os.stat(file_path)
    now = dt.now()
    file_name = getFileName(file_path)
    metadata = "Time: %d/%d/%d %d : %d : %d. Found the following metadata for file %s:\n\n" % (now.year, now.month,
                                                                                               now.day, now.hour, now.minute,
                                                                                               now.second, file_name[:-4])
    try:
        for md in doc_info:
            metadata += str(md[1:]) + " : " + pretifyPyPDF2Time(str(md[1:]) ,str(doc_info[md])) + "\n"
    except TypeError:
        sys.exit("Couldn't read document info! Make sure target is a valid pdf document...")

    metadata += "Last metadata mod Date: %s\nLast Mod Date: %s\nLast Access Date: %s\nOwner User ID: %s" %(dt.fromtimestamp(stats.st_ctime),
                                                                                                           dt.fromtimestamp(stats.st_mtime),
                                                                                                           dt.fromtimestamp(stats.st_atime),
                                                                                                           stats.st_uid)
    try:
        print(metadata)
    except UnicodeEncodeError:
        print("Console encoding can't decode the result. Enter chcp 65001 in the console and rerun the script.")

#sql-injection
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
    """A simple boolean function that determines whether a page 
    is SQL Injection vulnerable from its `response`"""
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
            # won't break because we want to print available vulnerable forms
    if(is_vulnerable):
        print("Vulerable to XSS vulnerability..")
    else:
        print("Not Vulnerble to XSS vulnerability..")
#END

#Files init
if path.exists('database.txt')==True:
    pass
else:
    with open("database.txt",'w') as file:
        file.write('kcck')
        file.close()

#init
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
        os.system('cls')
        #banner
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
                Note!
                    -->Type exit or quit to exit and type clear to clear the previous commands

                    -->Also, Encryption Message.txt will be overwritten so save it to another file before you use other
                        encryption modules
            """)

        while True:
            print("""
                  [1]Cryptographic Tools
                  [2]Forensic Analysis Tools
                  [3]Web Pentesting Tools
            """)
            ch=input(">>")
            if(ch=='1'):
                print("""
                    +---------------------------+  
                    |    CRYPTOGRAPHIC TOOLS    |
                    +---------------------------+
                    |  [1]Text Encryption       |
                    |  [2]Text Decryption       |
                    |  [3]File Encryption       |
                    |  [4]File Decryption       |
                    +---------------------------+
                """)
                inp=input(">>")
                if(inp=='1'):
                    print("""\n
                        1.Encrypt a text(1-50 words)
                        2.Encrypt a text file(>50 words)
                        """)
                    inp=input(">>")
                    if(inp=='1'):
                        txt=input("Enter text >>")
                        print("""Select Encryption method
                                    [1]Morse Code Encryption
                                    [2]ROT-13 Encryption
                                    [3]Caesar Cipher Encryption
                                    [4]Base64 Encoding
                                    """)
                        op=input(">>")
                        if(op=='1'):
                            en=morse(txt.upper(),'1')
                            with open('Encrypted Message.txt','w') as f:
                                f.write(en)
                            print("[+]Encrypted successfully...")
                            print("[+]Check your encrypted message.txt file for the encrypted data..")
                            time.sleep(3)
                        elif(op=='2'):
                            out=rot(txt)
                            with open("Encrypted Message.txt",'w') as e: 
                                e.write(out)
                            print("[*]Encrypted successfully...")
                        elif(op=='3'):
                            print("[+]specify the shift value")
                            s=int(input(">>"))
                            o=caesar(txt,s)
                            with open('Encrypted Message.txt','w') as f:
                                f.write(o)
                            print("[+]Encrypted Successfully...")
                            time.sleep(2)
                        elif(op=='4'):
                            with open('Encrypted Message.txt','w') as f:
                                f.write(txt.encode('ascii'))
                            print("[+]Encrypted Successfully...")
                    elif(inp=='2'):
                        print("Enter filename :")
                        file=input(">>")
                        print("""Select Encryption method
                                    [1]Morse Code Encryption
                                    [2]ROT-13 Encryption
                                    [3]Caesar Cipher Encryption
                                    [4]Base64 Encoding
                                    """)
                        op=input(">>")
                        if(op=='1'):
                            try:
                                f=open(file,'r')
                                a=f.read()
                                en=morse(a.upper(),'1')
                                f.close()
                                with open(file,'w') as f:
                                    f.write(en)
                                    f.close()
                                print("[+]Encrypted Successfully...")
                            except Exception as e:
                                print("[-]Failed due to ",e)
                                pass
                        elif(op=='2'):
                            f=open(file, 'r')
                            st=f.read()
                            encrypt=str(rot(st))
                            with open(file,'w') as f:
                                f.write(encrypt)
                            print("[*]Encrypted successfully...")
                        elif(op=='3'):
                            print("[+]specify the shift value")
                            s=int(input(">>"))
                            try:
                                fi=open(file,'r')
                                cont=fi.read()
                                o=caesar(cont,s)
                                with open(file,'w') as file:
                                    file.write(o)
                                print(f"[+]Encrypted {file} successfully...")
                            except:
                                print("[-]OOPS..ran into an error")
                        elif(op=='4'):
                            f=open(file,'r')
                            st=f.read()
                            cipher=st.decode('ascii')
                            with open(file,'w') as f:
                                f.write(cipher)
                            print("[*]Encrypted Successfully...")

                elif(inp=='2'):
                    print("""\n
                        1.Decrypt a text(1-50 words)
                        2.Decrypt a text file(>50 words)
                        """)
                    inp=input(">>")
                    if(inp=='1'):
                        txt=input("Enter text >>")
                        print("""Select Decryption method
                                    [1]Morse Code Decryption
                                    [2]ROT-13 Decryption
                                    [3]Caesar Cipher Decryption
                                    [4]Base64 Decoding
                                    """)
                        op=input(">>")
                        if(op=='1'):
                            en=morse(txt.upper(),'2')
                            with open('Decrypted Message.txt','w') as f:
                                f.write(en)
                            print("[+]Decrypted successfully...")
                            print("[+]Check your Decrypted message.txt file for the decrypted data..")
                            time.sleep(3)
                        elif(op=='2'):
                            out=rot(txt)
                            with open("Decrypted Message.txt",'w') as e: 
                                e.write(out)
                            print("[*]Decrypted successfully...")

                        elif(op=='3'):
                            print("""
                            1.crack the cipher(if you dont remember shift value)
                            2.decrypt the cipher with shift value
                            """)
                            try:
                                for i in range(27):
                                    o=caesar(txt,26-i)
                                    print(f"key{i} : ",o)
                                    time.sleep(2)
                                print("[+] Completed..")
                            except Exception as e:
                                print("[-]faied due to the exception : ",e)
                        
                        elif(op=='4'):
                            with open('Decrypted Message.txt','w') as f:
                                f.write(txt.encode('ascii'))
                            print("[+]Decrypted Successfully...")
                    elif(inp=='2'):
                        print("Enter filename :")
                        file=input(">>")
                        print("""Select Decryption method
                                    [1]Morse Code Decryption
                                    [2]ROT-13 Decryption
                                    [3]Caesar Cipher Decryption
                                    [4]Base64 Decoding
                                    """)
                        op=input(">>")
                        if(op=='1'):
                            try:
                                f=open(file,'r')
                                a=f.read()
                                en=morse(a.upper(),'2')
                                f.close()
                                with open(file,'w') as f:
                                    f.write(en)
                                    f.close()
                                print("[+]Decrypted Successfully...")
                            except Exception as e:
                                print("[-]Failed due to ",e)
                                pass
                        elif(op=='2'):
                            f=open(file, 'r')
                            st=f.read()
                            encrypt=str(rot(st))
                            with open(file,'w') as f:
                                f.write(encrypt)
                            print("[*]Decrypted successfully...")
                        elif(op=='3'):
                            print("""
                            1.crack the cipher(if you dont remember shift value)
                            2.decrypt the cipher with shift value
                            """)
                            with open("Decrypted Message.txt",'w') as f:
                                f.write('')
                                f.close()
                            f=open(file,'r')
                            c=f.read()
                            try:
                                for i in range(27):
                                    fi=open('Decrypted Message.txt','a')
                                    o=caesar(c,26-i)
                                    fi.write(f"key{i} :",o)
                                    time.sleep(2)
                                print("[+] Completed..")
                            except Exception as e:
                                print("[-]faied due to the exception : ",e)

                        elif(op=='4'):
                            f=open(file,'r')
                            st=f.read()
                            cipher=st.decode('ascii')
                            with open(file,'w') as f:
                                f.write(cipher)
                            print("[*]Decrypted Successfully...")
                
                elif(inp=='3'):
                    print("[+]Please create a private key(digits in range 1-256)")
                    print("[!]Remember your key, without the key your data will be encrypted forever")
                    key=int(input("pegasus>>"))
                    print("[+]Now Enter the file location")
                    filename=input("pegasus>>")

                    if '*' in filename:
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
                                
                        else:
                            print("[-]Invalid Choice....")
                        
                    else:
                        if path.exists(filename)==True:
                            print(f"Encrypting {filename}...it may take time if the file is too big!!")
                            encrypt(filename, key)
                            print("[*]File Encrypted successfully")
                            time.sleep(2)
                        else:
                            print("[-]File cannot be decrypted....Please check the name")
                            time.sleep(2)
                
                elif(inp=='4'):
                    print("         ^| File Decryptor |^   ")
                    print("[+]Enter the private key(digits in range 0-256)")
                    key=int(input("pegasus>>"))
                    print("[+]Enter the file location")
                    filename=input("pegasus>>")
                    if '*' in filename:
                        ch=input("Are u using wildcard?[y|n]>>").lower()
                        if ch=='n':
                            if path.exists(filename)==True:
                                decrypt(filename,key)
                                print("[*]File Decrypted successfully")
                                time.sleep(2)
                            else:
                                print("[-]File cannot be decrypted....Please check the name")
                                time.sleep(2)
                        if ch=='y':
                            print("[+]Decrypting....")
                            os.system(f'dir {filename} /b > file_data.txt')
                            c=0
                            time.sleep(2)
                            with open('file_data.txt','r') as file:
                                a=file.readlines()
                                for i in range(0,len(a)):
                                    f_data=a[i]
                                    files=f_data.strip('\n')
                                    decrypt(files,key)
                                print("[+]Decrypted all the files...")
                            pass
                        else:
                            print("[-]Invalid Choice....")
                    else:
                        if path.exists(filename)==True:
                            decrypt(filename,key)
                            print("[*]File Decrypted successfully")
                            time.sleep(2)
                        else:
                            print("[-]File cannot be decrypted....Please check the name")
                            time.sleep(2)
            elif(ch=='2'):
                print("""
                         +-----------------------+
                         |       FORENSICS       |
                         +-----------------------+
                         | [1]IMAGE-FORENSICS    |
                         | [2]WLAN-FORENSICS     |
                         | [3]FILE-FORENSICS     |
                         +-----------------------+
                      """)
                print("Before starting forensics analysis..be sure to have administrator privileges.. ")
                inp=input(">>")
                if(inp=='1'):
                    path=input("Enter path of image >>")
                    getExif(path)
                    
                if(inp=='2'): 
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

                if(inp=='3'):
                    path=input("Enter path of file >>")
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
            elif(ch=='exit' or ch=='quit'):
                exit(0)

            elif(ch=="3"):
                print("+----------------------------+")
                print("|    WEB - APP Analysis      |")
                print("+----------------------------+")
                site=input("site url >>")
                ip=socket.gethostbyname(site)
                print(f"IP : {ip}")
                #ip = socket.gethostbyname(target)
                def portscan(port):

                    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    s.settimeout(0.5)#
                    try:
                        con = s.connect((site,port))

                        print('Port :',port,"is open.")

                        con.close()
                    except: 
                        pass
                r = 1 
                for x in range(1,100):
                    t = threading.Thread(target=portscan,kwargs={'port':r}) 
                    r += 1     
                    t.start()
        
                print("[+]Checking for SQL injections...")
                scan_sql_injection(f"http://{site}/")
                print("[+]Checking for XSS vulnerability...")
                print(scan_xss(f"http://{site}/"))
                print("[+]Scanning subdomains...")
                ch=input("want to use a heavy subdomain wordlist(take time)(y/n)>>")
                if(ch=='y' or ch=='Y'):
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
                    except KeyboardInterrupt:
                        with open("discovered_subdomains.txt", "w") as f:
                            for subdomain in discovered_subdomains:
                                print(subdomain, file=f)
                else:
                    try:
                        content = file.read()
                        subdomains = content.splitlines()
                        discovered_subdomains = []
                        file = open("subdomains-10k.txt")
                        for subdomain in subdomains:
                            url = f"http://{subdomain}.{site}"
                            try:
                                requests.get(url)
                            except requests.ConnectionError:
                                pass
                            else:
                                print("[+] Discovered subdomain:", url)
                                discovered_subdomains.append(url)
                    except KeyboardInterrupt:
                        with open("discovered_subdomains.txt", "w") as f:
                            for subdomain in discovered_subdomains:
                                print(subdomain, file=f)






            






                

                        



                        

                                                





