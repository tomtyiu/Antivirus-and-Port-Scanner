__author__ = 'yiut'
# -*- coding: Non-UTF-8 -*-
# -----------------------------------------------------------------------------
# Name:        Virus scanner, tested with Eicar with sha512 checksum scan
# Purpose:	   Simpmle Virus scanner, test with Eicar
#
# Author:	   Thomas Yiu
# Date:		   07/13/2015
# Version:     0.1
# -----------------------------------------------------------------------------

# !/usr/bin/python
from string import *

import sys
import os
import re
from zipfile import *
import string
import binascii
import fcsum
import pyaes
import pyaes.aes
import argparse
import logging
import collections
import encdecfunc
import signature_functions
import binhex
import binascii

# A 256 bit (32 byte) key
key = bytes("This_key_for_demo_purposes_only!", 'utf-8')

# For some modes of operation we need a random initialization vector
# of 16 bytes
iv = "InitializationVe"

valid_options = ['-p', '-f']
def data_hex(line):
    return binascii.hexlify(line.encode('utf-8'))

def typenamefunction(signature):
    virussig=[]
    with open(filename2) as fhand:
            for line1 in fhand:
                virussig.append(line1)
    vir=virussig_parse(virussig, len(virussig))
    #print(vir)
    #print(SignatureRecord)

#using fru example for parse command line arguments
def parseCmdLineArgs(argv, argc):
    szArg = 0
    prog = sys.argv[0]
    #argc = len(sys.argv)
    global filename2
    global filename
    global directory
    global encryptf
    global readfile
    global decryptf

    lineout = "-----------------------------------------------------------------------------\n" + \
              "Antivirus program " + "\n"\
              "-----------------------------------------------------------------------------"
    parser = argparse.ArgumentParser(description=lineout, formatter_class=argparse.RawTextHelpFormatter)
    parser.add_argument('infiles', nargs='*', type=str, help='Input one or more data segment files\n')
    parser.add_argument('-f', '--fvirussig', nargs='?', metavar="FILE", help="Virus signature file", required=False)
    parser.add_argument('-vt', '--virustestfile', nargs='?', metavar="FILE", help="Virus signature file", required=False)
    parser.add_argument('-p', '--path', nargs='?', metavar="FILE", help="path of files to search", required=False)
    parser.add_argument('-e', '--encrypt', nargs='?', metavar="FILE", help="encrypt virus file to test", required=False)
    parser.add_argument('-d', '--decrypt', nargs='?', metavar="FILE", help="dec virus file to test", required=False)
    g_args = parser.parse_args()

    # Invoke logger
    # log = logClass(g_isDebug, g_isVerbose)
    # log.debug("g_isDebug=%d", g_isDebug)
    # log.debug("g_isVerbose=%d", g_isVerbose)

    if argc == 1:
        parser.print_help()
        exit()
    if g_args.fvirussig:
        filename2 = g_args.fvirussig
        #   log.debug("filesname2=%s", filename2)
    if g_args.virustestfile:
        filename = g_args.virustestfile
        #  log.debug("filesname=%s", filename)
    if g_args.path:
        directory = g_args.path
        directory_scanner(directory, filename2)
    if g_args.encrypt:
        #encryptf: decrypt file name
        encryptf=g_args.encrypt
        #   encdecfunc.enc_openssl(filename, encryptf)
    if g_args.decrypt:
        #decryptf: decrypt file name
        decryptf=g_args.decrypt
        #encdecfunc.dec_openssl(filename, decryptf)

    virus_signature(filename2, filename)


def writefile_replace(filename, writefilename):
    try:
        filedata = openfile(filename)
        # print("String check:",isinstance(filedata, str))
        # print("String of data", filedata)
        filedata = filedata.replace(" ", "")
        file_out = open(writefilename, 'w')
        print("File saved to", writefilename)
        file_out.write(filedata)
        file_out.close()
    except FileNotFoundError:
        print('Filename: ' + filename + ' is not valid')
        exit()


def writefile(filename, writefilename):
    try:
        filedata = openfile(filename)
        # print("String check:",isinstance(filedata, str))
        # print("String of data", filedata)
        filedata = filedata.lstrip("b'")
        file_out = open(writefilename, 'w')
        print("File saved to", filename)
        file_out.write(filedata)
        file_out.close()
    except FileNotFoundError:
        print('Filename: ' + filename + ' is not valid')
        exit()


def openfile(filename):
    try:
        with open(filename) as fhandle:
            for line in fhandle:
                return line
    except FileNotFoundError:
        print('Filename: ' + filename + ' is not valid')
        exit()


def zipfiles(filename):
    if is_zipfile(filename):
        print("valid zip file")
        with ZipFile(filename) as myzip:
            with myzip.open('eicar.com') as myfile:
                for line in myfile:
                    # print(line)
                    strings = line.decode("utf-8")
                    # print(strings)
                    t = scanner(strings)
        print("scan complete")
    else:
        print("Not zip file, scanning", filename)
        try:
            with open(filename) as fhand:
                for line in fhand:
                    t = scanner(line)
            sha512c = fcsum.sha512checksum(filename)
            # print(sha512c) #sha512 check virus
            if sha512c == eicar_check:
                print("Eicar sha512 validation, virus detected")
            else:
                print("No virus")
            print("Scanning complete")
        except FileNotFoundError:
            print('Filename: ' + filename + ' is not valid')
            exit()

def directory_scanner(directory, filename2):
    #signature test="X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
    lineout = "-----------------------------------------------------------------------------\n" + \
              "Directory virus scan testing" + "\n"\
              "-----------------------------------------------------------------------------"
    print(lineout)
    count = 0
    virussig = []
    filedata=[]
    filesindirectory = list_files(directory)
    print("Scanning files in directory:", filesindirectory)
    lengthdirectory = len(filesindirectory)
    print("# files in directory", lengthdirectory)
    # print(lengthdirectory) - length test
    # print(filesindirectory) - directory test
    dictionary=signature_functions.dictfile(filename2, 'Virus Signature')
    try:
        with open(filename2) as fhand:
            for line1 in fhand:
                virussig.append(line1)
    except FileNotFoundError:
        print("File not found")

    try:
        for i in range(0,lengthdirectory):
            with open(filesindirectory[i],'rt', encoding='utf-8') as fhand:
                for line1 in fhand:
                    data=data_hex(line1)
                    #print(data)
                    data2=data.decode('utf-8')
                    print(data2)
                    v=signature_functions.find_dict(str(data2),dictionary,signature_functions.le(dictionary))
                    print("Found:",v)
    except FileNotFoundError:
        print(filesindirectory, "error")


def virussig_parse(virussig, length):
    v_sig = []
    for k in range(0, length):
        v_sig.append(virussig[k].partition("="))
        v_sig.append(virussig[k].rstrip('\n'))
        v_sig.append(virussig[k].rstrip(''))
    return v_sig


def virus_signature(filename2, filename):
    # filename2: virus signature;  filename= infected files
    testkey = "Eicar-Test-Signature"
    testsig = "=58354f2150254041505b345c505a58353428505e2937434329377d2445494341522d5354414e4441"
    lineout = "-----------------------------------------------------------------------------\n" + \
              "Virus signature testing" + "\n"\
              "-----------------------------------------------------------------------------"
    print(lineout)
    filedata = []
    virussig = []
    v_sig = []
    try:

        with open(filename2) as fhand:
            for line1 in fhand:
                virussig.append(line1)
        with open(filename) as fhand2:
            for line2 in fhand2:
                data = line2
                # print(data)
                for i in range(0, len(virussig)):
                    if data in virussig[i]:
                        print("Virus Detected with line virus scan test")
                filedata = data.partition("=")
        # filedata.append(data)
        print("test: filedata", filedata)
        # print(virussig)
        length = len(virussig)
        print("# of virus signatures, ", length)
        sig = virussig_parse(virussig, length)
        for x in range(0, len(sig)):
            if testsig in sig[x]:
                print("found virus in virus signature function: ", sig[x])
    except FileNotFoundError:
        print('Filename: ' + filename + ' is not valid')
        exit()

def find_file(path,filename):
    files=list_files(path)
    for f in range(0,len(files)):
        if files[f] in filesname:
            print("File found:",files[f])

def list_files(path):
    # returns a list of names (with extension, without full path) of all files
    # in folder path
    """

    :rtype : object
    """
    files = []
    for name in os.listdir(path):
        if os.path.isfile(os.path.join(path, name)):
            files.append(name)
    return files


def scanner(signature):
    signature.replace(" ", "")
    print("Current signature:", signature)
    # hexi = signature,encode('hex')
    # print(hexi)
    # print(isinstance(signature, str)) test if signature is true
    if 'EICAR-STANDARD-ANTIVIRUS-TEST-FILE' in signature:
        print("Virus detected", "\n")
        print("Eicar test file", "\n")
        print("Detection type: Test", "\n")
    else:
        print("Error")
    string = signature
    # print("Signature leng h",signature.count())
    # match=string.find(signature,"EICAR")
    # if match:
    #    return signature
    # else:
    #    return


def encryptfile(filename):
    """

    :rtype : object
    """
    key = bytes("This_key_for_demo_purposes_only!", 'utf-8')

    mode = pyaes.AESModeOfOperationCBC(key, iv=iv)

    file_in = open('eicar.com', 'r+')
    print("Encrypting file: ", filename)
    file_out = open('enceicar.bin', 'w')
    print("Encrypted file saved to enceicar.bin")
    pyaes.encrypt_stream(mode, file_in, file_out)
    file_in.close()
    file_out.close()


def decryptfile():
    key = bytes("This_key_for_demo_purposes_only!", 'utf-8')

    # mode= pyaes.AESModeOfOperationCBC(key, iv=iv)
    mode = pyaes.AESModeOfOperationCBC(key, iv=iv)

    file_in = open('encryptedeicar.bin', 'r+')
    file_out = open('decrypteicar.txt', 'w')

    pyaes.decrypt_stream(mode, file_in, file_out)
    file_in.close()
    file_out.close()


def aesfunc(filename):
    print("\nCurrent encryption for AES 256-CBC")
    encryptfile(filename)
    # filename is virus file
    writefile('enceicar.bin', 'enceicar2.bin')
    writefile_replace('encrypted_eicar_hex.txt', 'encrypted_eicar_hex_signature.txt')
    # writefile('enceicar2.bin', )
    # file_hex('eicar.com','test.txt')
    # decryptfile()
    # plaintext = bytes("TextMustBe16Byte", 'utf-8') test only
    # ciphertext = aes.encrypt(plaintext)


    # '\xd6:\x18\xe6\xb1\xb3\xc3\xdc\x87\xdf\xa7|\x08{k\xb6'
    # print(repr(ciphertext))


    # The cipher-block chaining mode of operation maintains state, so
    # decryption requires a new instance be created
    # aes = pyaes.AESModeOfOperationCBC(key, iv = iv)
    # decrypted = aes.decrypt(ciphertext)

    # True
    # print(decrypted == plaintext)

#def main(**kwargs):


if __name__ == '__main__':
    args=parseCmdLineArgs(sys.argv,len(sys.argv))


