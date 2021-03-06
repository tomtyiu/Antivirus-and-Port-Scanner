__author__ = 'yiut'
# -*- coding: Non-UTF-8 -*-
# -----------------------------------------------------------------------------
# Name:        Virus scanner, tested with Eicar with sha512 checksum scan
# Purpose:	   Simple Virus scanner, test with Eicar
#
# Author:	   Thomas Yiu
# Date:		   07/21/2015
# Version:     0.5
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
import pathfinder
import hex_file
import port_scanner
import multiprocess_antivirus
import logging
import logging.config

DetectFound="Eicar Test Sigature found!! Your PC has been infected by Malware or unwanted program"
# A 256 bit (32 byte) key
key = bytes("This_key_for_demo_purposes_only!", 'utf-8')

# For some modes of operation we need a random initialization vector
# of 16 bytes
iv = "InitializationVe"

valid_options = ['-p', '-f']

def logs():
    # create logger
    logging.basicConfig(filename='main_antivirus.log',level=logging.DEBUG)
    logger = logging.getLogger('simple_example')
    logging.config.fileConfig('logging.conf')
    logger.setLevel(logging.DEBUG)

    # create console handler and set level to debug
    ch = logging.StreamHandler()
    ch.setLevel(logging.DEBUG)

    # create formatter
    formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')

    # add formatter to ch
    ch.setFormatter(formatter)

    # add ch to logger
    logger.addHandler(ch)

    # 'application' code
    logger.debug('debug message')
    logger.info('info message')
    logger.warn('warn message')
    logger.error('error message')
    logger.critical('critical message')

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
    global filename3 # decrypt filename
    global multi
    global check

    lineout = "-----------------------------------------------------------------------------\n" + \
              "HP Antivirus program " + "\n"\
              "EICAR detection test project" + "\n"\
              "-----------------------------------------------------------------------------"
    print(lineout)
    parser = argparse.ArgumentParser(description=lineout, formatter_class=argparse.RawTextHelpFormatter)
    group = parser.add_mutually_exclusive_group()
    parser.add_argument('infiles', nargs='*', type=str, help='Input one or more data segment files\n')
    parser.add_argument('-f', '--fvirussig', nargs='?', metavar="FILE", help="Virus signature file", required=False)
    parser.add_argument('-vt', '--virustestfile', nargs='?', metavar="FILE", help="Virus signature file", required=False)
    parser.add_argument('-dir', '--directory', nargs='?', metavar="FILE", help="path of files to search", required=False)
    parser.add_argument('-e', '--encrypt', nargs='?', metavar="FILE", help="encrypt virus file to test", required=False)
    parser.add_argument('-d', '--decrypt', nargs='?', metavar="FILE", help="Decrypt virus file to test", required=False)
    parser.add_argument('-p', '--port', dest="port", metavar="PORT", help="Port scannner for server", required=False)
    parser.add_argument('-c', '--check', dest="check", metavar="CHECK", help="Port check for server", required=False)
    parser.add_argument('-s', '--sniff', dest='sniff', metavar='sniff', help='Port Sniffer mode: (1== realtime) (0==single entry)', required=False)
    parser.add_argument('-m', '--multi', nargs='?', metavar="FILE", help="Multiprocessing mode", required=False)
    parser.add_argument('-V', '--Version', action='version', version='%(prog)s v0.5')
    group.add_argument('-v', '--verbose', action='count', help="increase output verbose level")
    assert isinstance(group.add_argument, object)
    group.add_argument('-q', '--quiet', action='store_true', help="Quiet all output level")
    g_args = parser.parse_args()

    if argc == 1:
        parser.print_help()
        exit()

    if g_args.fvirussig:
        filename2 = g_args.fvirussig
    else:
        pass

    if g_args.virustestfile:
        filename = g_args.virustestfile
        if os.path.isfile(filename):
            virus_signature(filename2, filename)
        else:
            print("File not found")
    else:
        pass

    if g_args.directory:
        directory = g_args.directory
        if os.path.isdir(directory):
            q=directory_scanner(directory, filename2)
            print("Files Quarantined",q)
        else:
            print("Directory not found")
    else:
        pass

    if g_args.encrypt:
        #encryptf: decrypt file name
        #encryptf=g_args.encrypt
        encdecfunc.enc_openssl(filename, encryptf)
    if g_args.decrypt:
        #decryptf: decrypt file name
        #filename3=g_args.decrypt
        decryptf=g_args.decrypt
        encdecfunc.dec_openssl(decryptf, 'vir_sig.txt')
        print("Decrypt file: vir_sig.txt")

    if g_args.port:
        port=g_args.port
        #assert isinstance(port, object)
        port_scanner.porttest(0,int(port))

    if g_args.sniff:
        sniff=g_args.sniff
        port_scanner.port_sniff(int(sniff))

    if g_args.multi:
        multi=g_args.multi
        multiprocess_antivirus.procedure(multi, directory, filename2)

    if g_args.verbose:
        print("vervose turn on")

    if g_args.check:
        port_scanner.port_check()

    #encdecfunc.dec_openssl()

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
    quarantine=[]
    filedata=[]
    #@directory2=list_directory(directory)
    #print("Directory path:", directory2)
    name='*.txt'
    filesindirectory = list_directory(directory)

    #finddir=pathfinder.pathfind(directory)

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
                if filesindirectory[i]=='antivirus.py':
                    pass
                if filesindirectory[i]=='virus_signature.txt':
                    pass
                for line1 in fhand:
                    data=hex_file.data_hex(line1)
                    #print(data)
                    data2=data.decode('utf-8')
                    #print(data2)
                    v=signature_functions.find_dict(str(data2),dictionary,signature_functions.le(dictionary))
                    if v:
                        print("\n Eicar Test Sigature found!! Your PC has been infected by Malware or unwanted program:",v, "",filesindirectory[i])
                    if v:
                        removefile=input("Do you want to remove infected file: (Yes/No)")
                        if removefile=="Yes":
                            os.remove(filesindirectory[i])
                        else:
                            print("File will be quarantined")
                            quarantine.append(filesindirectory[i])
                            continue
        return quarantine
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
    dictionary=signature_functions.dictfile(filename2, 'Virus Signature')
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
                data=hex_file.data_hex(line2)
                #print(data)
                data2=data.decode('utf-8')
                print(data2)
                v=signature_functions.find_dict(str(data2),dictionary,signature_functions.le(dictionary))
                print('\n',DetectFound, v)
    except FileNotFoundError:
        print('Filename: ' + filename + ' is not valid')
        exit()

def find_file(path,filename):
    files=list_files(path)
    for f in range(0,len(files)):
        if files[f] in filesname:
            print("File found:",files[f])

#path of list files;  files not to check
def list_files(path,name):
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

def list_directory(path):
    directory=[]
    for name in os.listdir(path):
        if os.path.isfile(os.path.join(path, name)):
            directory.append(name)
    return directory

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


if __name__ == '__main__':
    args=parseCmdLineArgs(sys.argv,len(sys.argv))


