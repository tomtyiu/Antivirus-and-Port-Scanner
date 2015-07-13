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

#!/usr/bin/python
from string import *

import sys
import os
import re
from zipfile import *
import string
import binascii
import fcsum

valid_options = ['-p', '-f']

def zipfiles(filename):
    if is_zipfile(filename):
        print("valid zip file")
        with ZipFile(filename) as myzip:
            with myzip.open('eicar.com') as myfile:
                for line in myfile:
                   # print(line)
                    strings=line.decode("utf-8")
                    #print(strings)
                    t=scanner(strings)
        print("scan complete")
    else:
        print("Not zip file, scanning",filename)
        try:
            with open(filename) as fhand:
                for line in fhand:
                    t=scanner(line)
            sha512c=fcsum.sha512checksum(filename)
            #print(sha512c) #sha512 check virus
            if sha512c == eicar_check:
                print("Eicar sha512 validation, virus detected")
            else:
                print("No virus")
            print("Scanning complete")
        except FileNotFoundError:
            print('Filename: ' + filename + ' is not valid')
            exit()

def directory_scanner(directory,filename2):
    count=0
    virussig2=[]
    filesindirectory=list_files(directory)
    print("Scanning files in directory:", filesindirectory)
    lengthdirectory=len(filesindirectory)
    print("# files in directory",lengthdirectory)
    #print(lengthdirectory) - length test
    #print(filesindirectory) - directory test
    for i in range(0,lengthdirectory):
        try:
            print("Scan files:", filesindirectory[i],"\n")
            with open(filesindirectory[i]) as fhand:
                for line in fhand:
                    data=line
            with open(filename2) as fhand2:
                for line1 in fhand2:
                    virussig2.append(line1)
            #print(virussig2)
            length=len(virussig2)
            for i in range(0,lengthdirectory):
                if data in virussig2[i]:
                    print("File", filesindirectory[i])
                    print(" Infected virus Detected")
                    count+=1
        except FileNotFoundError:
            directory_find(directory, filename2)
    print("Number of affect files:",count)

def virus_signature(filename2, filename):
# filename2: virus signature;  filename= infected files
    virussig=[]
    #string="58354f2150254041505b345c505a58353428505e2937434329377d2445494341522d5354414e4441"
    try:
        with open(filename) as fhand2:
            for line2 in fhand2:
                data=line2
                print("Virus:", data)
               # print(data)
        with open(filename2) as fhand:
            for line1 in fhand:
                virussig.append(line1)
        #print(virussig)
        length=len(virussig)
        print("# of virus signatures, ", length)
        for i in range(0,length):
            if data in virussig[i]:
                print ("Eicar Test Virus Detected")

    except FileNotFoundError:
        virus_signature(filename2, filename)

def list_files(path):
    # returns a list of names (with extension, without full path) of all files
    # in folder path
    files = []
    for name in os.listdir(path):
        if os.path.isfile(os.path.join(path, name)):
            files.append(name)
    return files

def scanner(signature):
    signature.replace(" ","")
    print("Current signature:", signature)
    #hexi = signature,encode('hex')
    #print(hexi)
    #print(isinstance(signature, str)) test if signature is true
    if 'EICAR-STANDARD-ANTIVIRUS-TEST-FILE' in signature:
        print("Virus detected","\n")
        print("Eicar test file","\n")
        print("Detection type: Test","\n")
    else:
        print("Error")
    string=signature
    #print("Signature leng h",signature.count())
    #match=string.find(signature,"EICAR")
    #if match:
    #    return signature
   # else:
    #    return


def main():
    string="58 35 4F 21 50 25 40 41 50 5B 34 5C 50 5A 58 35 34 28 50 5E 29 37 43 43 29 37 7D 24 45 49 43 41 52 2D 53 54 41 4E 44 41 52 44 2D 41 4E 54 49 56 49 52 55 53 2D 54 45 53 54 2D 46 49 4C 45 21 24 48 2B 48 2A"
    #print("String of eicar", string.replace(" ", ""))
    eicar_check="cc805d5fab1fd71a4ab352a9c533e65fb2d5b885518f4e565e68847223b8e6b85cb48f3afad842726d99239c9e36505c64b0dc9a061d9e507d833277ada336ab"
    directory_scanner(directory, filename2)
    #virus_signature(filename, filename2) single file virus test




if __name__ == '__main__':
    if len(sys.argv) == 4:
        print("Virus utility")
        filename2=sys.argv[1]
        filename = sys.argv[2]
        directory = sys.argv[3]
        main()
    else:
     print('\nUsage:  antivirus [virus file or directory] [Virus signature file]')
     print("\n options: -f filename -p pathname")
