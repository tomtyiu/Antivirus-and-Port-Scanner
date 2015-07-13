__author__ = 'yiut'
# -*- coding: Non-UTF-8 -*-
# -----------------------------------------------------------------------------
# Name:        Virus scanner, tested with Eicar with sha512 checksum scan
# Purpose:	   Simpmle Virus scanner, test with Eicar
#
# Author:	   Thomas Yiu
# Date:		   07/13/2015
# Version:     0.1
# Usage:  antivirus.py [signature file]
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


if __name__ == '__main__':
    if len(sys.argv) == 2:
        filename = sys.argv[1]
        main()
    else:
        print('\nUsage:  antivirus [signature file]')
