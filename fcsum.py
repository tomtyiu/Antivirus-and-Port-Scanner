# -----------------------------------------------------------------------------
# Name:        file md5 and sha512 checksum
# Purpose:	   md5 sha512 check sum
#
# Author:	   Thomas Yiu
# Date:		   05/8/2015
#
# -----------------------------------------------------------------------------

import hashlib
import os
import sys
import ssl
import _thread
from multiprocessing import Pool
from time import sleep

global myip

#md5 checksum code
def  md5checksum(file):
    with open(file, 'rb') as fh:
       # m = hashlib.md5.new()
        m = hashlib.md5()
        while True:
            data = fh.read(8192)
            if not data:
                break
            m.update(data)
        return m.hexdigest()
    print("encryption processed")

def sha512checksum(file):
    with open(file, 'rb') as fh:
       # m = hashlib.sha512.new()
        m = hashlib.sha512()
        while True:
            data = fh.read(8192)
            if not data:
                break
            m.update(data)
        return m.hexdigest()
    print("encryption processed")

#main function to check md5 and sha512 1 or 2 files
def main():
    
    print ("Check 1 or 2 files for MD5")
    md5check=input("Number of files to check (1 or 2)?>>")
    if md5check == '1':
        filenamei=input("Enter a filename>> ")
        try:
            filename=open(filenamei)
            filehandle=md5checksum(filenamei)
            print('MD5 checksum of '+filenamei+' is '+filehandle)
            print('Check with md5 of the file in the website')
        except:
            print ('File cannot be opened: ' + filename)
            exit()
    else:
        filenamei=input("Enter a first filename>> ")    
        filenamei2=input("Enter a second filename>>")
        try:
            filename=open(filenamei)
            filename2=open(filenamei2)
            print("md5 hashing files... \n")
            filehandle=md5checksum(filenamei)
            filehandle2=md5checksum(filenamei2)
            print("sha512 hashing files... \n")
            filehandling512=sha512checksum(filenamei)
            filehandling512a=sha512checksum(filenamei2)
            print ('SHA512 checksum of '+filenamei+' is '+filehandling512)
            print ('SHA512 checksum of '+filenamei2+' is '+filehandling512a)

            print('MD5 checksum of '+filenamei+' is '+filehandle)
            print('MD5 checksum of '+filenamei2+' is '+filehandle2)
            if filehandle==filehandle2:
                print ("md5 checksum test pass")
            else:
                print("Error in md5 checksum, please check file")

            if filehandling512==filehandling512a:
                print ("sha512 checksum test pass")
            else:
                print("Error in sha512 checksum, please check file")
            print("\n\nFinish cryto")
        except:
            print ('File cannot be opened: ' + filename)
            exit()



if __name__ == '__main__':
    main()
