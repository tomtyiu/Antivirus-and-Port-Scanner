import subprocess
import os
import sys

#decrypt files openssl function
def dec_openssl(infile, outfile):
    lineout = "-----------------------------------------------------------------------------\n" + \
              "Openssl Decryption program" + "\n"\
              "-----------------------------------------------------------------------------"
    print(lineout)
    command="openssl enc -d -aes-256-cbc -in "+infile+" -out "+outfile+" -pass pass:ITETnyt/Se0t6"
    #print(command,'\n')
    print("Decrypt file processing using openssl")
    subprocess.call(command, shell=True)    # returns 0 or 1

#encrypt file openssl function
def enc_openssl(infile, outfile):
    lineout = "-----------------------------------------------------------------------------\n" + \
              "Openssl Encryption program" + "\n"\
              "-----------------------------------------------------------------------------"
    print(lineout)
    command="openssl enc -aes-256-cbc -in "+infile+" -out "+outfile+" -pass pass:ITETnyt/Se0t6"
    #print(command,'\n')
    print("Processing file",infile," ", outfile)
    print("encrypt file processing using openssl")
    subprocess.call(command, shell=True)    # returns 0 or 1

if __name__ == '__main__':
    infile=input("Input input file:")
    outfile=input("Output file:")
    print("Encrypt file.")
    enc_openssl(infile, outfile)
