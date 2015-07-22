__author__ = 'yiut'

#polymophic eicar virus example
#use for polymophic virus for antivirus testing
## European Institute for Computer Anti-Virus Research eicar file

import hex_file
import math
import random
import sys

def writefile(filename, data):
    try:
        file_out = open(filename, 'w')
        print("Saving to file...to", filename)
        print("writing data to file:", data)
        file_out.write(data)
        file_out.close()
    except FileExistsError:
        print("File exist! Open file to write")
        file_in=open(filename, 'r+')
        file_in.write(data)
        file_in.close()

def random_key():
    #a=int(a)
    random.seed()
    a=random.randrange(0,9999,1)
    print("Random encryption key",a)
    return a

def manipulator(code, enc_code):
    hex_eicar=hex_file.data_hex(code).decode('utf-8')
    #print("Hex:", hex_eicar)

    int_eicar=int(hex_eicar,16)
    #print("Integer", int_eicar)
    new_eicar=int_eicar^enc_code
    #print("new eicar:", new_eicar)
    b_eicar=hex(new_eicar)[2:]
    #print("Hex eicar", b_eicar)
    unhex_eicar=hex_file.data_unhex(b_eicar)
    return unhex_eicar

def polymorphic_function():
    enc_code=random_key()
    eicar_code1="X5O!P%@AP[4\PZX54(P^)7CC)7}$"
    eicar_code2="EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
    eicar_code3=eicar_code1+eicar_code2
    print("Combine original code: ", eicar_code3)
    codered=manipulator(eicar_code1,enc_code)
    codered=codered.decode('utf-8')
    print("Code now:",codered)
    final_code=codered+eicar_code2
    print("Final new code:", final_code)
    hex_eicar=hex_file.data_hex(final_code).decode('utf-8')
    print("signature of eicar:", hex_eicar)
    writefile("p_eicar.txt", final_code)

def main():

    lineout = "-----------------------------------------------------------------------------\n" + \
              "Polymophic function example " + "\n"\
              "EICAR detection test project" + "\n"\
              "-----------------------------------------------------------------------------"
    print(lineout)
    polymorphic_function()


if __name__ == '__main__':
    main()__author__ = 'yiut'

#polymophic eicar virus example
#use for polymophic virus for antivirus testing
## European Institute for Computer Anti-Virus Research eicar file

import hex_file
import math
import random
import sys

def writefile(filename, data):
    try:
        file_out = open(filename, 'w')
        print("Saving to file...to", filename)
        print("writing data to file:", data)
        file_out.write(data)
        file_out.close()
    except FileExistsError:
        print("File exist! Open file to write")
        file_in=open(filename, 'r+')
        file_in.write(data)
        file_in.close()

def random_key():
    #a=int(a)
    random.seed()
    a=random.randrange(0,9999,1)
    print("Random encryption key",a)
    return a

def manipulator(code, enc_code):
    hex_eicar=hex_file.data_hex(code).decode('utf-8')
    #print("Hex:", hex_eicar)

    int_eicar=int(hex_eicar,16)
    #print("Integer", int_eicar)
    new_eicar=int_eicar^enc_code
    #print("new eicar:", new_eicar)
    b_eicar=hex(new_eicar)[2:]
    #print("Hex eicar", b_eicar)
    unhex_eicar=hex_file.data_unhex(b_eicar)
    return unhex_eicar

def polymorphic_function():
    enc_code=random_key()
    eicar_code1="X5O!P%@AP[4\PZX54(P^)7CC)7}$"
    eicar_code2="EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
    eicar_code3=eicar_code1+eicar_code2
    print("Combine original code: ", eicar_code3)
    codered=manipulator(eicar_code1,enc_code)
    codered=codered.decode('utf-8')
    print("Code now:",codered)
    final_code=codered+eicar_code2
    print("Final new code:", final_code)
    hex_eicar=hex_file.data_hex(final_code).decode('utf-8')
    print("signature of eicar:", hex_eicar)
    writefile("p_eicar.txt", final_code)

def main():

    lineout = "-----------------------------------------------------------------------------\n" + \
              "Polymophic function example " + "\n"\
              "EICAR detection test project" + "\n"\
              "-----------------------------------------------------------------------------"
    print(lineout)
    polymorphic_function()


if __name__ == '__main__':
    main()
