__author__ = 'yiut'
import antivirus
import encdecfunc
import sys
import os

def key(dict):
    return dict.keys()

def item(dict):
    return dict.items()

def value(dict):
    return dict.values()

def find_dict(value,dictionary,length):
    for k,v in dictionary.items():
        if value in v:
            return v

def dictfile(filename,dictname):
    print("Creating dictionary from",filename,'\n')
    print("Dictionary name ", dictname,'\n')
    try:
        with open(filename,'r') as filehandle:
            line=filehandle.readline()
            dicthame={}
            keycounter=1
            while line:
                key=str(keycounter)
                dicthame[key]=line
                keycounter+=1
                line=filehandle.readline()
            filehandle.close()
            return dicthame
    except FileNotFoundError:
        print("File NOT FOUND!!")

#returns length of dictionary
def le(dictionary):
    return len(dictionary)

def dictfilewrite(filename, dictionary):
    with open(filename,'w+') as file:
        print("Size of dictionary,", le(dictionary))
        for key in dictionary:
            file.write(dictionary[key])
        print("Save dictionary to ",filename)
        #filename.close()

if __name__ == '__main__':
    dictionary={}
    #dictionary2={}
    #filehandle=input("Input filename to read:")
    #filename=input("Input filename to write:")
    value=input("Find virus signature name: ")
    # dictname=input("input dictinoary name: ")
    dictionary=dictfile('virus_signature.txt', 'Virus Signature')
    find_dict(value, dictionary, le(dictionary))

    #print("key",key(dictionary))
    #print("items: ", item(dictionary))
    #print("Values:", value(dictionary))
    #dictfilewrite(filename,dictionary)
    #print(dictionary)


