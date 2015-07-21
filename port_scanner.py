__author__ = 'yiut'
# -*- coding: Non-UTF-8 -*-
# -----------------------------------------------------------------------------
# Name:        Port scanner and sniffer
# Purpose:	   Scans ports locally and sniff traffic
#
# Author:	   Thomas Yiu
# Date:		   07/21/2015
# Version:     0.1
# ---------------------------
import socket, sys
from struct import *

#set flag for continous mode or single data mode
flags=[0,1]

def port_sniff(flags):
    print("-------------------Port Sniffer-----------------")
    HOST = socket.gethostbyname(socket.gethostname())

    #SOCK_STREAM -> SOCK_RAW
    #Create an INET and RAW socket
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_RAW,socket.IPPROTO_IP)
    except socket.error as msg:
        print("Socket can not be created. Error:", str(msg[0])+"Message")
        sys.exit()

    #sock=socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_IP)
    sock.bind((HOST, 0))

    # Include IP headers
    sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

    # receive all packages
    sock.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)

    #flag =0 shows only one package
    if flags==0:
        # receive a package
        package=sock.recvfrom(65565)
        print(package)
        print(sock.recv(65565))
    # flag=1 realtime, continous mode
    if flags==1:
        while True:
            package=sock.recvfrom(65565)
            print(package)

    # disabled promiscuous mode
    sock.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)

#scans ports from start to end
def porttest(start,end):
    sock = socket.socket(socket.AF_INET, socket.SOCK_RAW,socket.IPPROTO_IP)
    print("-------------------Port testing-----------------")
    print("Localhost port: 127.0.0.1")
    print("Scanning ports..", start, " to ", end)
    socket.create_connection(('127.0.0.1',80))

    #port = 100
    for port in range(start,end):
        result = sock.connect_ex(('127.0.0.1',port))
        if result == 0:
           print("Port is open", port)
        else:
           print("Port is not open", port )
    #socket.close()


#testing purposes
if __name__ == '__main__':
    port_sniff(0)
    porttest(0,200)
