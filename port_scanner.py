__author__ = 'yiut'
# -*- coding: Non-UTF-8 -*-
# -----------------------------------------------------------------------------
# Name:        Port scanner and sniffer
# Purpose:	   Scans ports locally and sniff traffic
#
# Author:	   Thomas Yiu
# Date:		   07/21/2015
# Version:     0.2
# ---------------------------
import socket, sys
from struct import *
import time
import os

from multiprocessing import Process, Queue, current_process, freeze_support
from multiprocessing import Pool, Lock, Process, queues
import multiprocessing as mp
from multiprocessing.connection import wait

import logging

#set flag for continous mode or single data mode
flags=[0,1]
def info(title):
    print(title)
    print('module name:', __name__)
    if hasattr(os, 'getppid'):  # only available on Unix
        print('parent process:', os.getppid())
    print('process id:', os.getpid())

def port_sniff(flags):
    print("-------------------Port Sniffer-----------------")
    HOST = socket.gethostbyname(socket.gethostname())
    print("HOST: ",HOST)
    #SOCK_STREAM -> SOC K_RAW
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
    try:
        #flag =0 shows only one package
        if flags==0:
            # receive a package
            packet = sock.recvfrom(65565)

            #packet string from tuple
            packet = packet[0]

            #take first 20 characters for the ip header
            ip_header = packet[0:20]

            #now unpack them :)
            iph = unpack('!BBHHHBBH4s4s' , ip_header)

            version_ihl = iph[0]
            version = version_ihl >> 4
            ihl = version_ihl & 0xF

            iph_length = ihl * 4

            ttl = iph[5]
            protocol = iph[6]
            s_addr = socket.inet_ntoa(iph[8]);
            d_addr = socket.inet_ntoa(iph[9]);

            print('Version : ' + str(version) + ' IP Header Length : ' + str(ihl) + ' TTL : ' + str(ttl) + ' Protocol : ' + str(protocol) + ' Source Address : ' + str(s_addr) + ' Destination Address : ' + str(d_addr))

            tcp_header = packet[iph_length:iph_length+20]

            #now unpack them :)
            tcph = unpack('!HHLLBBHHH' , tcp_header)

            source_port = tcph[0]
            dest_port = tcph[1]
            sequence = tcph[2]
            acknowledgement = tcph[3]
            doff_reserved = tcph[4]
            tcph_length = doff_reserved >> 4

            print('Source Port : ' + str(source_port) + ' Dest Port : ' + str(dest_port) + ' Sequence Number : ' + str(sequence) + ' Acknowledgement : ' + str(acknowledgement) + ' TCP header length : ' + str(tcph_length))

            h_size = iph_length + tcph_length * 4
            data_size = len(packet) - h_size

            #get data from the packet
            data = packet[h_size:]

            print('Data : ' + str(data))


           # print(sock.recv(65565))

        # flag=1 realtime, continous mode
        if flags==1:
            while True:
                packet = sock.recvfrom(65565)

                #packet string from tuple
                packet = packet[0]

                #take first 20 characters for the ip header
                ip_header = packet[0:20]

                #now unpack them :)
                iph = unpack('!BBHHHBBH4s4s' , ip_header)

                version_ihl = iph[0]
                version = version_ihl >> 4
                ihl = version_ihl & 0xF

                iph_length = ihl * 4

                ttl = iph[5]
                protocol = iph[6]
                s_addr = socket.inet_ntoa(iph[8]);
                d_addr = socket.inet_ntoa(iph[9]);

                print('Version : ' + str(version) + ' IP Header Length : ' + str(ihl) + ' TTL : ' + str(ttl) + ' Protocol : ' + str(protocol) + ' Source Address : ' + str(s_addr) + ' Destination Address : ' + str(d_addr))

                tcp_header = packet[iph_length:iph_length+20]

                #now unpack them :)
                tcph = unpack('!HHLLBBHHH' , tcp_header)

                source_port = tcph[0]
                dest_port = tcph[1]
                sequence = tcph[2]
                acknowledgement = tcph[3]
                doff_reserved = tcph[4]
                tcph_length = doff_reserved >> 4

                print('Source Port : ' + str(source_port) + ' Dest Port : ' + str(dest_port) + ' Sequence Number : ' + str(sequence) + ' Acknowledgement : ' + str(acknowledgement) + ' TCP header length : ' + str(tcph_length))

                h_size = iph_length + tcph_length * 4
                data_size = len(packet) - h_size

                #get data from the packet
                data = packet[h_size:]

                print('Data : ' + str(data))
    except KeyboardInterrupt:
        Print("Ctrl-C pressed; terminate program")
    # disabled promiscuous mode
    sock.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)

def TCP_scan(port):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM,socket.IPPROTO_IP)
    socket.create_connection(('127.0.0.1','80'))
    result = sock.connect_ex(('127.0.0.1',port))
    if port == 22:
        print("SSH port \n")
    if port == 20:
        print("FTP port \n")
    if port == 80:
        print("HTTP port \n")
    if result == 0:
      print("TCP Port {}: \t Open".format(port))
      # print("Port is open", port)
    else:
       print("TCP Port {}: \t not Open".format(port))

def UDP_scan(port):
    sock2= socket.socket(socket.AF_INET, socket.SOCK_DGRAM,socket.IPPROTO_IP)
    socket.create_connection(('127.0.0.1',80))
    result = sock2.connect_ex(('127.0.0.1',port))
    if port == 22:
        print("SSH port \n")
    if port == 20:
        print("FTP port \n")
    if port == 80:
        print("HTTP port \n")

    if result == 0:
      print("UDP Port {}: \t Open".format(port))
      # print("Port is open", port)
    else:
       print("UDP Port {}: \t not Open".format(port))

#scans ports from start to end
def porttest(start,end):
    mp.set_start_method('spawn')
    task_queue=Queue()
    done_task=Queue()
    print("-------------------Port testing-----------------")
    print("Localhost port: 127.0.0.1")
    print("Scanning ports..", start, " to ", end)
    print("Parallel processing started.")
    for port in range(start,end):
        p1=mp.Process(target=TCP_scan, args=(port,))
        p1.start()
        p1.join()
        p2=mp.Process(target=UDP_scan, args=(port,))
        p2.start()
        p2.join()
    #socket.close()

#more port scanner; only for testing purposes or penetration testing
def porttestremote(remoteip, start,end):
    sock = socket.socket(socket.AF_INET, socket.SOCK_RAW,socket.IPPROTO_IP)
    print("-------------------Port testing-----------------")
    #print("Localhost port: 127.0.0.1")
    rserverip=socket.gethostbyname(remoteip)
    print("Max port# can not exceed 65536")
    print("Connecting to:", rserverip)
    print("Scanning ports..", start, " to ", end)
    socket.create_connection((rserverip,80))

    #port = 100
    for port in range(start,end):
        result = sock.connect_ex((rserverip,port))
        if result == 0:
           print("Port {}: \t Open".format(port))
        else:
           print("Port {}: \t Not Open".format(port))
    #socket.close()

#testing purposes
if __name__ == '__main__':
    freeze_support()
    info('main line')
    port_sniff(0)
    #remoteip=input("Remote IP address: ")
    start=int(input("Start port: "))
    end=int(input("End port: "))
    #print("-" * 60)
    #porttestremote(remoteip,start,end)
    porttest(start,end)

