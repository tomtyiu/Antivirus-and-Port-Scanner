__author__ = 'yiut'
#Multiprocessing Port Scanner (UDP/TCP)
#Must use port_scanner python file
#running 4 cores as default -- if more cores, change NUMBER_OF_PROCESSES

import time
import random
import math
import cmath
import port_scanner

from multiprocessing import Process, Queue, current_process, freeze_support
import logging


def worker(input, output):
    for func, args in iter(input.get, 'STOP'):
        result = calculate(func, args)
        output.put(result)

def calculate(func, args):
    result = func(*args)
    return '%s says that %s%s = %s' % \
        (current_process().name, func.__name__, args, result)



def procedure():
    NUMBER_OF_PROCESSES = 4
    start_times=time.clock()
    print("Start time:",start_times)
    start=int(input("Start port: "))
    end=int(input("End port: "))
    if end<=start:
        end=int(input("Error, please enter end port: "))
   # running TCP and UDP port scanning process
    TASKS1 = [(port_scanner.TCP_scan,(port,)) for port in range(start,end)]
    TASKS2 = [(port_scanner.UDP_scan, (port, )) for port in range(start,end)]

     # Create queues
    task_queue = Queue()
    done_queue = Queue()

    # Submit tasks
    for task in TASKS1:
        task_queue.put(task)

    # Start worker processes
    for i in range(NUMBER_OF_PROCESSES):
        Process(target=worker, args=(task_queue, done_queue)).start()

    # Get and print results
    print('Unordered results:')
    for i in range(len(TASKS1)):
        print('\t', done_queue.get())

    # Add more tasks using `put()`
    for task in TASKS2:
        task_queue.put(task)

    # Get and print some more results
    for i in range(len(TASKS2)):
        print('\t', done_queue.get())

    # Tell child processes to stop
    for i in range(NUMBER_OF_PROCESSES):
        task_queue.put('STOP')


    end_time=time.clock()
    print("Processing time:",time.process_time())
    print("Results time:",end_time-start_times)

if __name__ == '__main__':
    freeze_support()
    procedure()





