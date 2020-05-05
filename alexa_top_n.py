#!/usr/bin/python3

import sys
import subprocess
# for work threads
import threading, queue, _thread
from cases_info import Cases_Info

q = queue.Queue()
portno = 9110
cases_info = Cases_Info()
num_threads = 4
keep_working = True
tests = ['alexa.txt']
num_sites = 100 if len(sys.argv) == 1 else sys.argv[1]


def worker():
    try:
        while keep_working:
            item = q.get()
            if item is None:
                break
            print(f'Working on {item}')
            do_work(item)
            q.task_done()
            print(f'Finished {item}')
    # for cases where we see it, send it to the main thread instead 
    except KeyboardInterrupt: 
        _thread.interrupt_main()
        return

def main():
    try:
        threads = [threading.Thread(target=worker) for _ in range(num_threads)]
        # turn on the worker threads
        for t in threads:
            t.start()

        count = 0
        done = False
        max_sites = max(num_sites, 100)
        for f in tests:
            if done == True:
                break
            with open(f, 'r') as cases:
                for case in cases:
                    case = case.rstrip()
                    x = (f, case)
                    q.put(x)
                    count += 1
                    if count == max_sites:
                        done = True
                        break
        cases_info.fail_lock.acquire()
        if cases_info.failed:
            cases_info.failed.append('') #split output btwn files/sets of cases
        cases_info.fail_lock.release()
        print('All task requests sent\n', end='')
        # block until all tasks are done
        q.join()
        # stop workers
        for i in range(num_threads):
            q.put(None)
        for t in threads:
            t.join()
        print('All work completed.')

        if len(cases_info.passed) == cases_info.num_cases:
            print('All tests passed.')
        else:
            print('{} tests passed.\n'.format(len(cases_info.passed)), \
                  'Failed: ', '\n\t'.join(cases_info.failed), sep='', end='\n')
    except KeyboardInterrupt: 
        keep_working = False
        sys.exit()

if __name__ == "__main__":
    main()
