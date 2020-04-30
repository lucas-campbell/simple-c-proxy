#!/usr/bin/python3

import sys
import subprocess
# for work threads
import threading, queue, _thread
from cases_info import Cases_Info

q = queue.Queue()
portno = 9110
cases_info = Cases_Info()
num_threads = 2
keep_working = True


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

def do_work(info):
    f = info[0]
    case = info[1]
    reg = '{}'.format(case)
    if len(sys.argv) > 1:
        proxy = '{} -x {}:{}'.format(case, sys.argv[1], portno)
    else:
        proxy = '{} -x localhost:{}'.format(case, portno)
    reg = subprocess.run(['curl', '-s', reg], stdout=subprocess.PIPE)
    proxy = subprocess.run(['curl', '-s'] + proxy.split(), stdout=subprocess.PIPE)
    if reg.returncode == 0 and proxy.returncode != 0 or \
        reg.stdout != proxy.stdout:
        #failed.append(f + ' : ' + case) #non-threaded version
        cases_info.add_failed(f + ' : ' + case)
    else:
        #print(proxy.stdout)
        #passed.append(f + ' : ' + case)
        cases_info.add_passed(f + ' : ' + case)
    #num_cases += 1 #not needed, done in add methods

def main():
    try:
        # each file is a subcategory of cases
        tests = ['simple.txt']

        threads = [threading.Thread(target=worker) for _ in range(num_threads)]
        # turn on the worker threads
        for t in threads:
            t.start()

        for f in tests:
            with open(f, 'r') as cases:
                for case in cases:
                    case = case.rstrip()
                    x = (f, case)
                    q.put(x)
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
        print('All work completed')

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
