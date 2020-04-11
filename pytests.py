#!/usr/bin/python3

import sys
import subprocess

portno = 9110

# each file is a subcategory of cases
tests = ['simple.txt']
passed = []
failed = []
num_cases = 0

for f in tests:
    with open(f, 'r') as cases:
        for case in cases:
            case = case.rstrip()
            reg = '{}'.format(case)
            proxy = '{} -x localhost:{}'.format(case, portno)
            reg = subprocess.run(['curl', '-s', reg], stdout=subprocess.PIPE)
            proxy = subprocess.run(['curl', '-s'] + proxy.split(), stdout=subprocess.PIPE)
            if reg.returncode == 0 and proxy.returncode != 0 or \
                reg.stdout != proxy.stdout:
                failed.append(f + ' : ' + case)
            else:
                #print(proxy.stdout)
                passed.append(f + ' : ' + case)
            num_cases += 1
    if failed:
        failed.append('') #split output btwn files/sets of cases

if len(passed) == num_cases:
    print('All tests passed.')
    exit(0)
else:
    print('{} tests passed.\n'.format(len(passed)), \
          'Failed: ', '\n\t'.join(failed), sep='', end='\n')
