#!/usr/bin/env python3

import threading

class Cases_Info:
    """
    Thread-safe info to update about cases (what passed/failed)
    """
    def __init__(self):
        self.passed = []
        self.failed = []
        self.num_cases = 0
        self.pass_lock = threading.Lock()
        self.fail_lock = threading.Lock()
        self.count_lock = threading.Lock()

    def add_passed(self, msg):
        # append to passed list
        self.pass_lock.acquire()
        self.passed.append(msg)
        self.pass_lock.release()
        # increment num cases
        self.count_lock.acquire()
        self.num_cases += 1
        self.count_lock.release()

    def add_failed(self, msg):
        # append to failed list
        self.fail_lock.acquire()
        self.failed.append(msg)
        self.fail_lock.release()
        # increment num cases
        self.count_lock.acquire()
        self.num_cases += 1
        self.count_lock.release()



