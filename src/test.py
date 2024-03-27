#!/usr/bin/env python3

from dsc_defines import *
import subprocess
import time
import random
import hashlib
import sys
import os


def TestLatency(num):
	pub_addresses = []
	for i in range(20):
		public_key = hashlib.sha256(str(random.randint(1, 10000)).encode('utf-8')).hexdigest()
		key_bytes = bytes.fromhex(public_key)
		pub_addresses.append(Base58Str(key_bytes))

	cur_dir = os.path.dirname(os.path.abspath(__file__))
	start_time = time.time()
	for i in range(num):
		LogMsg(f'# {i + 1}:')
		subprocess.call(['python3', os.path.join(cur_dir, 'dsc.py'), 'wallet', 'send', '0.01', pub_addresses[i % len(pub_addresses)]])
	cost_time = time.time() - start_time
	LogMsg(f"Latency test, send {num} transactions, total time: {cost_time} seconds")

def TestThroughPut(num):
	pub_addresses = []
	for i in range(20):
		public_key = hashlib.sha256(str(random.randint(1, 10000)).encode('utf-8')).hexdigest()
		key_bytes = bytes.fromhex(public_key)
		pub_addresses.append(Base58Str(key_bytes))
	cur_dir = os.path.dirname(os.path.abspath(__file__))
	start_time = time.time()
	pub_addresses_str = ' '.join(pub_addresses)
	subprocess.call(['python3', os.path.join(cur_dir, 'dsc.py'), 'wallet', 'throughput', str(num), pub_addresses_str])
	cost_time = time.time() - start_time
	LogMsg(f"Throughput test, send {num} transactions, total time: {cost_time} seconds")

if __name__ == "__main__":
	arguments = sys.argv[1:]
	if len(arguments) != 2:
		LogMsg("Usage: python3 test.py <latency|throughput> <num>")
		exit(1)
	if arguments[0] == 'latency':
		TestLatency(int(arguments[1]))
	elif arguments[0] == 'throughput' or arguments[0] == 'tp':
		TestThroughPut(int(arguments[1]))
	else:
		LogMsg("Usage: python3 test.py <latency|throughput> <num>")