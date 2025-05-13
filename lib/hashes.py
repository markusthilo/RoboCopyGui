#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from hashlib import algorithms_available, file_digest
from threading import Thread
from time import sleep
from pathlib import Path

class FileHash:
	'''Calculate hashes of files'''

	@staticmethod
	def get_algorithms():
		'''Get list of available algorithms'''
		return sorted(algorithms_available)

	@staticmethod
	def parse_algorithms(arg):
		'''Parse algorithms given from command line as arguments, None will return md5 as default'''
		if arg:
			if arg.lower() == 'none':
				return None
			algs = list()
			for alg in arg.split(','):
				alg_lower = alg.lower()
				if not alg_lower in algorithms_available:
					raise ValueError(f'Algorithm {alg} is not available with hashlib')
				algs.append(alg_lower)
		else:
			return ['md5']

	@staticmethod
	def hashsum(path, algorithm='md5'):
		'''Calculate hash of one file'''
		try:
			with path.open('rb') as fh:
				return file_digest(fh, algorithm).hexdigest()
		except:
			return ''

class HashThread(Thread):
	'''Calculate hashes of files in thread'''

	def __init__(self, paths, algorithms=['md5']):
		'''Generate object to calculate hashes of files using multiprocessing pool'''
		super().__init__()
		self._paths = paths
		self._algs = algorithms

	def run(self):
		'''Calculate all hashes (multiple algorithms) in parallel - this method launches the worker'''
		self.hashes = [[FileHash.hashsum(path, algorithm=alg) for alg in self._algs] for path in self._paths]

	def wait(self, echo=print):
		'''Wait for worker to finish and return results'''
		if self.is_alive():
			echo('Hash calculation is still running')
			index = 0
			while self.is_alive():
				echo('-\\|/'[index], end='\r')
				sleep(.25)
				index = index + 1 if index < 3 else 0
		self.join()
		return self.hashes