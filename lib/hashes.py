#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from hashlib import algorithms_available, file_digest
from threading import Thread

class FileHash:
	'''Calculate hashes of files'''

	@staticmethod
	def get_algorithms():
		'''Get list of available algorithms'''
		return sorted(algorithms_available)

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
		self._algorithms = algorithms

	def run(self):
		'''Calculate all hashes (multiple algorithms) in parallel - this method launches the worker'''
		self.hashes = [[FileHash.hashsum(path, algorithm=alg) for alg in self._algorithms] for path in self._paths]
