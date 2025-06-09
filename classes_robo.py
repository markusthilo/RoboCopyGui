#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from json import load, dump
#from subprocess import Popen, PIPE, STDOUT, STARTUPINFO, STARTF_USESHOWWINDOW
from pathlib import Path
from hashlib import algorithms_available, file_digest
from threading import Thread

class Config:
	'''Handle configuration file in JSON format'''

	def __init__(self, path):
		'''Read config file'''	
		self._path = path
		self._keys = list()
		with self._path.open(encoding='utf-8') as fp:
			for key, value in load(fp).items():
				self.__dict__[key] = value
				self._keys.append(key)

	def exists(self, key):
		'''Check if key exists'''
		return key in self._keys

	def save(self, path=None):
		'''Save config file'''
		if path:
			self._path = path
		with self._path.open('w', encoding='utf-8') as fp:
			dump({key: self.__dict__[key] for key in self._keys}, fp)

class Size(int):
	'''Human readable size'''

	def __repr__(self):
		'''Genereate readable size'''
		def _round(*base):	# intern function to calculate human readable
			for prefix, b in base:
				rnd = round(self/b, 2)
				if rnd >= 1:
					break
			if rnd >= 10:
				rnd = round(rnd, 1)
			if rnd >= 100:
				rnd = round(rnd)
			return f'{rnd} {prefix}', rnd
		if self < 0:
			raise ValueError('Size must be positive')
		iec, rnd_iec = _round(('PiB', 2**50), ('TiB', 2**40), ('GiB', 2**30), ('MiB', 2**20), ('kiB', 2**10))
		si, rnd_si = _round(('PB', 10**15), ('TB', 10**12), ('GB', 10**9), ('MB', 10**6), ('kB', 10**3))
		return (f'{iec} / {si} / ' if rnd_iec or rnd_si else '') + f'{int(self)} ' + ('byte' if self == 1 else 'bytes')

	def __add__(self, other):
		'''Plus'''
		return Size(int.__add__(self, other))

class RoboCopy:
	'''Wrapper for RoboCopy'''

	CMD = 'robocopy'

	def __init__(self):
		'''Prepare RoboCopy arguments'''
		self._args = ['/z', '/fp', '/ns', '/njh', '/njs', '/nc', '/r:0', '/w:0']
		self._cmd = [self.CMD, '/?']
		self._startupinfo = STARTUPINFO()
		self._startupinfo.dwFlags |= STARTF_USESHOWWINDOW
		try:
			for line in self.run():
				if line.lstrip().lower().startswith('/unicode'):
					self._args.append('/unicode')
				elif line.lower().startswith('/compress'):
					self._args.append('/compress')
		except Exception as ex:
			raise ChildProcessError(f'Unable to execute "robocopy /?"\n\t{type(ex)}: {ex}')

	def __repr__(self):
		'''Return command line as string'''
		return ' '.join(f"'{item}'" if isinstance(item, Path) else f'{item}' for item in self._cmd)

	def mk_cmd(self, src, dst, file=None):
		'''Create command line for RoboCopy'''
		self._cmd = [self.CMD, src, dst]
		if file:
			self._cmd.append(Path(file))
		else:
			self._cmd.append('/e')
		self._cmd.extend(self._args)
		return self.__repr__()

	def popen(self):
		'''Launch RoboCopy process'''
		self.process = Popen(self._cmd,
			stdout = PIPE,
			stderr = STDOUT,
			encoding = 'utf-8',
			errors = 'ignore',
			universal_newlines = True,
			startupinfo = self._startupinfo
		)
		return self.process

	def run(self):
		'''Run RoboCopy and yield stdout'''
		self.popen()
		for line in self.process.stdout:
			if stripped := line.strip():
				yield stripped
		self.returncode = self.process.wait()

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

	def __init__(self, files, algorithms=['md5']):
		'''Generate object to calculate hashes of files using multiprocessing pool'''
		super().__init__()
		self._files = files
		self._algorithms = algorithms
		self.keys = ['src_path', 'src_size']  + self._algorithms + ['dst_path']

	def run(self):
		'''Calculate all hashes (multiple algorithms) in parallel - this method launches the worker'''
		self.files = [
			{'src_path': src_path, 'src_size': size}
			| {alg: FileHash.hashsum(src_path, algorithm=alg) for alg in self._algorithms}
			| {'dst_path': dst_path}
			for src_path, size, dst_path in self._files
		]
