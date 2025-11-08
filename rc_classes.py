#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import logging
from json import load, dump
from time import time
from subprocess import Popen, PIPE, STDOUT, STARTUPINFO, STARTF_USESHOWWINDOW
from pathlib import Path
from hashlib import algorithms_available, file_digest
from threading import Thread
from os import getpid

__local_path__ = Path().home().joinpath('AppData', 'Local', 'RoboCopyGui')

class Config:
	'''Load configuration file in JSON format'''

	def __init__(self, path):
		'''Read config file'''
		with path.open(encoding='utf-8') as fp:
			for key, value in load(fp).items():
				self.__dict__[key] = value

class Settings:
	'''Handle user settings'''

	_KEYS = ('src_dir_path', 'dst_dir_path', 'log_dir_path', 'options', 'hashes', 'verify')

	def __init__(self):
		'''Generate object for setting, try to load from JSON file'''
		self._path = __local_path__ / 'settings.json'
		try:
			self.load()
		except:
			self._path.parent.mkdir(parents=True, exist_ok=True)
		self.src_dir_path = self._get_dir('src_dir_path')
		self.dst_dir_path = self._get_dir('dst_dir_path')
		self.log_dir_path = self._get_dir('log_dir_path')
		self.options = self.options if 'options' in self.__dict__ else ['/compress', '/z']
		self.hashes = self.hashes if 'hashes' in self.__dict__ else ['md5']
		self.verify = self.verify if 'verify' in self.__dict__ else 'size'

	def _get_dir(self, key):
		'''Get directory path to given key'''
		return self.__dict__[key] if key in self.__dict__ and self.__dict__[key].is_dir() else None

	def save(self):
		'''Save config file'''
		with self._path.open('w', encoding='utf-8') as fp:
			dump({key: self.__dict__[key] for key in self._KEYS}, fp)

class Logger:
	'''Handle logging'''

	@staticmethod
	def clean(config):
		'''Remove old log and TSV files'''
		errors = list()
		if __local_path__.is_dir():
			now = time()	# purge logs older 7 days
			keep = 86400 * config.keep_log	# in seconds
			for path in __local_path__.glob(f'*{config.log_name}'):
				if now - path.stat().st_mtime > keep:
					try:
						path.unlink()
					except Exception as ex:
						errors.append((path, ex))
			for path in __local_path__.glob(f'*{config.tsv_name}'):
				if now - path.stat().st_mtime > keep:
					try:
						path.unlink()
					except Exception as ex:
						errors.append((path, ex))
		else:
			try:
				__local_path__.mkdir(parents=True)
			except Exception as ex:
				errors.append((path, ex))
		return errors

	def __init__(self, config):
		'''Generate object for logging'''
		prefix = f'{getpid():08x}' + time.strftime('%Y-%m-%d_%H%M%S_')
		self._log_name = prefix + config.log_name
		self._tsv_name = prefix + config.tsv_name
		self._local_log_path = __local_path__ / self._log_name
		formatter = logging.Formatter('%(asctime)s %(levelname)s: %(message)s', datefmt='%Y-%m-%d %H:%M:%S')
		logger = logging.getLogger()
		logger.setLevel(logging.INFO)
		log_fh = logging.FileHandler(filename=self._local_log_path, mode='w', encoding='utf-8')
		log_fh.setFormatter(formatter)
		logger.addHandler(log_fh)

	def add(self, dir_path):
		'''Add file to log'''
		userlog_fh = logging.FileHandler(filename=dir_path/self._log_name, mode='w', encoding='utf-8')
		userlog_fh.setFormatter(formatter)
		logger.addHandler(userlog_fh)

	def copy_log_into(self, dir_path):
		'''Copy log file to given directory'''
		dir_path.joinpath(self._log_name).write_bytes(self._local_log_path.read_bytes())

	def open_tsv(self):
		'''Open TSV file for writing'''
		self._local_tsv_path = __local_path__ / self._tsv_name
		return self._local_tsv_path.open('w', encoding='utf-8')

	def copy_tsv_into(self, dir_path):
		'''Copy TSV file to given directory'''
		dir_path.joinpath(self._tsv_name).write_bytes(self._local_tsv_path.read_bytes())

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
			return f'{rnd}{prefix}', rnd
		if self < 0:
			raise ValueError('Size must be positive')
		iec, rnd_iec = _round(('PiB', 2**50), ('TiB', 2**40), ('GiB', 2**30), ('MiB', 2**20), ('kiB', 2**10))
		si, rnd_si = _round(('PB', 10**15), ('TB', 10**12), ('GB', 10**9), ('MB', 10**6), ('kB', 10**3))
		return (f'{iec}/{si}/' if rnd_iec or rnd_si else '') + f'{int(self)}B'

	def __add__(self, addend):
		''' + '''
		return Size(int.__add__(self, addend))

	def __sub__(self, subtrahend):
		''' - '''
		return Size(int.__sub__(self, subtrahend))

	def __mul__(self, factor):
		''' * '''
		return Size(int.__mul__(self, factor))

	def __truediv__(self, quotient):
		''' / '''
		return Size(int.__floordiv__(self, quotient))

	def __mod__(self, absolut):
		''' % : Percentage of'''
		return f'{int.__mul__(self, 100).__floordiv__(absolut)} %'

class NormString:
	'''Normalize string to given length for better echo'''

	def __init__(self, max_len):
		'''Calculate only once'''
		self._max_len = max_len
		self._part_len = (max_len - 3) // 2

	def get(self, msg):
		'''Normalize'''
		len_msg = len(msg)
		if len_msg > self._max_len:
			return f'{msg[:self._part_len]}...{msg[-self._part_len:]}'
		else:
			return msg + ' ' * (self._max_len - len_msg)

class RoboCopy(Popen):
	'''Wrapper for RoboCopy'''

	def __init__(self, src=None, dst=None, file=None, parameters=None):
		'''Prepare RoboCopy'''
		self._startupinfo = STARTUPINFO()
		self._startupinfo.dwFlags |= STARTF_USESHOWWINDOW
		self._cmd = ['robocopy']
		if parameters in ('help', '/?', 'h', '?'):
			self._cmd.append('/?')
			return
		if src:
			self._cmd.append(src)
		if dst:
			self._cmd.append(dst)
		if file:
			self._cmd.append(Path(file))
		else:
			self._cmd.append('/e')
		if parameters:
			self._cmd.extend(parameters)

	def __repr__(self):
		'''Return command line as string'''
		return ' '.join(f"'{item}'" if isinstance(item, Path) else f'{item}' for item in self._cmd)

	def popen(self):
		'''Launch RoboCopy process'''
		super().__init__(self._cmd,
			stdout = PIPE,
			stderr = PIPE,
			encoding = 'utf-8',
			errors = 'ignore',
			universal_newlines = True,
			startupinfo = self._startupinfo
		)
		return self

	def run(self, echo=print, max_len=79, kill=None):
		'''Run RoboCopy and yield stdout'''
		self.popen()
		short_path = ''
		short = NormString(max_len)
		shorter = NormString(max_len - 8)
		for line in self.stdout:
			if msg := line.strip():
				if msg.endswith('%'):
					echo(f'{msg} of {short_path}', end='\r')
				else:
					echo(short.get(msg), end='\r')
					short_path = shorter.get(msg)
			if kill and kill.is_set():
				self.terminate()
		return self.wait()

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
