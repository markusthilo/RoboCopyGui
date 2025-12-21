#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import logging
from pathlib import Path
from json import load, dump
from time import time, strftime
from traceback import format_exc
from sys import exc_info
from subprocess import Popen, PIPE, STDOUT, STARTUPINFO, STARTF_USESHOWWINDOW
from hashlib import algorithms_available, file_digest
from threading import Thread

__parent_path__ = Path(__file__).parent

class Logger:
	'''Handle logging'''

	@staticmethod
	def debug(message):
		'''Log debug message'''
		logging.debug(message)

	@staticmethod
	def info(message):
		'''Log info message'''
		logging.info(message)

	@staticmethod
	def exception(level, message=None):
		'''Log exception'''
		ex_type, ex_text, traceback = exc_info()
		if ex_type:
			msg = f'{message}, {ex_type.__name__}: {ex_text}' if message else f'{ex_type.__name__}: {ex_text}'
		else:
			msg = message if message else ''
		if traceback:
			msg += f'\n{format_exc().strip()}'
		logging.__dict__[level.lower()](msg)

	@staticmethod
	def warning(message=None):
		'''Log warning'''
		Logger.exception('warning', message=message)

	@staticmethod
	def error(message=None, exception=None):
		'''Log error'''
		Logger.exception('error', message=message)

	@staticmethod
	def critical(message=None, exception=None):
		'''Log critical error'''
		Logger.exception('critical', message=message)

	def __init__(self, echo, config):
		'''Generate object for logging'''
		self._log_formatter = logging.Formatter('%(asctime)s %(levelname)s: %(message)s', datefmt='%Y-%m-%d %H:%M:%S')
		self._logger = logging.getLogger()
		self._logger.setLevel(logging.__dict__[config.log_level.upper()])
		class stream:	# stream handler using echo
			def write(message):
				echo(message.strip())
		self._streamhandler = logging.StreamHandler(stream=stream)
		self._streamhandler.setFormatter(logging.Formatter('%(levelname)s: %(message)s'))
		self._logger.addHandler(self._streamhandler)
		self._local_dir_path = config.local_path
		self._local_dir_path.mkdir(parents=True, exist_ok=True)
		self._ts = strftime('%Y-%m-%d_%H%M%S')
		self._log_name = config.log_name.replace('#', self._ts)
		self.local_log_path = self._local_dir_path / self._log_name
		self._local_fh = logging.FileHandler(filename=self.local_log_path, mode='w', encoding='utf-8')
		self._local_fh.setFormatter(self._log_formatter)
		self._logger.addHandler(self._local_fh)
		Logger.debug(f'Logging to {self.local_log_path} (level: {config.log_level})')
		now = int(time())	# purge old logs
		keep = 86400 * config.keep_log	# days in seconds
		for path in self._local_dir_path.glob(f'*{config.log_name}'):
			if now - path.stat().st_mtime > keep:
				try:
					path.unlink()
				except:
					Logger.error(f'Unable to delete expired log file {path}')
		for path in self._local_dir_path.glob(f'*{config.tsv_name}'):
			if now - path.stat().st_mtime > keep:
				try:
					path.unlink()
				except:
					Logger.error(f'Unable to delete expired CSV/TSV file {path}')
		self.local_log_path = None

	def add_user_log(self, dir_path):
		'''Add user given file to log'''
		self.local_log_path = dir_path / self._log_name
		self._user_fh = logging.FileHandler(filename=self.local_log_path, mode='w', encoding='utf-8')
		self._user_fh.setFormatter(self._log_formatter)
		self._logger.addHandler(self._user_fh)
		Logger.info(f'Now logging to {self.local_log_path} and {self.user_log_path}')

	def copy_log_into(self, dir_path):
		'''Copy log file into given directory'''
		dir_path.joinpath(self._log_name).write_bytes(self.local_log_path.read_bytes())

	def open_tsv(self):
		'''Open TSV file for writing'''
		self.local_tsv_path = self._local_dir_path / self._tsv_name
		return self.local_tsv_path.open('w', encoding='utf-8')

	def copy_tsv_into(self, dir_path):
		'''Copy TSV file to given directory'''
		dir_path.joinpath(self._tsv_name).write_bytes(self.local_tsv_path.read_bytes())

class Json:
	'''Handle JSON config file'''

	def __init__(self, path):
		'''Read file'''
		self.path = path
		self._keys = list()
		try:
			with self.path.open(encoding='utf-8') as fp:
				for key, value in load(fp).items():
					self._keys.append(key)
					if key.endswith('_path'):
						if value.startswith('~/'):
							value = Path.home() / value[2:]
						elif value.startswith('$HOME/'):
							value = Path.home() / value[6:]
						try:
							self.__dict__[key] = Path(value).resolve()
						except:
							self.__dict__[key] = None
					else:
						self.__dict__[key] = value
		except:
			pass

	def save(self):
		'''Save  file'''
		self.path.parent.mkdir(parents=True, exist_ok=True)
		json = dict()
		for key in self._keys:
			if isinstance(self.__dict__[key], Path):
				json[key] = f'{self.__dict__[key]}'
			else:
				json[key] = self.__dict__[key]
		with self.path.open('w', encoding='utf-8') as fp:
			dump(json, fp)

class Config(Json):
	'''Load configuration file in JSON format'''

	def __init__(self):
		'''Read config file'''
		super().__init__(__parent_path__ / 'config.json')

	def save(self):
		raise AttributeError('Method <save> is no implemented in class <Config>')

class GuiDefs(Json):
	'''Load configuration file in JSON format'''

	def __init__(self):
		'''Read config file'''
		super().__init__(__parent_path__ / 'gui.json')

	def save(self):
		raise AttributeError('Method <save> is not implemented in class <GuiDefs>')

class Settings(Json):
	'''Handle user settings'''

	def __init__(self, config):
		'''Generate object for setting, try to load from JSON file'''
		super().__init__(config.local_path / config.settings_name)
		self._keys = ['src_dir_path', 'dst_dir_path', 'log_dir_path', 'options', 'hashes', 'verify', 'lang']
		attrs = self.__dict__.keys()
		if not 'src_dir_path' in attrs:
			self.src_dir_path = None
		if not 'dst_dir_path' in attrs:
			self.dst_dir_path = None
		if not 'log_dir_path' in attrs:
			self.log_dir_path = None
		if not 'options' in attrs:
			self.options = config.default_options
		if not 'hashes' in attrs:
			self.hashes = config.default_hashes
		if not 'verify' in attrs:
			self.verify = config.default_verify
		if not 'lang' in attrs:
			self.lang = config.default_lang

class Labels(Json):
	'''Load labels file in JSON format'''

	def __init__(self, lang):
		'''Read labels file'''
		super().__init__(__parent_path__ / f'labels_{lang}.json')

	def save(self):
		raise AttributeError('Method <save> is not implemented in class <Labels>')

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
