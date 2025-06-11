#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import logging
from sys import executable as __executable__
from pathlib import Path
from time import time, strftime
from os import getpid
from time import strftime, sleep, perf_counter
from datetime import timedelta
from classes_robo import Config, RoboCopy, HashThread, FileHash, Size

__parent_path__ = Path(__file__).parent if Path(__executable__).stem == 'python' else Path(__executable__).parent

class Copy:
	'''Copy files using RoboCopy'''

	def __init__(self, src_paths, dst_path, simulate=False, echo=print, kill=None, finish=None):
		'''Pass arguments to worker'''
		self._config = Config(__parent_path__ / 'config.json')
		self._labels = Config(__parent_path__ / 'labels.json')
		self._time = strftime('%Y-%m-%d_%H%M')
		self._userlog_path = Path(self._config.log_dir, strftime(self._config.log_name))
		self._tsv_path = Path(self._config.log_dir, strftime(self._config.tsv_name))
		self._pid = f'{getpid():08x}'
		self._src_paths = src_paths				# given source paths
		self._dst_path = dst_path.absolute()	# given destination path
		self._simulate = simulate				# True to run robocopy with /l = only list files, do not copy app_path, labels,
		self._echo = echo						# method to show messages (print or from gui)
		self._kill = kill						# event to stop copy process
		self._finish = finish					# callback function to be called after copy
		self._log_dir_path = __parent_path__ / 'logs'	### logging ###
		if self._log_dir_path.exists():
			if self._log_dir_path.is_file():
				raise FileExistsError(f'{self._log_dir_path} is a file')
			else:
				now = time()	# purge logs older 7 days
				for path in self._log_dir_path.glob('*_log.txt'):
					if now - path.stat().st_mtime > 604800:
						try:
							path.unlink()
						except:
							pass
		else:
			self._log_dir_path.mkdir()
		self._log_file_path = self._log_dir_path / f'{self._time}_{self._pid}_log.txt'
		formatter = logging.Formatter('%(asctime)s %(levelname)s: %(message)s', datefmt='%Y-%m-%d %H:%M:%S')
		logger = logging.getLogger()
		logger.setLevel(logging.INFO)
		log_fh = logging.FileHandler(filename=self._log_file_path, mode='w', encoding='utf-8')
		log_fh.setFormatter(formatter)
		logger.addHandler(log_fh)
		if self._config.log_dir:	# additional log file for the user
			userlog_fh = logging.FileHandler(filename=self._userlog_path, mode='w', encoding='utf-8')
			userlog_fh.setFormatter(formatter)
			logger.addHandler(userlog_fh)

	def _verify_by_size(self):
		'''Verify copied files by size'''
		self._info(self._labels.starting_size_verification)
		for cnt, (src_path, src_size, dst_path) in enumerate(self._files, start=1):
			if self._check_kill_signal():
				return True
			self._echo_file_progress(cnt)
			dst_size = Size(dst_path.stat().st_size)
			if dst_size != src_size:
				self._warning(self._labels.mismatching_sizes.replace('#',
					f'{src_path}: {src_size}, {dst_path}: {dst_size}')
				)
				self._bad_files[dst_path] = dst_size
		self._info(self._labels.size_check_finished)

	def _verify_by_hash(self):
		'''Verify copied files by hash'''
		processed_size = Size(0)
		self._info(self._labels.starting_hash_verification)
		for cnt, hash_set in enumerate(self._hash_thread.files, start=1):
			if self._check_kill_signal():
				return True
			self._echo_size_progress(cnt, processed_size)
			dst_hash = FileHash.hashsum(hash_set['dst_path'], algorithm=self._verify)
			if dst_hash != hash_set[self._verify]:
				self._warning(self._labels.mismatching_hashes.replace('#',
					f'{hash_set["src_path"]}: {hash_set[self._verify]}, {hash_set["dst_path"]}: {dst_hash}')
				)
				self._bad_files[dst_path] = dst_hash
			processed_size += hash_set['src_size']

	def _echo_simulation(self, fh=None):
		'''Show what would be copied'''
		self._info(self._labels.starting_simulation)
		for src_path, size, dst_path in self._files:
			if self._check_kill_signal():
				return True
			msg = f'{src_path} ({Size(size)}) \u2192 {dst_path}'
			if dst_path.exists():
				self._echo(f'\u26A0 {msg}, {self._labels.existing}')
				self._bad_files[src_path] = dst_path
			else:
				self._echo(f'\u2713 {msg}')

	def _wait_hashing(self):
		'''Wait for hash thread to finish'''
		index = 0
		while self._hash_thread.is_alive():
			if self._check_kill_signal():
				return True
			self._echo(f'{"|/-\\"[index]}  ', end='\r')
			index += 1
			if index > 3:
				index = 0
			sleep(.25)

	def _write_collisions(self, fh):
		'''Write TSV with possible collisions / files that might be overwritten (simulation)'''
		print('src_path\tsrc_size\tdst_path\tdst_exists', file=fh)
		for src_path, src_size, dst_path in self._files:
			if self._check_kill_signal():
				return True
			line = f'{src_path}\t{src_size}\t{dst_path}\t'
			if src_path in self._bad_files:
				line += 'exists'
			print(line, file=fh)

	def _write_sizes(self, fh):
		'''Write TSV without any verification)'''
		print('src_path\tsrc_size\tdst_path', file=fh)
		for src_path, src_size, dst_path in self._files:
			if self._check_kill_signal():
				return True
			print(f'{src_path}\t{src_size}\t{dst_path}', file=fh)

	def _write_bad_sizes(self, fh):
		'''Write TSV with files that have different sizes (simulation)'''
		print('src_path\tsrc_size\tdst_path\tbad_dst_size', file=fh)
		for src_path, src_size, dst_path in self._files:
			if self._check_kill_signal():
				return True
			line = f'{src_path}\t{src_size}\t{dst_path}\t'
			if src_path in self._bad_files:
				line += f'{self._bad_files[src_path]}'
			print(line, file=fh)

	def _write_hashes(self, fh):
		'''Write TSV with hashes of copied files'''
		print(f'{"\t".join(self._hash_thread.keys)}', file=fh)
		for hash_set in self._hash_thread.files:
			if self._check_kill_signal():
				return True
			print(f'{"\t".join(f'{hash_set[key]}' for key in self._hash_thread.keys)}', file=fh)

	def _write_bad_hashes(self, fh):
		'''Write TSV with hashes and mismathing hashes in destination'''
		print(f'{"\t".join(self._hash_thread.keys)}\tbad_{self._config.verify}', file=fh)
		for cnt, hash_set in enumerate(self._hash_thread.files, start=1):
			if self._check_kill_signal():
				return True
			line = f'{"\t".join(f'{hash_set[key]}' for key in self._hash_thread.keys)}\t'
			if hash_set['src_path'] in self._bad_files:
				line += f'{self._bad_files[hash_set["src_path"]]}'
			print(line, file=fh)

	def _write_hashes_bad_sizes(self, fh):
		'''Write TSV with hashes and mismatching sizes in destination'''
		print(f'{"\t".join(self._hash_thread.keys)}\tbad_dst_size', file=fh)
		for hash_set in self._hash_thread.files:
			if self._check_kill_signal():
				return True
			line = f'{"\t".join(f'{hash_set[key]}' for key in self._hash_thread.keys)}'
			if hash_set['src_path'] in self._bad_files:
				line += f'{self._bad_files[hash_set["src_path"]]}'
			print(line, file=fh)

	def run(self):
		'''Execute copy process (or simulation)'''
		start_time = perf_counter()		### read source structure ###
		src_dir_paths = set()	# given directories to copy
		src_file_paths = set()	# given files to copy
		self._info(self._labels.reading_source)
		for path in self._src_paths:
			src_path = path.absolute()
			if src_path.is_dir():
				src_dir_paths.add(src_path)
			elif src_path.is_file():
				src_file_paths.add(src_path)
			else:
				self._error(self._labels.invalid_path.replace('#', f'{path}'))
		src_dir_paths = list(src_dir_paths)
		src_file_paths = list(src_file_paths)
		self._files = list()	# all files to copy (including subdirectories): (path, size)
		self._total_size = Size(0)	# total size of all files to copy
		for this_src_dir_path in src_dir_paths:
			for path in this_src_dir_path.rglob('*'):
				if self._check_kill_signal():
					return
				if path.is_file():
					size = Size(path.stat().st_size)
					self._files.append((path, size, self._dst_path / path.relative_to(this_src_dir_path.parent)))
					self._total_size += size
		for path in src_file_paths:
			size = Size(path.stat().st_size)
			self._files.append((path, size, self._dst_path / path.name))
			self._total_size += size
		self._info(f'{self._labels.done_reading}: {len(self._files)} {self._labels.files}, {self._total_size}')
		if self._config.hashes:	### start hashing ###
			self._info(self._labels.starting_hashing)
			self._hash_thread = HashThread(self._files, algorithms=self._config.hashes)
			self._hash_thread.start()
		robo_parameters = self._config.robocopy_base_parameters	### robocopy parameters ###
		robo_parameters.extend(self._config.options)
		if self._simulate:	### add /l parameter for simulation
			robo_parameters.append('/l')
		for src_path in src_dir_paths:	### copy directories ###
			dst_path = self._dst_path / src_path.name
			robocopy = RoboCopy(src_path, dst_path, parameters=robo_parameters)
			self._info(self._labels.executing.replace('#', f'{robocopy}'))
			returncode = robocopy.run(echo=self._echo, kill=self._kill)
			if self._check_kill_signal():
				return
			if returncode >= 8:
				self._error(self._labels.robocopy_error.replace('#', f'{returncode}'))
		for src_path in src_file_paths:	### copy files ###
			robocopy = RoboCopy(src_path.parent, self._dst_path, file=src_path.name, parameters=robo_parameters)
			self._info(self._labels.executing.replace('#', f'{robocopy}'))
			returncode = robocopy.run(echo=self._echo, kill=self._kill)
			if self._check_kill_signal():
				return
			if returncode >= 8:
				self._error(self._labels.robocopy_error.replace('#', f'{returncode}'))
		self._info(self._labels.robocopy_finished)
		self._total_files = len(self._files)	### post robocopy, hashing might run in parallel ###
		self._bad_files = dict()
		if self._simulate:	### simulation ###
			if self._echo_simulation():
				return
		elif self._config.verify == 'size':	### check sizes but not hen simulating ###
			if self._verify_by_size():
				return
		if self._config.hashes:	### wait until hashing is finished ###
			if self._hash_thread.is_alive():
				self._info(self._labels.hashing_in_progress)
				if self._wait_hashing():
					return
			self._info(self._labels.hashing_finished)
		if self._config.log_dir:	### write tsv file when log dir is given ###
			with self._tsv_path.open('w', encoding='utf-8') as fh:
				if self._config.verify:
					if self._config.verify == 'size':
						if self._config.hashes:
							if self._write_hashes_bad_sizes(fh):
								return
						else:
							if self._write_bad_sizes(fh):
								return
					else:
						if self._write_bad_hashes(fh):
							return
				elif self._config.hashes:
					if self._write_hashes(fh):
						return
				else:
					if self._write_sizes(fh):
						return
		end_time = perf_counter()
		delta = end_time - start_time
		self._info(self._labels.all_done.replace('#', f'{timedelta(seconds=delta)}'))
		if warnings:= len(self._bad_files):
			returncode = self._labels.warnings_occured.replace('#', f'{warnings}')
			self._warning(returncode)
		else:
			returncode = True
		logging.shutdown()
		return returncode

	def _info(self, msg):
		'''Log info and echo message'''
		logging.info(msg)
		self._echo(msg)

	def _warning(self, msg):
		'''Log and echo warning'''
		logging.warning(msg)
		self._echo( f'{self._labels.warning}: msg')

	def _error(self, msg):
		'''Log and echo error'''
		logging.error(msg)
		logging.shutdown()
		returncode = f'{self._labels.error}: msg'
		self._echo(returncode)
		return returncode

	def _check_kill_signal(self):
		'''Check if kill signal is set'''
		if self._kill and self._kill.is_set():
			self._info(self._labels.aborting_by_user)
			logging.shutdown()
			return True
		return False

	def	_echo_file_progress(self, processed_files):
		'''Show progress while processing files, percentage by nimber of files'''
		self._echo(f'{processed_files} {self._labels.of} {self._total_files}, {processed_files * 100 // self._total_files} %', end='\r')

	def	_echo_size_progress(self, processed_files, processed_size):
		'''Show progress while processing files, percentage by size'''
		msg = f'{processed_files} {self._labels.of} {self._total_files}, {processed_size} {self._labels.of} {self._total_bytes}'
		msg += f', {processed_bytes % total_bytes}'
		self._echo(msg, end='\r')

