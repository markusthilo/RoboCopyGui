#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import logging
from pathlib import Path
from time import strftime, sleep, perf_counter
from datetime import timedelta
from lib.robocopy import RoboCopy
from lib.hashes import HashThread, FileHash
from lib.size import Size

class Copy:
	'''Copy files using RoboCopy'''

	def __init__(self, src_paths, dst_path, app_path, labels,
		tsv_path=None, log_path=None, hashes=None, verify=None, simulate=False, echo=print, kill=None
	):
		'''Create object'''
		self._src_paths = src_paths			# given source paths
		self._dst_path = dst_path.resolve()	# given destination path
		self._app_path = app_path			# root directory of robocopygui.py or robocopygui.exe
		self._labels = labels				# phrases for logging etc. ("language package")
		self._tsv_path = tsv_path			# path to write file list (None will prevent writing one)
		self._log_path = log_path			# path to additional log (given by user, None will only write lastlog in app folder)
		self._hashes = hashes				# list of hash algorithms to be calculated
		self._verify = verify				# algorithm or method to compare files in source and destination
		self._simulate = simulate			# True to run robocopy with /l = only list files, do not copy
		self._echo = echo					# method to show messages (print or from gui)
		self._kill = kill					# event to stop copy process

	def run(self):
		'''Execute copy process (or simulation)'''
		try:	### start logging ###
			formatter = logging.Formatter('%(asctime)s %(levelname)s: %(message)s', datefmt='%Y-%m-%d %H:%M:%S')
			logger = logging.getLogger()
			logger.setLevel(logging.INFO)
			lastlog_fh = logging.FileHandler(filename=self._app_path/'lastlog.txt', mode='w', encoding='utf-8')
			lastlog_fh.setFormatter(formatter)
			logger.addHandler(lastlog_fh)
			if self._log_path:	# additional log file for the user
				userlog_fh = logging.FileHandler(filename=self._log_path, mode='w', encoding='utf-8')
				userlog_fh.setFormatter(formatter)
				logger.addHandler(userlog_fh)
			self._robocopy = RoboCopy()
		except Exception as ex:
			self._abort(ex)
		start_time = perf_counter()		### read source structure ###
		src_dir_paths = set()	# given directories to copy
		src_file_paths = set()	# given files to copy
		self._info(self._labels.reading_source)
		for path in self._src_paths:
			src_path = path.resolve()
			if src_path.is_dir():
				src_dir_paths.add(src_path)
			elif src_path.is_file():
				src_file_paths.add(src_path)
			else:
				msg = self._labels.invalid_path.replace('#', '{path}')
				logging.error(msg)
				self._echo(msg)
				raise FileNotFoundError(msg)
		src_dir_paths = list(src_dir_paths)
		src_file_paths = list(src_file_paths)
		files = list()	# all files to copy (including subdirectories): (path, size)
		total_bytes = Size(0)	# total size of all files to copy
		for this_src_dir_path in src_dir_paths:
			for path in this_src_dir_path.rglob('*'):
				if path.is_file():
					size = path.stat().st_size
					files.append((path, size, self._dst_path / path.relative_to(this_src_dir_path.parent)))
					total_bytes += size
		for path in src_file_paths:
			size = path.stat().st_size
			files.append((path, size, self._dst_path / path.name))
			total_bytes += size
		self._info(f'{self._labels.done_reading}: {len(files)} {self._labels.file_s}, {total_bytes.readable()}')
		if self._simulate:	### sumilating copy process ###
			self._info(self._labels.starting_simulation)
			collisions = list()
			for src_path, size, dst_path in files:
				msg = f'{src_path} ({Size(size).readable()}) -> {dst_path}'
				if dst_path.exists():
					self._echo(f'{msg} {self._labels.existing}')
					collisions.append((src_path, size, dst_path), True)
				else:
					self._echo(msg)
					collisions.append((src_path, size, dst_path), False)
				if self._kill and self._kill.is_set():
					self._echo(self._labels.simulation_aborted)
					logging.shutdown()
					return
			####################################################
			### write file list to tsv file if requested ###
			if self._tsv_path:
				try:
					with open(self._tsv_path, 'w', encoding='utf-8') as tsv_fh:
						for src_path, size, dst_path in files:
							tsv_fh.write(f'{src_path}\t{size}\t{dst_path}\n')
				except Exception as ex:
					self._abort(ex)
			####################################################
			self._info(self._labels.simulation_finished)
			logging.shutdown()
			return
		if self._hashes:	### start hashing ###
			self._info(self._labels.starting_hashing)
			hash_thread = HashThread(files, algorithms=self._hashes)
			hash_thread.start()
		for src_path in src_dir_paths:	### copy directories ###
			dst_path = self._dst_path / src_path.name
			self._info(self._labels.executing.replace('#',
				f'{self._robocopy.mk_cmd(src_path, dst_path)}')
			)
			self._robocopy.popen()
			for line in self._robocopy.run(kill=self._kill):
				if line.endswith('%'):
					self._echo(line, end='\r')
				else:
					self._echo(line)
			self._chck_returncode(self._robocopy.returncode)
		for src_path in src_file_paths:	### copy files ###
			self._info(self._labels.executing.replace('#',
				f'{self._robocopy.mk_cmd(src_path.parent, self._dst_path, file=src_path.name)}')
			)
			self._robocopy.popen()
			for line in self._robocopy.run(kill=self._kill):
				if line.endswith('%'):
					self._echo(line, end='\r')
				else:
					self._echo(line)
			self._chck_returncode(self._robocopy.returncode)
		self._info(self._labels.robocopy_finished)
		total_files = len(files)
		mismatches = 0
		bad_dst_file_paths = dict()
		if self._verify == 'size':	### verify files by size ###
			self._echo_file_progress(total_files, total_files)
			self._info(self._labels.starting_size_verification)
			for cnt, (src_path, src_size, dst_path) in enumerate(files, start=1):
				self._echo_file_progress(total_files, cnt)
				dst_size = dst_path.stat().st_size
				if dst_size != src_size:
					self._warning(self._labels.mismatching_sizes.replace('#',
						f'{src_path}: {src_size} byte(s), {dst_path}: {dst_size} bytes(s)')
					)
					mismatches += 1
					bad_dst_file_paths[dst_path] = dst_size
			self._info(self._labels.size_check_finished)
			if not self._hashes:
				with self._tsv_path.open('w', encoding='utf-8') as fh:
					print('src_path\tsrc_size\tdst_path\tbad_dst_size', file=fh)
					for src_path, src_size, dst_path in files:
						bad_dst_size = bad_dst_file_paths[dst_path] if dst_path in bad_dst_file_paths else ''
						print(f'{src_path}\t{src_size}\t{dst_path}\t{bad_dst_size}', file=fh)
		if self._hashes:	### wait until hashing is finished ###
			self._info(self._labels.waiting_for_hashing)
			if hash_thread.is_alive():
				self._info(self._labels.hashing_in_progress)
				index = 0
				while hash_thread.is_alive():
					self._echo(f'{"|/-\\"[index]}  ', end='\r')
					index += 1
					if index > 3:
						index = 0
					sleep(.25)
			self._info(self._labels.hashing_finished)
		if self._verify and self._verify != 'size':	### verify by hash value ###
			bad_dst_hash = ''
			self._info(self._labels.starting_hash_verification)
			with self._tsv_path.open('w', encoding='utf-8') as fh:
				print(f'{"\t".join(hash_thread.keys)}\tbad_{self._verify}', file=fh)
				for cnt, hash_set in enumerate(hash_thread.files, start=1):
					self._echo_file_progress(total_files, cnt)
					dst_hash = FileHash.hashsum(hash_set['dst_path'], algorithm=self._verify)
					if dst_hash != hash_set[self._verify]:
						self._warning(self._labels.mismatching_hashes.replace('#',
							f'{hash_set["src_path"]}: {hash_set[self._verify]}, {hash_set["dst_path"]}: {dst_hash}')
						)
						mismatches += 1
						bad_dst_hash = dst_hash
					else:
						bad_dst_hash = ''
					print(f'{"\t".join(f'{hash_set[key]}' for key in hash_thread.keys)}\t{bad_dst_hash}', file=fh)
			self._info(self._labels.hash_check_finished.replace('#', f'{self._verify}'))
		if not self._verify and self._hashes:	### write simple tsv file without hashes ### 
			with self._tsv_path.open('w', encoding='utf-8') as fh:
				print(f'{"\t".join(hash_thread.keys)}', file=fh)
				for cnt, hash_set in enumerate(hash_thread.files, start=1):
					self._echo_file_progress(total_files, cnt)
					print(f'{"\t".join(f'{hash_set[key]}' for key in hash_thread.keys)}', file=fh)
		end_time = perf_counter()
		delta = end_time - start_time
		self._info(self._labels.copy_finished.replace('#', f'{timedelta(seconds=delta)}'))
		logging.shutdown()
		return 'error' if mismatches else 'green'

	def _info(self, msg):
		'''Log info and echo message'''
		logging.info(msg)
		self._echo(msg)

	def _decode_exception(self, arg):
		'''Decode exception'''
		return f'{type(arg)}: {arg}' if isinstance(arg, Exception) else str(arg)

	def _warning(self, arg):
		'''Log and echo warning'''
		msg = self._decode_exception(arg)
		logging.warning(msg)
		self._echo(msg)

	def _error(self, arg):
		'''Log and echo error'''
		msg = self._decode_exception(arg)
		logging.error(msg)
		self._echo(msg)

	def _abort(self, ex):
		'''Abort on error / exception'''
		self._error(ex)
		try:
			logging.shutdown()
		except:
			pass
		raise ex

	def _chck_returncode(self, returncode):
		if returncode > 5:
			ex = ChildProcessError(self._labels.robocopy_problem.replace('#', f'{returncode}'))
			self._error(ex)
			raise ex

	def	_echo_file_progress(self, total, this):
		'''Show progress of processing files'''
		self._echo(f'{this} {self._labels.of_files.replace("#", 'f{total}')}, {int(100*this/total)}%', end='\r')
