#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import logging
from pathlib import Path
from time import strftime, sleep, perf_counter
from datetime import timedelta
#from lib.robocopy import RoboCopy
from lib.hash import HashThread
from lib.size import Size

class Copy:
	'''Copy files using RoboCopy'''

	def __init__(self, src_paths, dst_path, app_path, labels,
		echo=print, tsv_path=None, log_path=None, hashes=None, verify=None, simulate=False, kill=None
	):
		'''Create object'''
		self._src_paths = src_paths
		self._dst_paths = dst_path
		self._app_path = app_path
		self._labels = labels
		self._echo = echo
		self._tsv_path = tsv_path
		self._log_path = log_path
		self._hashes = hashes
		self._verify = verify
		self._simulate = simulate
		self._kill = kill if kill else lambda: False

	def run(self):
		'''Execute copy process (or simulation)'''

		### DEBUG ###
		self._echo('self._src_paths', self._src_paths)
		for e in self.__dict__.items():
			print(e)
		#############

		try:
			logger = logging.getLogger()
			logger.setLevel(logging.DEBUG)
			formatter = logging.Formatter('%(asctime)s %(levelname)s: %(message)s', datefmt='%Y-%m-%d %H:%M:%S')
			lastlog_fh = logging.FileHandler(filename=self._app_path/'lastlog', mode='w')
			lastlog_fh.setFormatter(formatter)
			logger.addHandler(lastlog_fh)
			if self._log_path:
				self._log_path.parent.mkdir(parents=True, exist_ok=True)
				userlog_fh = logging.FileHandler(filename=self._log_path, mode='w')
				userlog_fh.setFormatter(formatter)
				logger.addHandler(userlog_fh)

			#self._robocopy = RoboCopy()	##### DEBUG #####

		except Exception as ex:
			self._exception(ex)
			try:
				logging.shutdown()
			except:
				pass
			raise ex
		start_time = perf_counter()
		self._src_dir_paths = set()
		self._src_file_paths = set()
		for path in self._src_paths:
			if path.is_dir():
				self._src_dir_paths.add(path.resolve())
			elif path.is_file():
				self._src_file_paths.add(path.resolve())
			else:
				msg = self._labels.invalid_path.replace('#', '{path}')
				logging.error(msg)
				self._echo(msg)
				raise FileNotFoundError(msg)

		### DEBUG ###
		for path in self._src_dir_paths:
			print(path)
		for path in self._src_file_paths:
			print(path)
		#############
		
	
		logging.info(f'{self._mail_address} -> {self._config.destination}')
		self._info(f'{self._labels.reading_structure} {src_path}')
		src_file_paths = list()
		src_file_sizes = list()
		total_bytes = 0
		for path in src_path.rglob('*'):	# analyze root structure
			if path.is_file():
				size = path.stat().st_size
				src_file_paths.append(path)
				src_file_sizes.append(size)
				total_bytes += size
		hash_thread = HashThread(src_file_paths)
		self._info(self._labels.starting_hashing.replace('#', f'{len(src_file_paths)}'))
		hash_thread.start()
		dst_path = Path(self._config.target, src_path.name)
		self._info(f'{self._labels.starting_robocopy}: {src_path} -> {dst_path}, {Size(total_bytes).readable()}')
		for line in self._robocopy.copy_dir(src_path, dst_path):
			if line.endswith('%'):
				self._echo(line, end='\r')
			else:
				self._echo(line)
			if self._kill_switch and self._kill_switch.is_set():
				self._robocopy.terminate()
				raise SystemExit(self._labels.worker_killed)
		if self._robocopy.returncode > 5:
			raise ChildProcessError(self._labels.robocopy_problem.replace('#', f'{self._robocopy.returncode}'))
		self._info(self._labels.robocopy_finished)
		mismatches = 0
		total = len(src_file_paths)
		for cnt, (src_file_path, src_size) in enumerate(zip(src_file_paths, src_file_sizes), start=1):
			self._echo(f'{int(100*cnt/total)}%', end='\r')
			dst_file_path = dst_path.joinpath(src_file_path.relative_to(src_path))
			dst_size = dst_file_path.stat().st_size
			if dst_size != src_size:
				msg = self._labels.mismatching_sizes.replace('#', f'{src_file_path} => {src_size}, {dst_file_path} => {dst_size}')
				logging.warning(msg)
				self._echo(msg)
				mismatches += 1
		self._info(self._labels.size_check_finished)
		if hash_thread.is_alive():
			self._info(self._labels.hashing_in_progress)
			index = 0
			while hash_thread.is_alive():
				echo(f'{"|/-\\"[index]}  ', end='\r')
				index += 1
				if index > 3:
					index = 0
				sleep(.25)
		hash_thread.join()
		self._info(self._labels.hashing_finished)
		tsv = self._config.tsv_head
		for path, md5 in hash_thread.get_hashes():
			tsv += f'\n{path.relative_to(src_path.parent)}\t{md5}'
		try:
			log_tsv_path.write_text(tsv, encoding='utf-8')
		except Exception as ex:
			self._error(ex)
		if mismatches:
			raise BytesWarning(self._labels.size_mismatch.replace('#', f'{mismatches}'))
		if self._write_trigger:
			dst_path.joinpath(self._config.tsv_name).write_text(
				tsv, encoding='utf-8'
			)
		if self._send_done:
			dst_path.joinpath(self._config.done_name).write_text(
				self._mail_address, encoding='utf-8'
			)
		if self._send_finished:
			JsonMail(self._app_path / 'mail.json').send(
				Path(self._config.mail),
				to = self._mail_address,
				subject = src_path.name,
				body = tsv
			)
		end_time = perf_counter()
		delta = end_time - start_time
		self._info(self._labels.copy_finished.replace('#', f'{timedelta(seconds=delta)}'))
		logger.removeHandler(remote_log_fh)




	def _info(self, msg):
		'''Log info and echo message'''
		logging.info(msg)
		self._echo(msg)

	def _exception(self, ex):
		'''Log and echo error'''
		msg = f'{type(ex)}: {ex}'
		logging.error(msg)
		self._echo(msg)


class OldHashedRoboCopy:
	'''Tool to copy files using RoboCopy and build hashes'''

	@staticmethod
	def _relative_to_anchor(path):
		'''Convert drive or network path to name'''
		anchor = f'{path.anchor}'
		anchor = f'Drive_{anchor[0].upper()}' if anchor[1] == ':' else anchor.replace("\\", "_").replace("/", "_").replace(":", "_").strip("_")
		return Path(anchor) / path.relative_to(path.anchor)

	def __init__(self, echo=print):
		'''Create object'''
		self.robocopy_path = Path(environ['SYSTEMDRIVE'])/'\\Windows\\system32\\Robocopy.exe'
		if self.robocopy_path.is_file():
			self.available = True
			self.echo = echo
		else:
			self.available = False

	def _log_robocopy(self, returncode):
		'''Log robocopy returncode'''
		if returncode > 3:
			self.log.warning(f'Robocopy.exe gave returncode {returncode}')
			self.warnings += 1
		else:
			self.log.info(f'Robocopy.exe finished with returncode {returncode}', echo=True)

	def copy(self, sources, destination=None, filename=None, outdir=None, hashes=['md5'], log=None):
		'''Copy multiple sources'''
		available_algs = FileHash.get_algorithms()
		self.hash_algs = None if not hashes or 'none' in hashes else [alg for alg in hashes if alg in available_algs]
		self.filename = TimeStamp.now_or(filename)
		self.outdir = PathUtils.mkdir(outdir)
		self.tsv_path = self.outdir / f'{self.filename}_listing.tsv'
		self.log = log if log else Logger(
			filename=self.filename, outdir=self.outdir, head='hashedrobocopy.HashedRoboCopy', echo=self.echo)
		self.warnings = 0
		src_files = set()
		src_dirs = set()
		for source in sources:
			abs_path = Path(source).absolute()
			if abs_path.is_file():
				src_files.add(abs_path)
			elif abs_path.is_dir():
				src_dirs.add(abs_path)
			elif abs_path.exists():
				self.log.warning(f'Source {abs_path} is neither a file nor a directory')
			else:
				self.log.error(f'Source {abs_path} does not exist')
		if destination:
			self.destination = Path(destination).absolute()
			if self.destination.exists() and not self.destination.is_dir():
				self.log.error('Destination {self.destination} exits and is not a directory')
		else:
			if not hashes:
				self.log.error('No destination specified and no hashes to calculate')
			self.destination = None
		self.dirs = list(src_dirs)
		self.files = list()
		self.total_bytes = 0
		for path in src_files:
			size = path.stat().st_size
			self.files.append((path, path.relative_to(path.parent), size))
			self.total_bytes += size
		for dir_path in src_dirs:
			_relative = self._relative_to_anchor if dir_path == dir_path.parent else lambda path: path.relative_to(dir_path.parent)
			for path in dir_path.rglob('*'):
				if path.is_file():
					size = path.stat().st_size
					self.files.append((path, _relative(path), size))
					self.total_bytes += size
				elif path.is_dir():
					self.dirs.append(path)
				else:
					self.log.warning(f'{path} is neither a file nor a directory and will be ignored')
		if self.hash_algs:
			self.log.info(f'Start calculating hashe(s) for {len(self.files)} file(s)', echo=True)
			hash_thread = HashThread((tpl[0] for tpl in self.files), algorithms=self.hash_algs)
			hash_thread.start()
		if self.destination:
			for src_path in src_dirs:
				if src_path == src_path.parent:
					dst_path = self.destination / self._relative_to_anchor(src_path)
					dst_path.mkdir(exist_ok=True)
				else:
					dst_path = self.destination / src_path.name
				self.log.info(f'Using Robocopy.exe to copy entire directory {src_path} recursivly into {self.destination}', echo=True)
				robocopy = RoboCopy(src_path, dst_path, '/e')
				self._log_robocopy(robocopy.wait(echo=self.echo))
			for src_path in src_files:
				self.log.info(f'Using Robocopy.exe to copy file {src_path} into {self.destination}', echo=True)
				robocopy = RoboCopy(src_path.parent, self.destination, src_path.name)
				self._log_robocopy(robocopy.wait(echo=self.echo))
		head = 'Source\tType/File Size'
		if self.hash_algs:
			self.hashes = hash_thread.wait(echo=self.echo)
			head += f'\t{"\t".join(self.hash_algs)}'
			cols2add = '\t-' * len(self.hash_algs)
		else:
			cols2add = ''
		with self.tsv_path.open('w', encoding='utf-8') as fh:
			print(head, file=fh)
			for path in self.dirs:
				print(f'{path}\tdirectory{cols2add}', file=fh)
			if self.hash_algs:
				for (src_path, rel_path, size), hashes in zip(self.files, self.hashes):
					line = f'{src_path}\t{size}'
					for hash in hashes:
						line += f'\t{hash}'
					print(line, file=fh)
			else:
				for src_path, rel_path, size in self.files:
					print(f'{src_path}\t{size}', file=fh)
		if self.destination:
			for src_path, rel_path, size in self.files:
				dst_path = self.destination / rel_path
				print(dst_path)
				dst_size = dst_path.stat().st_size
				if dst_size != size:
					self.log.warning(f'File size of {dst_path} differs from source {src_path} ({dst_size} / {size})')
			self.log.info(f'Done, paths are listed in {self.tsv_path}', echo=True)
		if self.warnings:
			self.log.warning(f'{self.warnings} warning(s) were thrown, check {self.log.path}')
		else:
			self.log.info('Finished without errors', echo=True)


