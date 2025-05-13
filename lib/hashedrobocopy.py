#!/usr/bin/env python3
# -*- coding: utf-8 -*-

__app_name__ = 'HashedRoboCopy'
__author__ = 'Markus Thilo'
__version__ = '0.6.0_2025-03-30'
__license__ = 'GPL-3'
__email__ = 'markus.thilo@gmail.com'
__status__ = 'Testing'
__description__ = '''
Use RoboCopy and buld hashes of the source.
'''

from os import environ
from pathlib import Path
from argparse import ArgumentParser
from lib.pathutils import PathUtils
from lib.timestamp import TimeStamp
from lib.logger import Logger
from lib.hashes import FileHash, HashThread
from lib.winutils import RoboCopy

class HashedRoboCopy:
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

class HashedRoboCopyCli(ArgumentParser):
	'''CLI for the copy tool'''

	def __init__(self, echo=print):
		'''Define CLI using argparser'''
		super().__init__(description=__description__.strip(), prog=__app_name__.lower())
		self.add_argument('-a', '--algorithms',
			help=f'''Algorithms to hash seperated by colon (e.g. "md5,sha256", no hashing: "none", default: "md5",
available algorithms: {', '.join(FileHash.get_algorithms())})''', metavar='STRING'
		)
		self.add_argument('-d', '--destination', type=Path,
			help='Destination root (only calculate hashes if no destination is given)', metavar='DIRECTORY'
		)
		self.add_argument('-f', '--filename', type=str,
			help='Filename to generate for log and file list (without extension)', metavar='STRING'
		)
		self.add_argument('-o', '--outdir', type=Path,
			help='Directory to write log and file list (default: current)', metavar='DIRECTORY'
		)
		self.add_argument('sources', nargs='+', type=Path,
			help='Source files or directories to copy', metavar='FILE/DIRECTORY'
		)
		self.echo = echo

	def parse(self, *cmd):
		'''Parse arguments'''
		args = super().parse_args(*cmd)
		self.sources = args.sources
		self.algorithms = FileHash.parse_algorithms(args.algorithms)
		self.destination = args.destination
		self.filename = args.filename
		self.outdir = args.outdir

	def run(self):
		'''Run the tool'''
		hrc = HashedRoboCopy(echo=self.echo)
		hrc.copy(self.sources,
			destination = self.destination,
			filename = self.filename,
			outdir = self.outdir,
			hashes = self.algorithms
		)
		hrc.log.close()

if __name__ == '__main__':	# start here if called as application
	app = HashedRoboCopyCli()
	app.parse()
	app.run()
