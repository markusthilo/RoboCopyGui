#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from subprocess import Popen, PIPE, STDOUT, STARTUPINFO, STARTF_USESHOWWINDOW
from pathlib import Path

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

