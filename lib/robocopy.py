#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from subprocess import Popen, PIPE, STDOUT, STARTUPINFO, STARTF_USESHOWWINDOW
from pathlib import Path

class RoboCopy:
	'''Wrapper for RoboCopy'''

	CMD = 'robocopy'

	def __init__(self):
		'''Prepare RoboCopy arguments'''
		self._args = ['/fp', '/ns', '/njh', '/njs', '/nc']
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

	def mk_cmd(self, src, dst, file=None, simulate=False):
		'''Create command line for RoboCopy'''
		self._cmd = [self.CMD, src, dst]
		if file:
			self._cmd.append(Path(file))
		else:
			self._cmd.append('/e')
		self._cmd.extend(self._args)
		if simulate:
			self._cmd.append('/l')
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

	def run(self, kill=None):
		'''Run RoboCopy and yield stdout'''
		for line in self.popen().stdout:
			if kill and kill.is_set():
				self.process.terminate()
				raise SystemExit('Kill signal')
			if stripped := line.strip():
				yield stripped
		self.returncode = self.process.wait()

	def wait(self, kill=None, echo=print):
		'''Run RoboCopy and yield progress '''
		for line in self.run(kill=kill):
			if line.endswith('%'):
				echo(line, end='\r')
			else:
				echo(line)
		return self.returncode

