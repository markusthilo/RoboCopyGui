#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from tkinter.filedialog import askopenfilenames, askdirectory
from tkinter.scrolledtext import ScrolledText
from tkinter.font import nametofont
from .hashes import FileHash
from .guiconfig import GuiConfig
from .guilabeling import HashedCopyLabels
from .guielements import DirSelector, FilenameSelector, OutDirSelector
from .guielements import GridSeparator, GridLabel, NotebookFrame
from .guielements import GridButton, AddJobButton, MissingEntry, Checker

class HashedRoboCopyGui(HashedCopyLabels):
	'''Notebook page'''

	MODULE = 'HashedRoboCopy'

	def __init__(self, root):
		'''Notebook page'''
		self.root = root
		frame = NotebookFrame(self)
		GridLabel(frame, self.SOURCE)
		font = nametofont('TkTextFont').actual()
		self.sources = ScrolledText(
			frame,
			font = (font['family'], font['size']),
			width = GuiConfig.ENTRY_WIDTH,
			height = GuiConfig.JOB_HEIGHT
		)
		self.sources.grid(row=frame.row, column=2, rowspan=2, columnspan=255)
		GridButton(frame, self.ADD_FILES, self._add_files, tip=self.TIP_ADD_FILES)
		GridButton(frame, self.ADD_DIR, self._add_dir, tip=self.TIP_ADD_DIR)
		GridSeparator(frame)
		GridLabel(frame, self.DESTINATION)
		self.destination = DirSelector(
			frame,
			self.root.settings.init_stringvar('Destination'),
			self.DIRECTORY,
			self.SELECT_DESTINATION,
			tip  = self.TIP_DESTINATION
		)
		GridSeparator(frame)
		GridLabel(frame, self.LOGGING)
		self.outdir = OutDirSelector(
			frame,
			self.root.settings.init_stringvar('OutDir'),
			tip = self.TIP_OUTDIR
		)
		self.filename = FilenameSelector(
			frame,
			'{now}_copy',
			self.root.settings.init_stringvar('Filename')
		)
		GridSeparator(frame)
		GridLabel(frame, self.CALCULATE_HASHES)
		self.calc_hashes = [
			(alg, Checker(
				frame,
				self.root.settings.init_boolvar(alg.upper()),
				f'{alg}       ',
				tip = f'{self.TIP_HASHES} {alg}',
				column = (i%8)*2 + 3,
				incrow = i%8 == 7
			))
			for i, alg in enumerate(FileHash.get_algorithms())
		]
		AddJobButton(frame, 'HashedRoboCopy', self._add_job)

	def _add_files(self):
		'''Add source file(s)'''
		filenames = askopenfilenames(title=self.ADD_FILES)
		if filenames:
			for filename in filenames:
				self.sources.insert('end', f'{filename}\n')
			self.sources.yview('end')

	def _add_dir(self):
		'''Add source directory'''
		dir = askdirectory(title=self.ADD_DIR)
		if dir:
			self.sources.insert('end', f'{dir}\n')
			self.sources.yview('end')

	def _add_job(self):
		'''Generate command line'''
		destination = self.destination.get()
		outdir = self.outdir.get()
		filename = self.filename.get()
		if not outdir:
			MissingEntry(self.LOGGING_DIR_REQUIRED)
			return
		sources = ''
		for line in self.sources.get('1.0', 'end').split('\n'):
			path = line.strip()
			if path:
				sources += f' "{line.strip()}"'
		self.sources.delete('1.0', 'end')
		if not sources:
			MissingEntry(self.SOURCE_REQUIRED)
			return
		cmd = f'hashedrobocopy --outdir "{outdir}"'
		if filename:
			cmd += f' --filename "{filename}"'
		if destination:
			cmd += f' --destination "{destination}"'
		hash_algs = [alg for alg, var in self.calc_hashes if var.get()]
		if hash_algs:
			cmd += f' --algorithms {",".join(hash_algs)}'
		else:
			cmd += ' --algorithms none'
		cmd += sources
		self.root.append_job(cmd)
