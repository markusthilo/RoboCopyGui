#!/usr/bin/env python3
# -*- coding: utf-8 -*-

__author__ = 'Markus Thilo'
__version__ = '0.1.0_2025-06-09'
__license__ = 'GPL-3'
__email__ = 'markus.thilomarkus@gmail.com'
__status__ = 'Testing'
__description__ = 'Dialog for Tk to select multiple existing directories and files'

from pathlib import Path
from tkinter import Toplevel
from tkinter.font import nametofont
from tkinter.ttk import Frame, Button, Treeview, Scrollbar
from os import name as __osname__
try:
	from wmi import WMI
except:
	pass
__winsystem__ = __osname__ == 'nt'

class AskPathsWindow(Toplevel):
	'''Filedialog to choose multiple existing directory and file paths'''

	def __init__(self,
			parent = None,
			title = None,
			confirm = None,
			cancel = None,
			restriction = None,
			multiple = True,
			initialdir = None
		):
		'''
		Open application window
		
		parent:			tkinter: parent Tk element / window
		confirm:		str: text on button "Confirm" (None gives "Confirm")
		cancel:			str: text on button "Cancel" (None gives "Cancel")
		restriction:	str / None: "dir" if only directories to select, "file" if only files
						to select, something else or None if both are OK (default)
		multiple:		bool: True if more than one item to select (default is True)
		initialdir:		pathlib.Path/None: directory to focus on open (default is home directory)

		self.selected is a resulting lists of pathlib .Path objects
		'''
		self.selected = list()
		self._root_paths = list()
		if __winsystem__:	# on windows multiple root paths / logical drives are possible
			try:
				self._conn = WMI()
				for volume in self._conn.Win32_LogicalDisk():
					path = Path(f'{volume.DeviceID}\\')
					if path.is_dir():
						self._root_paths.append(path)
			except:
				pass
		if not self._root_paths:
			self._root_paths = [Path(Path.home().anchor)]
		self._restriction = restriction if restriction in ('dir', 'file') else None
		self._multiple = False if multiple is False else True
		if not title:
			title = 'Select '
			if self._restriction == 'dir':
				title += 'directories' if self._multiple else 'directory'
			elif self._restriction == 'file':
				title += 'files' if self._multiple else 'file'
			else:
				title += 'directories and files' if self._multiple else 'directory and file'
		self._focus_path = Path(initialdir).absolute() if initialdir else Path.home()
		self._focus_path = self._focus_path if self._focus_path.exists() else Path.home()
		super().__init__()	### tkinter windows configuration ###
		self.transient(parent)
		self.focus_set()
		self.title(title)
		self.protocol('WM_DELETE_WINDOW', self._cancel)
		self._font = nametofont('TkTextFont').actual()
		min_size_x = self._font['size'] * 32
		min_size_y = self._font['size'] * 24
		self.minsize(min_size_x , min_size_y)
		self.geometry(f'{min_size_x*2}x{min_size_y*2}')
		self.resizable(True, True)
		self.rowconfigure(0, weight=1)
		self.columnconfigure(0, weight=1)
		self._pad = int(self._font['size'] * 0.5)
		frame = Frame(self)
		frame.grid(sticky='nswe', padx=self._pad, pady=self._pad)
		self._tree = Treeview(frame, show='tree', selectmode='extended' if multiple else 'browse')
		self._tree.bind('<Double-Button-1>', self._focus)
		self._tree.bind('<Return>', self._select)
		self._tree.bind('<BackSpace>', self._deselect)
		self._tree.bind('<Delete>', self._deselect)
		self._tree.bind('<Control-a>', self._select_all)
		self._tree.bind('<Control-A>', self._select_all)
		self._tree.bind('<Control-d>', self._deselect_all)
		self._tree.bind('<Control-D>', self._deselect_all)
		self._gen_tree()
		self._tree.pack(side='left', fill='both', expand=True)
		vsb = Scrollbar(frame, orient='vertical', command=self._tree.yview)
		vsb.pack(side='right', fill='y')
		self._tree.configure(yscrollcommand=vsb.set)
		frame = Frame(self)
		frame.grid(row=1, sticky='nswe', padx=self._pad, pady=self._pad)
		Button(frame,
			text = cancel if cancel else 'Cancel',
			command = self._cancel
		).pack(side='right', padx=(self._pad, 0), pady=(0, self._pad))
		Button(frame,
			text = confirm if confirm else 'Confirm',
			command = self._confirm
		).pack(side='right', padx=self._pad, pady=(0, self._pad))

	def _gen_tree(self):
		'''Refresh tree'''
		paths_to_focus = list(self._focus_path.parents)
		paths_to_focus.reverse()
		paths_to_focus.append(self._focus_path)
		for parent_path in [''] + list(reversed(self._focus_path.parents)) + [self._focus_path]:
			dir_paths = set()
			file_paths = set()
			if parent_path:
				try:
					paths = list(parent_path.iterdir())
				except:
					return
			else:
				paths = self._root_paths
			for path in paths:
				if path.is_dir():
					dir_paths.add(path)
				else:
					file_paths.add(path)
			for path in sorted(dir_paths):
				if 	parent_path:	# open folder
					if path in self._focus_path.parents:
						text = f'\U0001F5C1 {path.name}'
						open_tree = True
					elif path == self._focus_path:	# folder in focus
						text = f'\U0001F5C2 {path.name}'
						open_tree = True
					else:	# closed folder
						text = f'\U0001F5C0 {path.name}'
						open_tree = False
				elif __winsystem__:	# drive
					text = f'\U0001F5B4 {path}'.rstrip('\\')
					open_tree = True
				else:	# root
					text = '\U0001F5C1 /'
					open_tree = True
				self._tree.insert(parent_path, 'end', text=text, iid=path, open=open_tree)
			for path in sorted(file_paths):
				self._tree.insert(parent_path, 'end', text=f'\U0001F5C5 {path.name}', iid=path, open=False)

	def _focus(self, event):
		'''Focus to directory'''
		if item := self._tree.identify('item', event.x, event.y):
			path = Path(item)
			if path.is_dir():
				self._focus_path = path
				self._tree.delete(*self._tree.get_children())
				self._gen_tree()
				self._tree.focus(item)

	def _accepted_path(self, item):
		'''Check if path is ok'''
		path = item if isinstance(item, Path) else Path(item)
		if self._restriction == 'dir':
			return path if path.is_dir() else None
		elif self._restriction == 'file':
			return path if path.is_file() else None
		return path if path.exists() else None

	def _filter_to_path(self, items):
		'''Filter items and yield path thar are OK'''
		for item in items:
			if path := self._accepted_path(item):
				yield path

	def _confirm(self):
		'''Select button event'''
		self.selected = list(self._filter_to_path(self._tree.selection()))
		self.destroy()

	def _cancel(self):
		'''Cancel button event'''
		self.selected = list()
		self.destroy()

	def _select(self, dummy):
		'''Select button event'''
		if path := self._accepted_path(self._tree.focus()):
			self._tree.selection_add(path)
		self._confirm()

	def _deselect(self, dummy):
		'''Deselect button event'''
		if item := self._tree.focus():
			self._tree.selection_remove(item)

	def _select_all(self, dummy):
		'''Select all button event'''
		if not self._multiple:
			return
		if item := self._tree.focus():
			try:
				self._tree.selection_add(list(self._filter_to_path(Path(item).parent.iterdir())))
			except:
				return

	def _deselect_all(self, dummy):
		'''Deselect all button event'''
		self._tree.selection_set()

	def get(self):
		'''Return selected paths as list'''
		return self.selected

def askpaths(title=None, confirm=None, cancel=None, restriction=None, multiple=True, initialdir=None):
	'''Function layer for AskPathsWindow'''
	window = AskPathsWindow(
		title = title,
		confirm = confirm,
		restriction = restriction,
		multiple = multiple,
		cancel = cancel,
		initialdir = initialdir
	)
	window.wait_window(window)
	return window.selected