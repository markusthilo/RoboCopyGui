#!/usr/bin/env python3
# -*- coding: utf-8 -*-

__author__ = 'Markus Thilo'
__version__ = '0.0.1_2025-06-09'
__license__ = 'GPL-3'
__email__ = 'markus.thilomarkus@gmail.com'
__status__ = 'Testing'
__description__ = 'Dialog for Tk to select multiple existing directories and files'

from pathlib import Path
from tkinter import Tk, PhotoImage, StringVar, BooleanVar, Checkbutton, Toplevel
from tkinter.font import nametofont
from tkinter.ttk import Frame, Label, Entry, Button, Combobox, Treeview
from tkinter.ttk import Scrollbar, Spinbox, Progressbar
from tkinter.scrolledtext import ScrolledText
from tkinter.messagebox import showerror, askokcancel, askyesno, showwarning
from idlelib.tooltip import Hovertip
try:
	from wmi import WMI
	__winsystem__ = True
except:
	__winsystem__ = False

class AskPathsWindow(Toplevel):
	'''Filedialog to choose multiple existing directory and file paths'''

	def __init__(self, parent, title=None, confirm=None, cancel=None, restriction=None, multiple=True, initialdir=None):
		'''Open application window'''
		self.selected = list()
		if __winsystem__:	# on windows multiple root paths / logical drives are possible
			self._conn = WMI()
			self._root_paths = list()
			for volume in self._conn.Win32_LogicalDisk():
				path = Path(f'{volume.DeviceID}\\')
				if path.is_dir():
					self._root_paths.append(path)
		else:
			self._root_paths = [Path('/')]
		if not title:
			title = ['Select']
			if restriction == 'dir':
				title += 'directories' if multiple else 'directory'
			elif restriction == 'file':
				title += 'files' if multiple else 'file'
			else:
				title += 'directories and files' if multiple else 'directory and file'
		self._restriction = restriction if restriction in ('dir', 'file') else None

		self._focus_path = Path(initialdir).absolute() if initialdir else Path.home()
		self._focus_path = self._focus_path if self._focus_path.exists() else Path.home()
		super().__init__()	### tkinter windows configuration ###
		self.transient(parent)
		self.focus_set()
		self.title(title)
		self.protocol('WM_DELETE_WINDOW', self._cancel)
		self._font = nametofont('TkTextFont').actual()
		min_size_x = self._font['size'] * 64
		min_size_y = self._font['size'] * 48
		self.minsize(min_size_x , min_size_y)
		self.geometry(f'{min_size_x}x{min_size_y}')
		self.resizable(True, True)
		self._pad = int(self._font['size'] * 0.5)
		frame = Frame(self)
		frame.pack(fill='both', expand=True, padx=self._pad, pady=self._pad)
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
		frame.pack(fill='x', padx=self._pad, pady=self._pad)
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
				if 	parent_path:
					if path in self._focus_path.parents:
						text = f'\U0001F5C1 {path.name}'
						open_tree = True
					else:
						text = f'\U0001F5C2 {path.name}'
						open_tree = False
				else:
					text = f'\U0001F5C0 {path}'.rstrip('\\')
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

	def _confirm(self):
		'''Select button event'''
		for item in self._tree.selection():
			path = Path(item)
			if path not in self.selected:
				if self._restriction:
					if self._restriction == 'dir' and path.is_dir():
						self.selected.append(path)
					elif path.is_file():
						self.selected.append(path)
				else:
					self.selected.append(item)
		self.destroy()

	def _cancel(self):
		'''Cancel button event'''
		self.selected = list()
		self.destroy()

	def _select(self, dummy):
		'''Select button event'''
		if item := self._tree.focus():
			self._confirm()

	def _deselect(self, dummy):
		'''Deselect button event'''
		if item := self._tree.focus():
			self._tree.selection_remove(item)

	def _select_all(self, dummy):
		'''Select all button event'''
		if item := self._tree.focus():
			try:
				self._tree.selection_add([path for path in Path(item).parent.iterdir()])
				#self._tree.focus(item)
			except:
				return

	def _deselect_all(self, dummy):
		'''Deselect all button event'''
		self._tree.selection_set()

def askpaths(title=None, confirm=None, cancel=None, restriction=None, multiple=True, initialdir=None):
	'''Function layer for AskPathsWindow'''
	window = AskPathsWindow(None,
		title = title,
		confirm = confirm,
		restriction = None,
		multiple = True,
		cancel = cancel,
		initialdir = initialdir
	)
	window.wait_window(window)
	return window.selected