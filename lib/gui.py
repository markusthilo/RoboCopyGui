#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import logging
from threading import Thread, Event
from pathlib import Path
from tkinter import Tk, PhotoImage, StringVar, BooleanVar
from tkinter.font import nametofont
from tkinter.ttk import Frame, Label, Entry, Button, Combobox
from tkinter.scrolledtext import ScrolledText
from tkinter.messagebox import askyesno, showerror
from tkinter.filedialog import askdirectory, askopenfilenames, asksaveasfilename
from idlelib.tooltip import Hovertip
from lib.hashes import FileHash
#from lib.worker import Worker

class WorkThread(Thread):
	'''Thread that does the work while Tk is running the GUI'''

	def __init__(self, src_paths, dst_path,
		log_path = None,
		echo = print,
		finish = None,
	):
		'''Pass all attributes from GUI to work thread'''
		print(src_paths)
		print(dst_paths)
		finish(None)
		return
		super().__init__()
		self._kill_event = Event()
		self._worker = Worker(gui.app_path, gui.config, gui.labels,
			done = gui.send_done.get(),
			finished = gui.send_finished.get(),
			log = gui.log_path if self._gui.write_log.get() else None,
			trigger = gui.write_trigger.get(),
			echo = gui.echo,
			kill = self._kill_event
		)		

	def run(self):
		'''Run thread'''
		error = False
		for src_path in self._gui.source_paths:
			try:
				self._worker.copy_dir(src_path)
			except Exception as ex:
				logging.error(f'{type(ex)}: {ex}')
				self._gui.echo(f'{type(ex)}: {ex}')
				error = True
		try:
			logging.shutdown()
		except:
			pass
		self._gui.finished(error)

	def kill(self):
		'''Kill thread'''
		self._kill_event.set()

class Gui(Tk):
	'''GUI look and feel'''

	def __init__(self, app_path, version, config, gui_defs, labels):
		'''Open application window'''
		super().__init__()
		self.config = config
		self.labels = labels
		self._defs = gui_defs
		self._work_thread = None
		self.title(f'{self.labels.app_title} v{version}')
		self.rowconfigure(0, weight=1)
		self.columnconfigure(1, weight=1)
		self.rowconfigure(5, weight=1)
		self.iconphoto(True, PhotoImage(file=app_path / self._defs.appicon))
		self.protocol('WM_DELETE_WINDOW', self._quit_app)
		font = nametofont('TkTextFont').actual()
		font_family = font['family']
		font_size = font['size']
		min_size_x = font_size * self._defs.x_factor
		min_size_y = font_size * self._defs.y_factor
		self.minsize(min_size_x , min_size_y)
		self.geometry(f'{min_size_x}x{min_size_y}')
		self.resizable(True, True)
		self._pad = int(font_size * self._defs.pad_factor)
		frame = Frame(self)
		frame.grid(row=0, column=0, sticky='nw')
		self._source_dir_button = Button(frame, text=self.labels.directory, command=self._select_dir)
		self._source_dir_button.pack(anchor='nw', padx=self._pad, pady=self._pad)
		Hovertip(self._source_dir_button, self.labels.source_dir_tip)
		self._source_file_button = Button(frame, text=self.labels.file_s, command=self._select_files)
		self._source_file_button.pack(anchor='nw', padx=self._pad, pady=self._pad)
		Hovertip(self._source_file_button, self.labels.source_file_tip)
		self._source_text = ScrolledText(self, font=(font_family, font_size))
		self._source_text.grid(row=0, column=1, sticky='nsew', ipadx=self._pad, ipady=self._pad, padx=self._pad, pady=self._pad)
		self._destination_button = Button(self, text=self.labels.destination, command=self._select_destination)
		self._destination_button.grid(row=1, column=0, sticky='nw', padx=self._pad, pady=self._pad)
		self._destination = StringVar()
		self._destination_entry = Entry(self, textvariable=self._destination)
		self._destination_entry.grid(row=1, column=1, sticky='nsew', padx=self._pad, pady=self._pad)
		frame = Frame(self)
		frame.grid(row=2, column=1, sticky='nw')
		self.possible_hashes = FileHash.get_algorithms()
		self._choosen_hash = StringVar(value=self.labels.hash)
		self._hash_selector = Combobox(frame, values=self._gen_hash_list(), state='readonly', textvariable=self._choosen_hash)
		self._hash_selector.pack(side='left', anchor='nw', padx=self._pad, pady=self._pad)
		self._hash_selector.bind('<<ComboboxSelected>>', self._hash_event)
		Hovertip(self._hash_selector, self.labels.hash_tip)
		self._choosen_verify = StringVar(value=self.labels.verify)
		self._verify_selector = Combobox(frame, values=self._gen_verify_list(), state='readonly', textvariable=self._choosen_verify)
		self._verify_selector.pack(side='right', anchor='ne', padx=self._pad, pady=self._pad)
		self._verify_selector.bind('<<ComboboxSelected>>', self._verify_event)
		Hovertip(self._verify_selector, self.labels.verify_tip)
		self._log_button = Button(self, text=self.labels.log, command=self._select_log)
		self._log_button.grid(row=3, column=0, sticky='nw', padx=self._pad, pady=self._pad)
		self._log = StringVar(value=self.config.log_dir)
		self._log_entry = Entry(self, textvariable=self._log)
		self._log_entry.grid(row=3, column=1, sticky='nsew', padx=self._pad, pady=self._pad)
		self._simulate_button = Button(self, text=self.labels.simulate_button, command=self._simulate)
		self._simulate_button.grid(row=4, column=0, sticky='w', padx=self._pad, pady=self._pad)
		Hovertip(self._simulate_button, self.labels.simulate_tip)
		self._exec_button = Button(self, text=self.labels.exec_button, command=self._execute)
		self._exec_button.grid(row=4, column=1, sticky='e', padx=self._pad, pady=self._pad)
		Hovertip(self._exec_button, self.labels.exec_tip)
		self._info_text = ScrolledText(self, font=(font_family, font_size), padx=self._pad, pady=self._pad)
		self._info_text.grid(row=5, column=0, columnspan=2, sticky='nsew',
			ipadx=self._pad, ipady=self._pad, padx=self._pad, pady=self._pad)
		self._info_text.bind('<Key>', lambda dummy: 'break')
		self._info_text.configure(state='disabled')
		self._info_fg = self._info_text.cget('foreground')
		self._info_bg = self._info_text.cget('background')
		self._info_newline = True
		self._info_label = Label(self)
		self._info_label.grid(row=6, column=0, sticky='w', padx=self._pad, pady=self._pad)
		self._label_fg = self._info_label.cget('foreground')
		self._label_bg = self._info_label.cget('background')
		self._quit_button = Button(self, text=self.labels.quit, command=self._quit_app)
		self._quit_button.grid(row=6, column=1, sticky='e', padx=self._pad, pady=self._pad)
		self._init_warning()

	def _get_source_paths(self):
		'''Read directory paths from text field'''
		if text := self._source_text.get('1.0', 'end').strip():
			return [Path(source.strip()).absolute() for source in text.split('\n')]

	def _new_source_path(self, string):
		'''Return absolute source path if not already in field'''
		string = string.strip()
		if string:
			new_path = Path(string).absolute()
			old_paths = self._get_source_paths()
			if old_paths and new_path in old_paths:
				return
			return new_path

	def _select_dir(self):
		'''Select directory to add into field'''
		if dir_path := self._new_source_path(askdirectory(title=self.labels.select_dir, mustexist=True)):
			self._source_text.insert('end', f'{dir_path}\n')

	def _select_files(self):
		'''Select file(s) to add into field'''
		filenames = askopenfilenames(title=self.labels.select_files)
		if filenames:
			for filename in filenames:
				if path := self._new_source_path(filename):
					self._source_text.insert('end', f'{path}\n')

	def _select_destination(self):
		'''Select destination directory'''
		if directory := askdirectory(title=self.labels.select_destination, mustexist=False):
			self._destination.set(directory)
	
	def get_destination(self):
		'''Get destination directory'''
		return Path(self._destination.get()).absolute()

	def _gen_hash_list(self):
		'''Generate list of hashes to check'''
		return [
			f'\u2611 {hash}' if hash in self.config.hashes else f'\u2610 {hash}'
			for hash in self.possible_hashes
		]

	def _gen_verify_list(self):
		'''Generate list of verification methodes'''
		return [
			f'\u2611 {self.labels.size}' if self.config.verify == 'size' else f'\u2610 {self.labels.size}'
		] + [
			f'\u2611 {hash}' if self.config.verify == hash else f'\u2610 {hash}'
			for hash in self.config.hashes
		]

	def _hash_event(self, dummy_event):
		'''Hash algorithm selection'''
		choosen = self._choosen_hash.get()[2:]
		self._choosen_hash.set(self.labels.hash)
		if choosen in self.config.hashes:
			self.config.hashes.remove(choosen)
			if choosen == self.config.verify:
				self.config.verify = 'size'
		else:
			self.config.hashes.append(choosen)
			self.config.hashes.sort()
		self._hash_selector['values'] = self._gen_hash_list()
		self._verify_selector['values'] = self._gen_verify_list()

	def _verify_event(self, dummy_event):
		'''Hash algorithm selection'''
		choosen = self._choosen_verify.get()[2:]
		self._choosen_verify.set(self.labels.verify)
		choosen = 'size' if choosen == self.labels.size else choosen
		if choosen == self.config.verify:
			self.config.verify = ''
		else:
			self.config.verify = choosen
		self._verify_selector['values'] = self._gen_verify_list()

	def _select_log(self):
		'''Select directory '''
		if directory := askdirectory(title=self.labels.select_log, mustexist=False):
			self._log.set(directory)
			self.config.log_dir = directory
	
	def get_log_dir(self):
		'''Get log directory'''
		return Path(self._log.get()).absolute()

	def echo(self, *args, end=None):
		'''Write message to info field (ScrolledText)'''
		msg = ' '.join(f'{arg}' for arg in args)
		self._info_text.configure(state='normal')
		if not self._info_newline:
			self._info_text.delete('end-2l', 'end-1l')
		self._info_text.insert('end', f'{msg}\n')
		self._info_text.configure(state='disabled')
		if self._info_newline:
			self._info_text.yview('end')
		self._info_newline = end != '\r'

	#			index = 0
	#		while self.is_alive():
	#			echo('-\\|/'[index], end='\r')
	#			sleep(.25)
	#			index = index + 1 if index < 3 else 0
	#		self.join()

	def _clear_info(self):
		'''Clear info text'''
		self._info_text.configure(state='normal')
		self._info_text.delete('1.0', 'end')
		self._info_text.configure(state='disabled')
		self._info_text.configure(foreground=self._info_fg, background=self._info_bg)
		self._warning_state = 'stop'

	def _start_worker(self, job):
		'''Disable source selection and start worker'''
		src_paths = self._get_source_paths()
		if self.source_paths:
			self._simulate_button.configure(state='disabled')
			self._exec_button.configure(state='disabled')
			self._clear_info()
			self.job = job
			try:
				self._work_thread = WorkThread()
				self._work_thread.start()
			except:
				self.finished(True)

	def _simulate(self):
		'''Run simulation'''
		self._start_worker('simulate')

	def _execute(self):
		'''Start copy process / worker'''
		self._start_worker('execute')

	def _init_warning(self):
		'''Init warning functionality'''
		self._warning_state = 'disabled'
		self._warning()

	def _warning(self):
		'''Show flashing warning'''
		if self._warning_state == 'enable':
			self._info_label.configure(text=self.labels.warning)
			self._warning_state = '1'
		if self._warning_state == '1':
			self._info_label.configure(foreground=self._defs.red_fg, background=self._defs.red_bg)
			self._warning_state = '2'
		elif self._warning_state == '2':
			self._info_label.configure(foreground=self._label_fg, background=self._label_bg)
			self._warning_state = '1'
		elif self._warning_state != 'disabled':
			self._info_label.configure(text= '', foreground=self._label_fg, background=self._label_bg)
			self._warning_state = 'disabled'
		self.after(500, self._warning)

	def finished(self, error):
		'''Run this when worker has finished'''
		if error:
			self._info_text.configure(foreground=self._defs.red_fg, background=self._defs.red_bg)
			self._warning_state = 'enable'
			showerror(title=self.labels.warning, message=self.labels.problems)
		else:
			self._info_text.configure(foreground=self._defs.green_fg, background=self._defs.green_bg)
		self._source_text.configure(state='normal')
		self._source_text.delete('1.0', 'end')
		self._source_button.configure(state='normal')
		self._destination_entry.set('')
		self._exec_button.configure(state='normal')
		self._quit_button.configure(state='normal')
		self._work_thread = None

	def _quit_app(self):
		'''Quit app, ask when copy processs is running'''
		if self._work_thread:
			if not askyesno(title=self.labels.warning, message=self.labels.running_warning):
				return
			self._work_thread.kill()
		try:
			self.config.save()
		except:
			pass
		self.destroy()
