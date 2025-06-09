#!/usr/bin/env python3
# -*- coding: utf-8 -*-

__application__ = 'RoboCopyGui'
__author__ = 'Markus Thilo'
__version__ = '0.2.0_2025-06-09'
__license__ = 'GPL-3'
__email__ = 'markus.thilomarkus@gmail.com'
__status__ = 'Testing'
__description__ = 'Graphical user interface for RoboCopy with hash and verify options'

from sys import executable as __executable__
from pathlib import Path
from threading import Thread, Event
#from ctypes import windll
from subprocess import run
from tkinter import Tk, PhotoImage, StringVar, BooleanVar, Checkbutton
from tkinter.font import nametofont
from tkinter.ttk import Frame, Label, Entry, Button, Combobox
from tkinter.ttk import Scrollbar, Spinbox, Progressbar
from tkinter.scrolledtext import ScrolledText
from tkinter.filedialog import askopenfilenames, askdirectory
from tkinter.messagebox import showerror, askokcancel, askyesno, showwarning
from idlelib.tooltip import Hovertip
#from worker import Copy
from classes_robo import Config, FileHash
from tk_pathdialog import askpaths

__parent_path__ = Path(__file__).parent if Path(__executable__).stem == 'python' else Path(__executable__).parent

class WorkThread(Thread):
	'''The worker has tu run as thread not to freeze GUI/Tk'''

	def __init__(self, target_id, echo, finish):
		'''Pass arguments to worker'''
		super().__init__()
		self._finish = finish
		self._kill_event = Event()
		self._worker = Copy(src_paths, dst_path, echo=echo, kill=self._kill_event, finish=self._finish)

	def kill(self):
		'''Kill thread'''
		self._kill_event.set()

	def kill_is_set(self):
		'''Return True if kill event is set'''
		return self._kill_event.is_set()

	def run(self):
		'''Run thread'''
		try:
			returncode = self._worker.run()
		except Exception as ex:
			returncode = ex
		if self.kill_is_set():
			returncode = 'killed'
		self._finish(returncode)

class Gui(Tk):
	'''GUI look and feel'''

	def __init__(self):
		'''Open application window'''
		super().__init__()
		self._defs = Config(__parent_path__ / 'gui.json')
		self._labels = Config(__parent_path__ / 'labels.json')
		self._config = Config(__parent_path__ / 'config.json')
		self._config.application = __application__
		self._config.version = __version__
		self._work_thread = None
		self.title(f'{__application__} v{__version__}')	### define the gui ###
		for row, weight in enumerate(self._defs.row_weights):
			self.rowconfigure(row, weight=weight)
		for column, weight in enumerate(self._defs.column_weights):
			self.columnconfigure(column, weight=weight)
		self.iconphoto(True, PhotoImage(file=__parent_path__ / 'appicon.png'))
		self.protocol('WM_DELETE_WINDOW', self._quit_app)
		self._font = nametofont('TkTextFont').actual()
		min_size_x = self._font['size'] * self._defs.x_factor
		min_size_y = self._font['size'] * self._defs.y_factor
		self.minsize(min_size_x , min_size_y)
		self.geometry(f'{min_size_x}x{min_size_y}')
		self.resizable(True, True)
		self._pad = int(self._font['size'] * self._defs.pad_factor)
		frame = Frame(self)	### source selector
		frame.grid(row=0, column=0, sticky='nw')
		self._source_dir_button = Button(frame, text=self._labels.directory, command=self._select_source_dir)	# source dir button #
		self._source_dir_button.pack(anchor='nw', padx=self._pad, pady=self._pad)
		Hovertip(self._source_dir_button, self._labels.source_dir_tip)
		self._source_files_button = Button(frame, text=self._labels.files, command=self._select_source_files)	# souce file button
		self._source_files_button.pack(anchor='nw', padx=self._pad, pady=self._pad)
		Hovertip(self._source_files_button, self._labels.source_files_tip)

		self._source_multiple_button = Button(frame, text=self._labels.multiple, command=self._select_multiple)	# multiple button #
		self._source_multiple_button.pack(anchor='nw', padx=self._pad, pady=self._pad)
		Hovertip(self._source_multiple_button, self._labels.source_multiple_tip)

		self._source_text = ScrolledText(self, font=(self._font['family'], self._font['size']), padx=self._pad, pady=self._pad) # source field
		self._source_text.grid(row=0, column=1, columnspan=3, sticky='nswe', ipadx=self._pad, ipady=self._pad, padx=self._pad, pady=self._pad)
		Hovertip(self._source_text, self._labels.source_text_tip)
		self._destination_button = Button(self, text=self._labels.destination, command=self._select_destination)	### destination selector
		self._destination_button.grid(row=1, column=0, sticky='nswe', padx=self._pad, pady=(0, self._pad))
		self._destination = StringVar()
		self._destination_entry = Entry(self, textvariable=self._destination)
		self._destination_entry.grid(row=1, column=1, columnspan=3, sticky='nsew', padx=self._pad, pady=(0, self._pad))
		Hovertip(self._destination_button, self._labels.destination_tip)
		self._options_var = StringVar(value=self._labels.options)	### options ###
		self._options_selector = Combobox(self, values=self._gen_options_list(), state='readonly', textvariable=self._options_var)
		self._options_selector.grid(row=2, column=1, sticky='nswe', padx=self._pad)
		self._options_selector.bind('<<ComboboxSelected>>', self._options_event)
		Hovertip(self._options_selector, self._labels.options_tip)
		self.possible_hashes = FileHash.get_algorithms()	### hash ###
		self._hash_var = StringVar(value=self._labels.hash)
		self._hash_selector = Combobox(self, values=self._gen_hash_list(), state='readonly', textvariable=self._hash_var)
		self._hash_selector.grid(row=2, column=2, sticky='nswe', padx=self._pad)
		self._hash_selector.bind('<<ComboboxSelected>>', self._hash_event)
		Hovertip(self._hash_selector, self._labels.hash_tip)
		self._verify_var = StringVar(value=self._labels.verify)	### verify ###
		self._verify_selector = Combobox(self, values=self._gen_verify_list(), state='readonly', textvariable=self._verify_var)
		self._verify_selector.grid(row=2, column=3, sticky='nswe', padx=self._pad)
		self._verify_selector.bind('<<ComboboxSelected>>', self._verify_event)
		Hovertip(self._verify_selector, self._labels.verify_tip)
		self._log_button = Button(self, text=self._labels.log, command=self._select_log)	### log ###
		self._log_button.grid(row=3, column=0, sticky='nswe', padx=self._pad, pady=self._pad)
		self._log = StringVar(value=self._config.log_dir)
		self._log_entry = Entry(self, textvariable=self._log)
		self._log_entry.grid(row=3, column=1, columnspan=3, sticky='nswe', padx=self._pad, pady=self._pad)
		Hovertip(self._log_button, self._labels.log_tip)
		if False:# windll.shell32.IsUserAnAdmin() == 1:	### DEBUG ### ### admin label ###
			text = self._labels.admin
			tip = self._labels.admin_tip
		else:
			text = self._labels.no_admin
			tip = self._labels.no_admin_tip
		self._admin_label = Label(self, text=text)
		self._admin_label.grid(row=4, column=1, sticky='nswe', padx=self._pad, pady=(0, self._pad))
		Hovertip(self._admin_label, tip)
		self._simulate_button_text = StringVar(value=self._labels.simulate_button)	### simulate ###
		self._simulate_button = Button(self, textvariable=self._simulate_button_text, command=self._simulate)
		self._simulate_button.grid(row=4, column=2, sticky='nswe', padx=self._pad, pady=(0, self._pad))
		Hovertip(self._simulate_button, self._labels.simulate_tip)
		self._exec_button = Button(self, text=self._labels.exec_button, command=self._execute)	### execute ###
		self._exec_button.grid(row=4, column=3, sticky='nswe', padx=self._pad, pady=(0, self._pad))
		Hovertip(self._exec_button, self._labels.exec_tip)
		self._info_text = ScrolledText(self, font=(self._font['family'], self._font['size']), padx=self._pad, pady=self._pad) ### info ###
		self._info_text.grid(row=5, column=1, columnspan=3, sticky='nswe',
			ipadx=self._pad, ipady=self._pad, padx=self._pad, pady=self._pad)
		self._info_text.bind('<Key>', lambda dummy: 'break')
		self._info_text.configure(state='disabled')
		self._info_fg = self._info_text.cget('foreground')
		self._info_bg = self._info_text.cget('background')
		self._info_newline = True
		self._info_label = Label(self)
		self._info_label.grid(row=6, column=1, sticky='nswe', padx=self._pad, pady=(0, self._pad))
		self._label_fg = self._info_label.cget('foreground')
		self._label_bg = self._info_label.cget('background')
		self._shutdown = BooleanVar(value=False)	### shutdown after finish
		frame = Frame(self)
		frame.grid(row=6, column=2, sticky='nswe', pady=(0, self._pad))
		label = Label(frame, text=f'{self._labels.shutdown}:')
		label.pack(side='left', padx=(self._pad, 0))
		self._shutdown_button = Checkbutton(frame, variable=self._shutdown, command=self._toggle_shutdown)
		self._shutdown_button.pack(side='right', padx=(0, self._pad))
		Hovertip(frame, self._labels.shutdown_tip)
		Hovertip(label, self._labels.shutdown_tip)
		self._quit_button = Button(self, text=self._labels.quit, command=self._quit_app)	### quit/abort ###
		self._quit_button.grid(row=6, column=3, sticky='nswe', padx=self._pad, pady=self._pad)
		Hovertip(self._quit_button, self._labels.quit_tip)
		self._init_warning()

	def _read_source_paths(self):
		'''Read paths from text field'''
		if text := self._source_text.get('1.0', 'end').strip():
			return [Path(line.strip()).absolute() for line in text.split('\n')]
		return ()

	def _chck_source_path(self, source):
		'''Check if source path is valid'''
		if not source:
			return
		path = Path(source)
		if path.exists():
			return path
			showerror(title=self._labels.error, message=self._labels.src_path_not_found.replace('#', f'{path}'))

	def _select_source_dir(self):
		'''Select directory to add into field'''
		if directory := askdirectory(title=self._labels.select_dir, mustexist=True):
			path = Path(directory).absolute()
			if path in self._read_source_paths():
				showerror(title=self._labels.error, message=self._labels.already_added.replace('#', f'{path}'))
				return
			self._source_text.insert('end', f'{path}\n')

	def _select_source_files(self):
		'''Select file(s) to add into field'''
		if filenames := askopenfilenames(title=self._labels.select_files):
			print(filenames, type(filenames), len(filenames))
			if len(filenames) == 1:
				path = Path(filenames[0]).absolute()
				if path in self._read_source_paths():
					showerror(title=self._labels.error, message=self._labels.already_added.replace('#', f'{path}'))
					return
			for filename in filenames:
				path = Path(filename).absolute()
				if not path in self._read_source_paths():
					self._source_text.insert('end', f'{path}\n')

	def _select_multiple(self):
		'''Select multiple files and directories to add into field'''
		if paths := askpaths(
			title = self._labels.select_multiple,
			confirm = self._labels.confirm,
			cancel = self._labels.cancel,
			initialdir = self._config.last_dir
		):
			for path in paths:
				if not path in self._read_source_paths():
					self._source_text.insert('end', f'{path}\n')

	def _get_source_paths(self):
		'''Get source paths from text field'''
		unverified_paths = self._read_source_paths()
		if not unverified_paths:
			showerror(title=self._labels.error, message=self._labels.no_source)
			return
		src_paths = list()
		for path in unverified_paths:
			src_path = self._chck_source_path(path)
			if not src_path:
				return
			src_paths.append(src_path)
		return src_paths

	def _select_destination(self):
		'''Select destination directory'''
		if dst_dir := askdirectory(title=self._labels.select_destination, mustexist=False):
			self._destination.set(dst_dir)
	
	def _get_destination_path(self):
		'''Get destination directory'''
		dst_dir = self._destination.get()
		if not dst_dir:
			showerror(title=self._labels.error, message=self._labels.no_destination)
			return
		dst_path = Path(dst_dir).absolute()
		if not dst_path.exists():
			return dst_path
		if not dst_path.is_dir():
			showerror(self._labels.error, self._labels.dst_no_dir.replace('#', f'{dst_path}'))
			return
		top = dst_path.samefile(dst_path.parent)
		for path in dst_path.iterdir():
			if top and path.is_dir() and path.name.upper() in ('$RECYCLE.BIN', 'SYSTEM VOLUME INFORMATION'):
				continue
			if askyesno(self._labels.warning, self._labels.dst_not_empty.replace('#', f'{dst_path}')):
				break
			else:
				return
		return dst_path

	def _gen_options_list(self):
		'''Generate list of options'''
		return [
			f'\u2611 {option}' if option in self._config.options else f'\u2610 {option}'
			for option in self._config.robocopy_parameters
		]

	def _gen_hash_list(self):
		'''Generate list of hashes to check'''
		return [
			f'\u2611 {hash}' if hash in self._config.hashes else f'\u2610 {hash}'
			for hash in self.possible_hashes
		]

	def _gen_verify_list(self):
		'''Generate list of verification methodes'''
		return [
			f'\u2611 {self._labels.size}' if self._config.verify == 'size' else f'\u2610 {self._labels.size}'
		] + [
			f'\u2611 {hash}' if self._config.verify == hash else f'\u2610 {hash}'
			for hash in self._config.hashes
		]

	def _options_event(self, dummy_event):
		'''Robocopy options selection'''
		choosen = self._options_var.get()[2:]
		self._options_var.set(self._labels.options)	# reset shown text
		if choosen in self._config.options:
			self._config.options.remove(choosen)
		else:
			self._config.options.append(choosen)
			self._config.options.sort()
			for deselect in self._config.robocopy_parameters[choosen]:
				self._config.options.remove(deselect)
		self._options_selector['values'] = self._gen_options_list()

	def _hash_event(self, dummy_event):
		'''Hash algorithm selection'''
		choosen = self._hash_var.get()[2:]
		self._hash_var.set(self._labels.hash)	# reset shown text
		if choosen in self._config.hashes:
			self._config.hashes.remove(choosen)
			if choosen == self._config.verify:
				self._config.verify = 'size'
		else:
			self._config.hashes.append(choosen)
			self._config.hashes.sort()
		self._hash_selector['values'] = self._gen_hash_list()
		self._verify_selector['values'] = self._gen_verify_list()

	def _verify_event(self, dummy_event):
		'''Hash algorithm selection'''
		choosen = self._verify_var.get()[2:]
		self._verify_var.set(self._labels.verify)	# reset shown text
		choosen = 'size' if choosen == self._labels.size else choosen
		if choosen == self._config.verify:
			self._config.verify = ''
		else:
			self._config.verify = choosen
		self._verify_selector['values'] = self._gen_verify_list()

	def _select_log(self):
		'''Select directory '''
		if directory := askdirectory(title=self._labels.select_log, mustexist=False):
			self._log.set(directory)
			self._config.log_dir = directory

	def _clear_info(self):
		'''Clear info text'''
		self._info_text.configure(state='normal')
		self._info_text.delete('1.0', 'end')
		self._info_text.configure(state='disabled')
		self._info_text.configure(foreground=self._info_fg, background=self._info_bg)
		self._warning_state = 'stop'

	def _mk_log_dir(self, log_dir):
		'''Create log directory if not exists'''
		if log_dir:
			try:
				log_dir_path = Path(log_dir).absolute()
				log_dir_path.mkdir(parents=True, exist_ok=True)
				self._config.log_dir = f'{log_dir_path}'
			except Exception as ex:
				showerror(
					title = self._labels.warning,
					message = f'{self._labels.invalid_log_path.replace("#", f"{log_dir_path}")}\n{type(ex)}: {ex}'
				)
				return
			return log_dir_path

	def _start_worker(self, src_paths, dst_path, simulate):
		'''Disable source selection and start worker'''
		log_dir_path = self._mk_log_dir(self._log_entry.get())
		if not log_dir_path and self._config.hashes and not simulate:
			self._select_log()
			if not self._config.log_dir:
				showerror(title=self._labels.warning, message=self._labels.log_required)
				return
			log_dir_path = self._mk_log_dir(self._log_entry.get())
			if not log_dir_path:
				return
		self._config.log_dir = log_dir_path
		try:
			self._config.save()
		except:
			pass
		self._exec_button.configure(state='disabled')
		self._clear_info()
		self._work_thread = WorkThread(
			src_paths,
			dst_path,
			self._app_path,
			self._labels,
			log_dir_path / strftime(self._config.tsv_name) if log_dir_path else None,
			log_dir_path / strftime(self._config.log_name) if log_dir_path else None,
			self._config.hashes,
			self._config.verify,
			simulate,
			self.echo,
			self.finished
		)
		self._work_thread.start()

	def _simulate(self):
		'''Run simulation'''
		src_paths = self._get_source_paths()
		if not src_paths:
			return
		dst_path = self._get_destination_path()
		if not dst_path:
			return
		if self._work_thread:
			self._simulate_button_text.set(self._labels.simulate_button)
			self._work_thread.kill()
			self._work_thread = None
		else:
			self._simulate_button_text.set(self._labels.stop_button)
			self._start_worker(src_paths, dst_path, True)

	def _execute(self):
		'''Start copy process / worker'''
		src_paths = self._get_source_paths()
		if not src_paths:
			return
		dst_path = self._get_destination_path()
		if not dst_path:
			return
		try:
			dst_path.mkdir(exist_ok=True)
		except Exception as ex:
			showerror(
				title = self._labels.warning,
				message = f'{self._labels.invalid_dst_path.replace("#", dst_dir)}\n{type(ex): {ex}}'
			)
			return
		self._simulate_button.configure(state='disabled')
		self._exec_button.configure(state='disabled')
		self._start_worker(
			src_paths,
			dst_path,
			False
		)

	def _init_warning(self):
		'''Init warning functionality'''
		self._warning_state = 'disabled'
		self._warning()

	def _warning(self):
		'''Show flashing warning'''
		if self._warning_state == 'enable':
			self._info_label.configure(text=self._labels.warning)
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

	def _toggle_shutdown(self):
		'''Toggle select switch to shutdown after finish'''
		if self._shutdown.get():
			self._shutdown.set(False)
			if askyesno(title=self._labels.warning, message=self._labels.shutdown_warning):
				self._shutdown.set(True)

	def _reset(self):
		'''Run this when worker has finished copy process'''
		self._work_thread = None
		self._simulate_button_text.set(self._labels.simulate_button)
		self._simulate_button.configure(state='normal')
		self._exec_button.configure(state='normal')
		self._quit_button.configure(state='normal')
		self._work_thread = None

	def _quit_app(self):
		'''Quit app or ask to abort process'''
		if self._work_thread:	
			if self._work_thread.kill_is_set():
				self._reset()
			else:
				if askokcancel(title=self._labels.warning, message=self._labels.abort_warning):
					self._work_thread.kill() # kill running work thread
				return
		#self._get_value()
		#self._get_blocksize()
		#self._get_maxbadblocks()
		#self._get_maxretries()
		#self._get_create()
		#self._get_fs()
		#self._get_label()
		try:
			self._config.save()
		except:
			pass
		self.destroy()


	def _delay_shutdown(self):
		'''Delay shutdown and update progress bar'''
		if self._shutdown_cnt < self._defs.shutdown_delay:
			self._shutdown_cnt += 1
			self._delay_progressbar.step(1)
			self._shutdown_window.after(1000, self._delay_shutdown)
		else:
			run(['shutdown', '/s'])

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

	def finished(self, returncode):
		'''Run this when worker has finished copy process'''
		if returncode == 'killed':
			self._reset()
			return
		if self._shutdown.get():	### Shutdown dialog ###
			self._shutdown_window = Toplevel(self)
			self._shutdown_window.title(self._labels.warning)
			self._shutdown_window.transient(self)
			self._shutdown_window.resizable(False, False)
			self._shutdown_window.grab_set()
			frame = Frame(self._shutdown_window, padding=self._pad)
			frame.pack(fill='both', expand=True)
			Label(frame,
				text = '\u26A0',
				font = (self._font['family'], self._font['size'] * self._defs.symbol_factor),
				foreground = self._defs.symbol_fg,
				background = self._defs.symbol_bg
			).pack(side='left', padx=self._pad, pady=self._pad)
			Label(frame, text=self._labels.shutdown_question, anchor='s').pack(
				side='right', fill='both', padx=self._pad, pady=self._pad
			)
			frame = Frame(self._shutdown_window, padding=self._pad)
			frame.pack(fill='both', expand=True)
			self._delay_progressbar = Progressbar(frame, mode='determinate', maximum=self._defs.shutdown_delay)
			self._delay_progressbar.pack(side='top', fill='x', padx=self._pad, pady=self._pad)
			cancel_button = Button(frame, text=self._labels.cancel_shutdown, command=self._shutdown_window.destroy)
			cancel_button.pack(side='bottom', fill='both', padx=self._pad, pady=self._pad)
			self.update_idletasks()
			pos_x = self.winfo_rootx() + (self.winfo_width() // 2)
			pos_y = self.winfo_rooty() + (self.winfo_height() // 2)
			self._shutdown_window.geometry(f'+{pos_x}+{pos_y}')
			self._shutdown_cnt = 0
			self._delay_shutdown()
		if isinstance(returncode, Exception):
			self._info_text.configure(foreground=self._defs.red_fg, background=self._defs.red_bg)
			self._warning_state = 'enable'
			showerror(
				title = self._labels.error, 
				message = f'{self._labels.aborted_on_error}\n\n{type(returncode)}:\n{returncode}'
			)
		elif returncode:
			self._info_text.configure(foreground=self._defs.green_fg, background=self._defs.green_bg)
		else:
			showwarning(title=self._labels.warning, message=self._labels.warnings_occured)
		self._reset()

if __name__ == '__main__':  # start here when run as application
	Gui().mainloop()
