#!/usr/bin/env python3
# -*- coding: utf-8 -*-

__author__ = 'Markus Thilo'
__version__ = '0.0.1_2025-05-20'
__license__ = 'GPL-3'
__email__ = 'markus.thilomarkus@gmail.com'
__status__ = 'Testing'
__description__ = 'Graphical user interface for RoboCopy with hash and verify options'

from sys import executable as __executable__
from pathlib import Path
from lib.config import Config
from lib.gui import Gui

__parent_path__ = Path(__file__).parent if Path(__executable__).stem == 'python' else Path(__executable__).parent

if __name__ == '__main__':  # start here when run as application
	Gui(
		__parent_path__,
		__version__,
		Config(__parent_path__ / 'config.json'),
		Config(__parent_path__ / 'gui.json'),
		Config(__parent_path__ / 'labels.json')
	).mainloop()
