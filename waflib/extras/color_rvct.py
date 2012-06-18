#!/usr/bin/env python
# encoding: utf-8

# Replaces the default formatter by one which understands RVCT output and colorizes it.

__author__ = __maintainer__ = "Jérôme Carretero <cJ-waf@zougloub.eu>"
__copyright__ = "Jérôme Carretero, 2012"

import sys
import atexit
from waflib import Logs

errors = []

def show_errors():
	for i, e in enumerate(errors):
		if i > 5:
			break
		print("Error: %s" % e)

atexit.register(show_errors)

class ColorGCCFormatter(Logs.TerminalFormatter):
	def __init__(self, colors=None):
		Logs.TerminalFormatter.__init__(self, colors=colors)
	def format(self, rec, tty=True):
		frame = sys._getframe()
		while frame:
			func = frame.f_code.co_name
			if func == 'exec_command':
				cmd = frame.f_locals['cmd']
				if isinstance(cmd, list) and ('tcc' in cmd[0] or 'armld' in cmd[0]):
					lines = []
					for line in rec.msg.split('\n'):
						if 'Warning: ' in line:
							lines.append(self.colors.YELLOW + line)
						elif 'Error: ' in line:
							lines.append(self.colors.RED + line)
							errors.append(line)
						elif 'note: ' in line:
							lines.append(self.colors.CYAN + line)
						else:
							lines.append(line)
					rec.msg = "\n".join(lines)
			frame = frame.f_back
		return Logs.TerminalFormatter.format(self, rec)

def options(opt):
	Logs.log.handlers[0].setFormatter(ColorGCCFormatter(Logs.colors))

