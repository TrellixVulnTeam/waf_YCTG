#!/usr/bin/env python
# encoding: utf-8

# Replaces the default formatter by one which understands GCC output and colorizes it.

__author__ = __maintainer__ = "Jérôme Carretero <cJ-waf@zougloub.eu>"
__copyright__ = "Jérôme Carretero, 2012"

from waflib import Logs

class ColorGCCFormatter(Logs.TerminalFormatter):
	def __init__(self, colors=None):
		Logs.TerminalFormatter.__init__(self, colors=colors)
	def format(self, rec, tty=True):
		if getattr(rec, 'wafclass', None) == 'exec_command':
			lines = []
			for line in rec.msg.split('\n'):
				if 'warning: ' in line:
					lines.append(self.colors.YELLOW + line)
				elif 'error: ' in line:
					lines.append(self.colors.RED + line)
				elif 'note: ' in line:
					lines.append(self.colors.CYAN + line)
				else:
					lines.append(line)

			rec.msg = "\n".join(lines)
		return Logs.TerminalFormatter.format(self, rec)

def options(opt):
	Logs.log.handlers[0].setFormatter(ColorGCCFormatter(Logs.colors))

