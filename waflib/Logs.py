#!/usr/bin/env python
# encoding: utf-8
# Thomas Nagy, 2005-2010 (ita)

"""
logging, colors, terminal width and pretty-print
"""

import logging, sys, os, re, traceback, types
from waflib import Utils, ansiterm

if not os.environ.get('NOSYNC', False):
	# synchronized output is nearly mandatory to prevent garbled output
	if sys.stdout.isatty() and id(sys.stdout) == id(sys.__stdout__):
		sys.stdout = ansiterm.AnsiTerm(sys.stdout)
	if sys.stderr.isatty() and id(sys.stderr) == id(sys.__stderr__):
		sys.stderr = ansiterm.AnsiTerm(sys.stderr)

INFO = logging.INFO
WARNING = logging.WARNING
ERROR = logging.ERROR

LOG_FORMAT = "%(asctime)s %(c1)s%(zone)s%(c2)s %(message)s"
HOUR_FORMAT = "%H:%M:%S"

zones = ''
verbose = 0

colors_lst = {
'USE' : True,
'BOLD'  :'\x1b[01;1m',
'RED'   :'\x1b[01;31m',
'GREEN' :'\x1b[32m',
'YELLOW':'\x1b[33m',
'PINK'  :'\x1b[35m',
'BLUE'  :'\x1b[01;34m',
'CYAN'  :'\x1b[36m',
'NORMAL':'\x1b[0m',
'cursor_on'  :'\x1b[?25h',
'cursor_off' :'\x1b[?25l',
'erase_cur_eol' : '\x1b[K',
'cr' : '\r',
}

class color_dict(object):
	"""attribute-based color access, eg: colors.PINK"""
	def __init__(self, use=0):
		self.use = use
	def __getattr__(self, a):
		if self.use > 0:
			return colors_lst.get(a, '')
		return ''
	def __call__(self, a):
		if self.use > 0:
			return colors_lst.get(a, '')
		return ''

colors = color_dict()

def enable_colors(use):
	"""
	Declare whether to use colors
	"""

	if use == 1:
		if Utils.to_bool(os.environ.get('NOCOLOR', 'no')):
			use = 0
		if not (sys.stderr.isatty() or sys.stdout.isatty()):
			use = 0
		if Utils.is_win32:
			term = os.environ.get('TERM', '') # has ansiterm
		else:
			term = os.environ.get('TERM', 'dumb')

		if term in ('dumb', 'emacs'):
			use = 0

	if use >= 1:
		os.environ['TERM'] = 'vt100'

	colors.use = use

try:
	get_term_cols = ansiterm.get_term_cols
except AttributeError:
	def get_term_cols():
		return 80

re_log = re.compile(r'(\w+): (.*)', re.M)
class log_filter(logging.Filter):
	"""
	The waf logs are of the form 'name: message', and can be filtered by 'waf --zones=name'.
	For example, the following::

		from waflib import Logs
		Logs.debug('test: here is a message')

	Will be displayed only when executing::

		$ waf --zones=test
	"""
	def __init__(self, name=None):
		pass

	def filter(self, rec):
		"""
		filter a record, adding the colors automatically

		* error: red
		* warning: yellow

		:param rec: message to record
		"""
		rec.zone = rec.module

		if rec.levelno >= INFO:
			return True

		m = re_log.match(rec.msg)
		if m:
			rec.zone = m.group(1)
			rec.msg = m.group(2)

		if zones:
			return getattr(rec, 'zone', '') in zones or '*' in zones
		elif not verbose > 2:
			return False
		return True

class TerminalStreamHandler(logging.StreamHandler):
	""" stream handler dispatching messages to stdout/stderr based on their level or a flag """
	def __init__(self, *k, **kw):
		logging.StreamHandler.__init__(self, *k, **kw)
	def emit(self, record, **kw):
		stderr = record.levelno >= WARNING or getattr(record, 'stderr', False)
		stream = sys.stdout
		if stderr:
			stream = sys.stderr
		try:
			msg = self.formatter.format(record, tty=stream.isatty())
			ret = '\n'
			if getattr(record, 'noret', False):
				ret = ''
			fs = "%s" + ret
			if not hasattr(types, "UnicodeType"): #if no unicode support...
				stream.write(fs % msg)
			else:
				try:
					if (isinstance(msg, unicode) and
						getattr(stream, 'encoding', None)):
						fs = fs.decode(stream.encoding)
						try:
							stream.write(fs % msg)
						except UnicodeEncodeError:
							stream.write((fs % msg).encode(stream.encoding))
					else:
						stream.write(fs % msg)
				except UnicodeError:
					stream.write(fs % msg.encode("UTF-8"))
			self.flush()
		except (KeyboardInterrupt, SystemExit):
			raise
		except:
			self.handleError(record)

class TerminalFormatter(logging.Formatter):
	"""
	Log formatter which adds colors to important messages,
	and removes them if output is not a tty and colors are not
	forced.

	"""
	def __init__(self, colors=None):
		logging.Formatter.__init__(self, LOG_FORMAT, HOUR_FORMAT)
		self.colors = colors

	def format(self, rec, tty=True):
		try:
			msg = rec.msg.decode('utf-8')
		except Exception:
			msg = rec.msg
		c1 = getattr(rec, 'c1', None)
		if c1 is None:
			c1 = ''
			if rec.levelno >= ERROR:
				c1 = colors.RED
			elif rec.levelno >= WARNING:
				c1 = colors.YELLOW
			elif rec.levelno >= INFO:
				c1 = colors.GREEN
		c2 = getattr(rec, 'c2', colors.NORMAL)
		msg = '%s%s%s' % (c1, msg, c2)

		color_use = getattr(self.colors, 'use', 0)
		if (not tty and color_use < 1) or color_use == 0:
			# remove colored output from sub-processes
			msg = msg.replace('\r', '\n')
			msg = re.sub(r'\x1B\[(K|.*?(m|h|l))', '', msg)

		if rec.levelno >= INFO:
			return msg

		rec.msg = msg
		rec.c1 = colors.PINK
		rec.c2 = colors.NORMAL
		return logging.Formatter.format(self, rec)

class FileFormatter(logging.Formatter):
	""" Log formatter which prefixes lines with a message level indicator (used to write config.log) """
	def __init__(self):
		logging.Formatter.__init__(self, LOG_FORMAT, HOUR_FORMAT)
	def format(self, rec):
		msg = str(rec.msg)
		if rec.levelno < WARNING:
			mark = '---'
		elif rec.levelno < ERROR:
			mark = 'WWW'
		else:
			mark = '!!!'
		return "\n".join(["%s: %s" % (mark, x) for x in msg.split("\n")])

log = None
"""global logger for Logs.debug, Logs.error, etc"""

def debug(msg, *k, **kw):
	"""
	Wrap logging.debug, the output is filtered for performance reasons
	"""
	if verbose:
		k = list(k)
		msg = msg.replace('\n', ' ')
		global log
		log.debug(msg, *k, **kw)

def error(msg, *k, **kw):
	"""
	Wrap logging.errors, display the origin of the message when '-vv' is set
	"""
	global log
	log.error(msg, *k, **kw)
	if verbose > 2:
		st = traceback.extract_stack()
		if st:
			st = st[:-1]
			buf = []
			for filename, lineno, name, line in st:
				buf.append('  File "%s", line %d, in %s' % (filename, lineno, name))
				if line:
					buf.append('	%s' % line.strip())
			if buf: log.error("\n".join(buf))

def warn(msg, *k, **kw):
	"""
	Wrap logging.warn
	"""
	global log
	log.warn(msg, *k, **kw)

def info(msg, *k, **kw):
	"""
	Wrap logging.info
	"""
	global log
	log.info(msg, *k, **kw)

def init_log():
	"""
	Initialize the loggers globally
	"""
	global log
	log = logging.getLogger('waflib')
	log.handlers = []
	log.filters = []
	hdlr = TerminalStreamHandler()
	hdlr.setFormatter(TerminalFormatter(colors))
	log.addHandler(hdlr)
	log.addFilter(log_filter())
	log.setLevel(logging.DEBUG)
	log.colors = colors

def make_logger(path, name):
	"""
	Create a simple logger, which is often used to redirect the context command output::

		from waflib import Logs
		bld.logger = Logs.make_logger('test.log', 'build')
		bld.check(header_name='sadlib.h', features='cxx cprogram', mandatory=False)
		bld.logger = None

	:param path: file name to write the log output to
	:type path: string
	:param name: logger name (loggers are reused)
	:type name: string
	"""
	logger = logging.getLogger(name)
	hdlr = logging.FileHandler(path, 'w')
	hdlr.setFormatter(FileFormatter())
	logger.addHandler(hdlr)
	logger.setLevel(logging.DEBUG)
	logger.colors = color_dict(use=0)
	return logger

def make_mem_logger(name, to_log, size=10000):
	"""
	Create a memory logger to avoid writing concurrently to the main logger
	"""
	from logging.handlers import MemoryHandler
	logger = logging.getLogger(name)
	hdlr = MemoryHandler(size, target=to_log)
	formatter = logging.Formatter('%(message)s')
	hdlr.setFormatter(formatter)
	logger.addHandler(hdlr)
	logger.memhandler = hdlr
	logger.setLevel(logging.DEBUG)
	logger.colors = color_dict(use=0)
	return logger

def pprint(col, l, label='', sep='\n', error=False):
	"""
	Print messages in color using a named color::

		from waflib import Logs
		Logs.pprint('RED', 'Something bad just happened')

	:param col: color name to use in :py:const:`Logs.colors_lst`
	:type col: string
	:param str: message to display
	:type str: string or a value that can be printed by %s
	:param label: a message to add after the colored output
	:type label: string
	:param sep: a string to append at the end (line separator)
	:type sep: string
	:param error: whether to treat the message as an error (output to stderr), default is no error
	:type error: bool
	"""
	cmd = info
	if error:
		cmd = warn
	cmd("%s%s%s %s%s" % (colors(col), l, colors.NORMAL, label, sep), extra={'noret': True})

