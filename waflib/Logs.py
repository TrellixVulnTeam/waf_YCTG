#!/usr/bin/env python
# encoding: utf-8
# Thomas Nagy, 2005-2010 (ita)

"""
logging, colors, terminal width and pretty-print
"""

import os, re, traceback, sys, types

_nocolor = os.environ.get('NOCOLOR', 'no') not in ('no', '0', 'false')
try:
	if not _nocolor:
		import waflib.ansiterm
except ImportError:
	pass

try:
	import threading
except ImportError:
	if not 'JOBS' in os.environ:
		# no threading :-(
		os.environ['JOBS'] = '1'
else:
	wlock = threading.Lock()

	class sync_stream(object):
		def __init__(self, stream):
			self.stream = stream
			self.encoding = self.stream.encoding

		def write(self, txt):
			try:
				wlock.acquire()
				self.stream.write(txt)
				self.stream.flush()
			finally:
				wlock.release()

		def fileno(self):
			return self.stream.fileno()

		def flush(self):
			self.stream.flush()

		def isatty(self):
			return self.stream.isatty()

	if not os.environ.get('NOSYNC', False):
		if id(sys.stdout) == id(sys.__stdout__):
			sys.stdout = sync_stream(sys.stdout)
			sys.stderr = sync_stream(sys.stderr)

import logging # import other modules only after

INFO = logging.INFO
WARNING = logging.WARNING
ERROR = logging.ERROR

LOG_FORMAT = "%(asctime)s %(c1)s%(zone)s%(c2)s %(message)s"
HOUR_FORMAT = "%H:%M:%S"

zones = ''
verbose = 0

colors_lst = {
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

got_tty = not os.environ.get('TERM', 'dumb') in ['dumb', 'emacs']
if got_tty:
	try:
		got_tty = sys.stderr.isatty() or sys.stdout.isatty()
	except AttributeError:
		got_tty = False

def get_term_cols():
	return 80

def set_use_colors(use=1):
	"""
	Declare whether to use colors
	"""
	if use > 0:
		try:
			global get_term_cols
			import waflib.ansiterm
			waflib.ansiterm.setup()
			colors.use = use
			for x in (sys.stdout, sys.stderr):
				if x.isatty():
					get_term_cols = x.get_columns
			return
		except AttributeError:
			pass # not available
		except ImportError:
			pass
	if not got_tty and os.environ.get('TERM', 'dumb') != 'msys' and use == 1:
		use = 0
	
	colors.use = use

# If console packages are available, replace the dummy function with a real
# implementation
try:
	import struct, fcntl, termios
except ImportError:
	pass
else:
	if got_tty:
		def get_term_cols_real():
			"""
			Private use only.
			"""
			fds = [ x.fileno() for x in (sys.stderr, sys.stdout) if x.isatty() ]
			for fd in fds:
				return struct.unpack("HHHH", fcntl.ioctl(fd,termios.TIOCGWINSZ, struct.pack("HHHH", 0, 0, 0, 0)))[1]
			raise Exception("Cannot guess terminal columns")
		# try the function once to see if it really works
		try:
			get_term_cols_real()
		except Exception:
			pass
		else:
			get_term_cols = get_term_cols_real

get_term_cols.__doc__ = """
	Get the console width in characters.

	:return: the number of characters per line
	:rtype: int
	"""

class color_dict(object):
	"""attribute-based color access, eg: colors.PINK"""
	def __init__(self, use=0):
		self.use = use
	def __getattr__(self, a):
		return colors_lst.get(a, '') if self.use > 0 else ''
	def __call__(self, a):
		return colors_lst.get(a, '') if self.use > 0 else ''

colors = color_dict()

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

		rec.c2 = colors.NORMAL

		try:
			rec.c1
		except:
			rec.c1 = colors.PINK
			if rec.levelno >= ERROR:
				rec.c1 = colors.RED
			elif rec.levelno >= WARNING:
				rec.c1 = colors.YELLOW
			elif rec.levelno >= INFO:
				rec.c1 = colors.GREEN

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
		stream = sys.stderr if stderr else sys.stdout
		try:
			msg = self.formatter.format(record, tty=stream.isatty())
			ret = '' if getattr(record, 'noret', False) else '\n'
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
	"""Log formatter which adds colors to important messages, and removes them if not a tty"""
	def __init__(self, colors=None):
		logging.Formatter.__init__(self, LOG_FORMAT, HOUR_FORMAT)
		self.colors = colors
	def format(self, rec, tty=True):
		if rec.levelno >= INFO:
			try:
				msg = rec.msg.decode('utf-8')
			except Exception:
				msg = rec.msg
			msg = '%s%s%s' % (rec.c1, msg, rec.c2)
			if not tty and getattr(self.colors, 'use', 0) == 1: # costly but unlikely
				msg = msg.replace('\r', '\n')
				msg = re.sub(r'\x1B\[(K|.*?(m|h|l))', '', msg)
			return msg
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

def debug(*k, **kw):
	"""
	Wrap logging.debug, the output is filtered for performance reasons
	"""
	if verbose:
		k = list(k)
		k[0] = k[0].replace('\n', ' ')
		global log
		log.debug(*k, **kw)

def error(*k, **kw):
	"""
	Wrap logging.errors, display the origin of the message when '-vv' is set
	"""
	global log
	log.error(*k, **kw)
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

def warn(*k, **kw):
	"""
	Wrap logging.warn
	"""
	global log
	log.warn(*k, **kw)

def info(*k, **kw):
	"""
	Wrap logging.info
	"""
	global log
	log.info(*k, **kw)

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
	Print messages in color immediately on stderr::

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
	"""
	cmd = warn if error else info
	cmd("%s%s%s %s%s" % (colors(col), l, colors.NORMAL, label, sep), extra={'noret': True})

