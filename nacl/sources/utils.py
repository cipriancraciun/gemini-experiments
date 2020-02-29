

import codecs
import logging




def log (_code, _context, _message, *_arguments) :
	_logger.info ("%s %-20s  " + _message, _code, _context, *_arguments)

def log_cut () :
	_logger.info ("[--------]")


logging.basicConfig (format = "%(message)s")

_logger = logging.getLogger ("gemini-experiments")
_logger.setLevel (logging.DEBUG)




class B64Codec (object) :
	
	def encode (self, _input, _errors = None) :
		_output = _input.encode ("base64") .replace ("\n", "")
		return (_output, len (_input))
	
	def decode (self, _input, _errors = None) :
		_output = _input.decode ("base64")
		return (_output, len (_input))
	
	def lookup (self, _name) :
		if _name == "b64" :
			return codecs.CodecInfo (self.encode, self.decode)


codecs.register (B64Codec () .lookup)

