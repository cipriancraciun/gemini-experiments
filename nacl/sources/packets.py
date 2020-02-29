

import socket
import struct


from utils import *




def packet_input (_socket) :
	
	log ("[8594ee80]", "[socket][input]", "reading packet...")
	
	_size = socket_input (_socket, 4)
	_size = struct.unpack (">L", _size) [0]
	
	if _size == 0 :
		return None
	
	_packet = socket_input (_socket, _size)
	
	log ("[84dacd08]", "[socket][input]", "received packet (%d) `%s`;", len (_packet), _packet.encode ("b64"))
	
	return _packet


def packet_output (_socket, _packet) :
	
	if _packet is None :
		_packet = ''
	
	log ("[07216ddb]", "[socket][output]", "sending packet (%d) `%s`...", len (_packet), _packet.encode ("b64"))
	
	_size = len (_packet)
	_buffer = memoryview (bytearray (4 + _size))
	
	_buffer[0:4] = struct.pack (">L", _size)
	
	_buffer[4:] = _packet
	
	socket_output (_socket, _buffer)
	
	log ("[3cc42e4b]", "[socket][output]", "sent packet;")




def socket_listen (_address) :
	
	log ("[62e455fd]", "[socket][server]", "creating TCP listener on `%s`...", _address)
	
	_socket = socket.socket (socket.AF_INET, socket.SOCK_STREAM)
	
	_socket.setsockopt (socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
	
	_socket.bind (_address)
	_socket.listen (128)
	
	return _socket


def socket_accept (_socket) :
	
	log ("[883ac6ec]", "[socket][server]", "accepting TCP connection...")
	
	_socket, _address = _socket.accept ()
	
	log ("[4a622a40]", "[socket][server]", "accepted connection from `%s`;", _address)
	
	return _socket


def socket_connect (_address) :
	
	log ("[b882f37d]", "[socket][client]", "creating TCP connection to `%s`...", _address)
	
	_socket = socket.socket (socket.AF_INET, socket.SOCK_STREAM)
	
	_socket.connect (_address)
	
	return _socket




def socket_input (_socket, _size) :
	
	_buffer = memoryview (bytearray (_size))
	
	_offset = 0
	while _offset < _size :
		_read = _socket.recv_into (_buffer[_offset:])
		if _read == 0 :
			break
		else :
			_offset += _read
	
	if _offset < _size :
		raise Exception ("[bd4dd827]")
	
	return _buffer.tobytes ()


def socket_output (_socket, _buffer) :
	_socket.sendall (_buffer)

