

import sys

from packets import *
from protocol_v1 import *
from transport import *
from utils import *




def test_protocol_v1_server () :
	
	_listener = socket_listen (_test_address)
	
	def _handle (_selector) :
		return "20", "text/plain", "hello world!"
	
	protocol_v1_server (_listener, None, _handle)
	
	_listener.close ()


def test_protocol_v1_client () :
	
	_body = protocol_v1_client (_test_address, "/", None, None)
	
	assert _body == "hello world!"




def test_transport_server () :
	
	_listener = socket_listen (_test_address)
	
	_socket, _peer_public_key, _inbound_key, _outbound_key, _inbound_state, _outbound_state \
			= transport_accept (_listener, None)
	
	log_cut ()
	
	for _index in xrange (10) :
		
		_packet = transport_input (_socket, _inbound_key, _inbound_state)
		assert _packet == "ping-%d" % _index
		
		log_cut ()
		
		transport_output (_socket, _outbound_key, _outbound_state, "pong-%d" % _index)
		
		log_cut ()
	
	_socket.close ()
	_listener.close ()


def test_transport_client () :
	
	_socket, _peer_public_key, _inbound_key, _outbound_key, _inbound_state, _outbound_state \
			= transport_connect (_test_address, None)
	
	log_cut ()
	
	for _index in xrange (10) :
		
		transport_output (_socket, _outbound_key, _outbound_state, "ping-%d" % _index)
		
		log_cut ()
		
		_packet = transport_input (_socket, _inbound_key, _inbound_state)
		assert _packet == "pong-%d" % _index
		
		log_cut ()
	
	_socket.close ()




def test_packets_server () :
	
	_listener = socket_listen (_test_address)
	_socket = socket_accept (_listener)
	
	for _index in xrange (10) :
		
		_packet = packet_input (_socket)
		assert _packet == "ping-%d" % _index
		
		packet_output (_socket, "pong-%d" % _index)
	
	_socket.close ()
	_listener.close ()


def test_packets_client () :
	
	_socket = socket_connect (_test_address)
	
	for _index in xrange (10) :
		
		packet_output (_socket, "ping-%d" % _index)
		
		_packet = packet_input (_socket)
		assert _packet == "pong-%d" % _index
	
	_socket.close ()




_test_address = ("127.0.0.1", 9090)




if __name__ == "__main__" :
	_delegate = locals () ["test_" + sys.argv[1]]
	_delegate (*sys.argv[2:])

