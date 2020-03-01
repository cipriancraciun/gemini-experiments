

from transport import *
from utils import *




def protocol_v1_client (_address, _selector, _local_sign_priv_key, _output) :
	
	log ("[3fbbeade]", "[protocol][client]", "fetching from `%s` selector `%s`...", _address, _selector)
	
	_socket, _peer_public_key, _inbound_key, _outbound_key, _inbound_state, _outbound_state \
			= transport_connect (_address, _local_sign_priv_key)
	
	transport_output (_socket, _outbound_key, _outbound_state, _selector)
	
	_header = transport_input (_socket, _inbound_key, _inbound_state)
	
	_status, _meta = _header.split (" ")
	log ("[65a15f4a]", "[protocol][client]", "received status `%s`;", _status)
	
	if _status[0] == "2" :
		
		log ("[5c008e0e]", "[protocol][client]", "receiving body with MIME `%s`...", _meta)
		_body = transport_input (_socket, _inbound_key, _inbound_state)
		
		if _output is not None :
			_output.write (_body)
		
	else :
		
		log ("[b77e8f6e]", "[protocol][client]", "received details: `%s`;", _meta)
		_body = None
	
	log ("[670c560d]", "[protocol][client]", "fetched;")
	
	_socket.close ()
	
	if _output is None :
		return _body




def protocol_v1_server (_listener, _local_sign_priv_key, _handler) :
	
	log ("[9913bfb7]", "[protocol][server]", "serving...")
	
	_socket, _peer_public_key, _inbound_key, _outbound_key, _inbound_state, _outbound_state \
			= transport_accept (_listener, _local_sign_priv_key)
	
	_selector = transport_input (_socket, _inbound_key, _inbound_state)
	
	log ("[e5fcc3ff]", "[protocol][server]", "received selector `%s`...", _selector)
	
	_status, _meta, _body = _handler (_selector)
	_header = _status + " " + _meta
	
	transport_output (_socket, _outbound_key, _outbound_state, _header)
	
	if _body is not None :
		transport_output (_socket, _outbound_key, _outbound_state, _body)
	
	log ("[99323eef]", "[protocol][server]", "served;")
	
	_socket.close ()

