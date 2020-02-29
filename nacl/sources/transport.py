

from crypto import *
from packets import *
from utils import *




def transport_accept (_socket) :
	
	log ("[c217c7f7]", "[transport][server]", "accepting...")
	
	_socket = socket_accept (_socket)
	
	_local_pub_key, _local_priv_key = session_prepare_phase_1 ()
	
	log ("[c1ef39ff]", "[transport][server]", "sending public key...")
	packet_output (_socket, _local_pub_key)
	
	log ("[4b6a089d]", "[transport][server]", "receiving peer public key...")
	_peer_pub_key = packet_input (_socket)
	
	_inbound_key, _outbound_key, _inbound_nonce, _outbound_nonce \
			= session_prepare_phase_2 (_local_pub_key, _local_priv_key, _peer_pub_key, False)
	
	log ("[4bf0c410]", "[transport][server]", "accepted;")
	
	return _socket, _inbound_key, _outbound_key, _inbound_nonce, _outbound_nonce




def transport_connect (_address) :
	
	log ("[bae0d7f1]", "[transport][client]", "connecting...")
	
	_socket = socket_connect (_address)
	
	_local_pub_key, _local_priv_key = session_prepare_phase_1 ()
	
	log ("[c1ef39ff]", "[transport][client]", "sending public key...")
	packet_output (_socket, _local_pub_key)
	
	log ("[dc89759c]", "[transport][client]", "receiving peer public key...")
	_peer_pub_key = packet_input (_socket)
	
	_inbound_key, _outbound_key, _inbound_nonce, _outbound_nonce \
			= session_prepare_phase_2 (_local_pub_key, _local_priv_key, _peer_pub_key, True)
	
	log ("[280cd66b]", "[transport][client]", "connected;")
	
	return _socket, _inbound_key, _outbound_key, _inbound_nonce, _outbound_nonce




def transport_input (_socket, _inbound_key, _inbound_nonce) :
	
	log ("[340cf762]", "[transport][input]", "receiving...")
	
	_encrypted = packet_input (_socket)
	
	_packet = session_input (_inbound_key, _inbound_nonce, _encrypted)
	
	log ("[d24838e7]", "[transport][input]", "received;")
	
	return _packet


def transport_output (_socket, _outbound_key, _outbound_nonce, _packet) :
	
	log ("[9315ab07]", "[transport][output]", "sending...")
	
	_encrypted = session_output (_outbound_key, _outbound_nonce, _packet)
	
	packet_output (_socket, _encrypted)
	
	log ("[e4195cd0]", "[transport][output]", "sent;")

