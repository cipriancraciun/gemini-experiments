

from crypto import *
from packets import *
from utils import *




def transport_accept (_socket, _local_sign_pub_key, _local_sign_priv_key) :
	
	log ("[c217c7f7]", "[transport][server]", "accepting...")
	
	_socket = socket_accept (_socket)
	
	_peer_sign_pub_key, _inbound_key, _outbound_key, _inbound_nonce, _outbound_nonce \
		= transport_prepare (_socket, _local_sign_pub_key, _local_sign_priv_key, False)
	
	log ("[4bf0c410]", "[transport][server]", "accepted;")
	
	return _socket, _peer_sign_pub_key, _inbound_key, _outbound_key, _inbound_nonce, _outbound_nonce


def transport_connect (_address, _local_sign_pub_key, _local_sign_priv_key) :
	
	log ("[bae0d7f1]", "[transport][client]", "connecting...")
	
	_socket = socket_connect (_address)
	
	_peer_sign_pub_key, _inbound_key, _outbound_key, _inbound_nonce, _outbound_nonce \
		= transport_prepare (_socket, _local_sign_pub_key, _local_sign_priv_key, True)
	
	log ("[280cd66b]", "[transport][client]", "connected;")
	
	return _socket, _peer_sign_pub_key, _inbound_key, _outbound_key, _inbound_nonce, _outbound_nonce




def transport_prepare (_socket, _local_sign_pub_key, _local_sign_priv_key, is_client) :
	
	
	log ("[158e71a4]", "[transport][prepare]", "begin...")
	
	
	if _local_sign_pub_key is None :
		if _local_sign_priv_key is not None :
			raise Exception ("[5ece1af8]")
		
		log ("[a520f03a]", "[transport][prepare]", "generating local signature keys...")
		_local_sign_pub_key, _local_sign_priv_key = signature_keys_generate ()
	
	
	log ("[34985587]", "[transport][prepare]", "generating local session keys...")
	_local_sess_pub_key, _local_sess_priv_key = session_prepare_phase_1 ()
	
	
	log ("[c1ef39ff]", "[transport][prepare]", "sending local session public key...")
	packet_output (_socket, _local_sess_pub_key)
	
	log ("[4b6a089d]", "[transport][prepare]", "receiving peer session public key...")
	_peer_sess_pub_key = packet_input (_socket)
	
	
	log ("[59f2d020]", "[transport][prepare]", "deriving session secret keys and nonces...")
	_inbound_key, _outbound_key, _inbound_nonce, _outbound_nonce \
			= session_prepare_phase_2 (_local_sess_pub_key, _local_sess_priv_key, _peer_sess_pub_key, is_client)
	
	
	log ("[12f5a09d]", "[transport][prepare]", "generating local signature verifier...")
	_local_verifier = signature_verifier_generate (_local_sign_priv_key, _peer_sess_pub_key)
	
	
	log ("[c59a242c]", "[transport][prepare]", "sending local signature public key...")
	transport_output (_socket, _outbound_key, _outbound_nonce, _local_sign_pub_key)
	
	log ("[68499460]", "[transport][prepare]", "sending local signature verifier...")
	transport_output (_socket, _outbound_key, _outbound_nonce, _local_verifier)
	
	
	log ("[426190cd]", "[transport][prepare]", "receiving peer signature public key...")
	_peer_sign_pub_key = transport_input (_socket, _inbound_key, _inbound_nonce)
	
	log ("[f9644900]", "[transport][prepare]", "receiving peer signature verifier...")
	_peer_verifier = transport_input (_socket, _inbound_key, _inbound_nonce)
	
	
	log ("[4c17dc79]", "[transport][prepare]", "checking peer signature verifier...")
	signature_verifier_check (_peer_sign_pub_key, _local_sess_pub_key, _peer_verifier)
	
	log ("[7c4bb7a0]", "[transport][prepare]", "succeeded;")
	
	return _peer_sign_pub_key, _inbound_key, _outbound_key, _inbound_nonce, _outbound_nonce




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

