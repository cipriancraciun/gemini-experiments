

import pysodium


from utils import *




def session_prepare_phase_1 () :
	
	log ("[dcf6b145]", "[crypto][prepare]", "generating session public-private keys...")
	
	_local_pub_key, _local_priv_key = pysodium.crypto_kx_keypair ()
	
	log ("[3029ae13]", "[crypto][prepare]", "generated session private key `%s`;", _local_priv_key.encode ("b64"))
	log ("[4b75829d]", "[crypto][prepare]", "generated session public key `%s`;", _local_pub_key.encode ("b64"))
	
	return _local_pub_key, _local_priv_key


def session_prepare_phase_2 (_local_pub_key, _local_priv_key, _peer_pub_key, _is_client) :
	
	log ("[31accdc9]", "[crypto][prepare]", "deriving session inbound-outbound keys and nonces...")
	
	if _is_client :
		_crypto_kx_function = pysodium.crypto_kx_client_session_keys
	else :
		_crypto_kx_function = pysodium.crypto_kx_server_session_keys
	
	_inbound_key, _outbound_key = _crypto_kx_function (_local_pub_key, _local_priv_key, _peer_pub_key)
	
	log ("[9869609b]", "[crypto][prepare]", "derived session inbound key `%s`;", _inbound_key.encode ("b64"))
	log ("[a9f5bb5a]", "[crypto][prepare]", "derived session outbound key `%s`;", _outbound_key.encode ("b64"))
	
	_inbound_nonce = ("\0" * 8) + _local_pub_key[: pysodium.crypto_secretbox_NONCEBYTES - 8]
	_outbound_nonce = ("\0" * 8) + _peer_pub_key[: pysodium.crypto_secretbox_NONCEBYTES - 8]
	
	log ("[3a958650]", "[crypto][prepare]", "derived session inbound nonce `%s`;", _inbound_nonce.encode ("b64"))
	log ("[ad8563db]", "[crypto][prepare]", "derived session outbound nonce `%s`;", _outbound_nonce.encode ("b64"))
	
	return _inbound_key, _outbound_key, _inbound_nonce, _outbound_nonce




def session_input (_inbound_key, _inbound_nonce, _encrypted) :
	
	pysodium.sodium_increment (_inbound_nonce)
	log ("[8408f904]", "[crypto][input]", "using nonce `%s`;", _inbound_nonce.encode ("b64"))
	
	log ("[62fc5bf5]", "[crypto][input]", "decoding packet (encrypted) `%s`...", _encrypted.encode ("b64"))
	
	_packet = pysodium.crypto_secretbox_open (_encrypted, _inbound_nonce, _inbound_key)
	
	log ("[7eeb53a0]", "[crypto][input]", "decoded packet (plain) `%s`;", _packet.encode ("b64"))
	
	return _packet


def session_output (_outbound_key, _outbound_nonce, _packet) :
	
	pysodium.sodium_increment (_outbound_nonce)
	log ("[7a9b17ef]", "[crypto][output]", "using nonce `%s`;", _outbound_nonce.encode ("b64"))
	
	log ("[04a30b0d]", "[crypto][output]", "encoding packet (plain) `%s`...", _packet.encode ("b64"))
	
	_encrypted = pysodium.crypto_secretbox (_packet, _outbound_nonce, _outbound_key)
	
	log ("[06c3b67d]", "[crypto][output]", "encoded packet (encrypted) `%s`;", _encrypted.encode ("b64"))
	
	return _encrypted

