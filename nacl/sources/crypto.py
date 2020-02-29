

import pysodium


from utils import *




def signature_keys_generate () :
	
	log ("[744dd497]", "[crypto][signature]", "generating signature public-private keys...")
	
	_local_sign_pub_key, _local_sign_priv_key = pysodium.crypto_sign_keypair ()
	
	log ("[1f11c829]", "[crypto][signature]", "generated signature private key `%s`;", _local_sign_priv_key.encode ("b64"))
	log ("[2708e032]", "[crypto][signature]", "generated signature public key `%s`;", _local_sign_pub_key.encode ("b64"))
	
	return _local_sign_pub_key, _local_sign_priv_key


def signature_keys_generate_0 (_local_sign_priv_key) :
	
	_local_sign_pub_key = pysodium.crypto_sign_sk_to_pk (_local_sign_priv_key)
	
	return _local_sign_pub_key, _local_sign_priv_key


def signature_verifier_generate (_local_sign_priv_key, _peer_sess_pub_key) :
	
	log ("[41a10bce]", "[crypto][signature]", "signing `%s`...", _peer_sess_pub_key.encode ("base64"))
	
	_verifier = pysodium.crypto_sign_detached (_peer_sess_pub_key, _local_sign_priv_key)
	
	log ("[66026b06]", "[crypto][signature]", "signed `%s`;", _verifier.encode ("b64"))
	
	return _verifier


def signature_verifier_check (_peer_sign_pub_key, _local_sess_pub_key, _verifier) :
	
	log ("[e7943771]", "[crypto][signature]", "verifying `%s`...", _verifier.encode ("b64"))
	
	pysodium.crypto_sign_verify_detached (_verifier, _local_sess_pub_key, _peer_sign_pub_key)
	
	log ("[37e1f393]", "[crypto][signature]", "verified `%s`;", _local_sess_pub_key.encode ("b64"))




def session_prepare_phase_1 () :
	
	log ("[dcf6b145]", "[crypto][session]", "generating session public-private keys...")
	
	_local_sess_pub_key, _local_sess_priv_key = pysodium.crypto_kx_keypair ()
	
	log ("[3029ae13]", "[crypto][session]", "generated session private key `%s`;", _local_sess_priv_key.encode ("b64"))
	log ("[4b75829d]", "[crypto][session]", "generated session public key `%s`;", _local_sess_pub_key.encode ("b64"))
	
	return _local_sess_pub_key, _local_sess_priv_key


def session_prepare_phase_2 (_local_sess_pub_key, _local_sess_priv_key, _peer_sess_pub_key, _is_client) :
	
	
	if _is_client :
		_crypto_kx_function = pysodium.crypto_kx_client_session_keys
	else :
		_crypto_kx_function = pysodium.crypto_kx_server_session_keys
	
	log ("[31accdc9]", "[crypto][session]", "deriving session inbound-outbound keys...")
	
	_inbound_key, _outbound_key = _crypto_kx_function (_local_sess_pub_key, _local_sess_priv_key, _peer_sess_pub_key)
	
	log ("[9869609b]", "[crypto][session]", "derived session inbound key `%s`;", _inbound_key.encode ("b64"))
	log ("[a9f5bb5a]", "[crypto][session]", "derived session outbound key `%s`;", _outbound_key.encode ("b64"))
	
	log ("[17ada4da]", "[crypto][session]", "deriving session inbound-outbound nonces...")
	
	_inbound_nonce = ("\0" * 8) + _local_sess_pub_key[: pysodium.crypto_secretbox_NONCEBYTES - 8]
	_outbound_nonce = ("\0" * 8) + _peer_sess_pub_key[: pysodium.crypto_secretbox_NONCEBYTES - 8]
	
	log ("[3a958650]", "[crypto][session]", "derived session inbound nonce `%s`;", _inbound_nonce.encode ("b64"))
	log ("[ad8563db]", "[crypto][session]", "derived session outbound nonce `%s`;", _outbound_nonce.encode ("b64"))
	
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

