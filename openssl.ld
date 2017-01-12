OPENSSL_1.0.0 {
	global:
		SSLeay;
		SSLeay_version;
	local:
		_original*;
		_current*;
};

OPENSSL_1.0.1 {
} OPENSSL_1.0.0;

OPENSSL_1.0.1d {
        global:
                CRYPTO_memcmp;
} OPENSSL_1.0.1;

