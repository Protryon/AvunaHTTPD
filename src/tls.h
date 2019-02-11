/*
 * tls.h
 *
 *  Created on: Nov 28, 2015
 *      Author: root
 */

#ifndef TLS_H_
#define TLS_H_

#include <openssl/ssl.h>

struct cert {
		SSL_CTX* ctx;
		int isDummy;
};

struct cert* loadCert(const char* cert, const char* key);

struct cert* dummyCert();

#endif /* TLS_H_ */
