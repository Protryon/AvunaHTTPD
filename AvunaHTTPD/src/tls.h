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
};

struct cert* loadCert(const char* cert, const char* key);

#endif /* TLS_H_ */
