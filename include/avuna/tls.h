/*
 * tls.h
 *
 *  Created on: Nov 28, 2015
 *      Author: root
 */

#ifndef TLS_H_
#define TLS_H_

#include <avuna/pmem.h>
#include <openssl/ssl.h>

struct cert {
    SSL_CTX* ctx;
    int isDummy;
};

struct cert* loadCert(const char* cert, const char* key, struct mempool* pool);

struct cert* dummyCert(struct mempool* pool);

#endif /* TLS_H_ */
