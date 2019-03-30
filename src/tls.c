/*
 * tls.c
 *
 *  Created on: Nov 28, 2015
 *      Author: root
 */

#include <avuna/tls.h>

struct cert* loadCert(const char* cert, const char* key, struct mempool* pool) {
    const SSL_METHOD* method = SSLv23_method();
    SSL_CTX* ctx = SSL_CTX_new(method);
    SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL);
    if (SSL_CTX_use_certificate_file(ctx, cert, SSL_FILETYPE_PEM) < 0) {
        return NULL;
    }
    if (SSL_CTX_use_PrivateKey_file(ctx, key, SSL_FILETYPE_PEM) < 0) {
        return NULL;
    }
    if (!SSL_CTX_check_private_key(ctx)) {
        return NULL;
    }
    struct cert* oc = pmalloc(pool, sizeof(struct cert));
    oc->isDummy = 0;
    oc->ctx = ctx;
    return oc;
}

struct cert* dummyCert(struct mempool* pool) {
    const SSL_METHOD* method = SSLv23_method();
    SSL_CTX* ctx = SSL_CTX_new(method);
    SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL);
    struct cert* oc = pmalloc(pool, sizeof(struct cert));
    oc->ctx = ctx;
    oc->isDummy = 1;
    return oc;
}

