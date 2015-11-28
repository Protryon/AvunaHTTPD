/*
 * tls.h
 *
 *  Created on: Nov 28, 2015
 *      Author: root
 */

#ifndef TLS_H_
#define TLS_H_

#include <gnutls/gnutls.h>

struct cert {
		gnutls_certificate_credentials_t cert;
		gnutls_priority_t priority;
};

gnutls_dh_params_t dh_params;

struct cert* loadCert(const char* ca, const char* cert, const char* key);

#endif /* TLS_H_ */
