/*
 * tls.c
 *
 *  Created on: Nov 28, 2015
 *      Author: root
 */

#include "tls.h"
#include <gnutls/gnutls.h>
#include <stdlib.h>
#include "util.h"
#include "globals.h"

struct cert* loadCert(const char* ca, const char* cert, const char* key) {
	struct cert* oc = xmalloc(sizeof(struct cert));
	gnutls_certificate_allocate_credentials(&oc->cert);
	if (ca != NULL) gnutls_certificate_set_x509_trust_file(oc->cert, ca, GNUTLS_X509_FMT_PEM);
	int e1 = gnutls_certificate_set_x509_key_file(oc->cert, cert, key, GNUTLS_X509_FMT_PEM);
	if (e1 < 0) {
		return NULL;
	}
	//gnutls_certificate_set_ocsp_status_request_file(oc->cert, "ocsp-status.der", 0);
	gnutls_priority_init(&oc->priority, "PERFORMANCE:%SERVER_PRECEDENCE", NULL);
	gnutls_certificate_set_dh_params(oc->cert, dh_params);
	return oc;
}

