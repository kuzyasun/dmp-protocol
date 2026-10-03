#include "dmp/identity.h"

/* Test-only stand-in for an already authenticated SEC-1 direction.
 * It does not perform a handshake, AEAD, or replay check, and it is not
 * linked into libdmp. Compact REPLY_TO tests that use it are provisional. */

dmp_status dmp_test_open_authenticated_context(dmp_identity_table *table,
                                              const dmp_identity_context_config *config,
                                              dmp_identity_handle *out)
{
    dmp_identity_context_config authenticated;

    if (config == NULL) {
        return DMP_INVALID_ARGUMENT;
    }
    authenticated = *config;
    authenticated.security = 1U;
    return dmp_identity_context_open(table, &authenticated, out);
}
