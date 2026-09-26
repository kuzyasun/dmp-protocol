/* Experimental checked startup port; see README.md and LICENSE.libsodium. */
#ifndef DMP_SODIUM_ENTROPY_H
#define DMP_SODIUM_ENTROPY_H
#include <stddef.h>
#ifdef __cplusplus
extern "C" {
#endif

/* Zero means eligible CSPRNG ready / all requested bytes supplied.
 * Any nonzero value is failure; no fallback or partial output is acceptable.
 * The platform owns quality, readiness, bounded work and synchronization.
 * Called under the backend startup lock: no reentry into sodium/Noise init.
 * Failure leaves the backend uninitialized; a caller may explicitly retry.
 * This does not make libsodium's legacy randombytes APIs fallible; the selected
 * Noise provider must use its checked custom entropy port for runtime requests.
 */
int dmp_sodium_entropy_ready(void);
int dmp_sodium_entropy_read(void *bytes, size_t size);

#ifdef __cplusplus
}
#endif
#endif
