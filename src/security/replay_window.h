/* Private S6 receive window. Not a public libdmp header.
 *
 * SEC-1 allows a deployment-chosen W that is a power of two in [64, 65536]
 * and names 1024 as the default. This build's bitmap ceiling,
 * DMP_REPLAY_WINDOW_MAX, must itself be a power of two in [1024, 65536]
 * because that default has to fit. Override it with -DDMP_REPLAY_WINDOW_MAX.
 * Handshake init accepts a W in [64, ceiling] and rejects anything larger.
 * The bitmap lives in caller-owned storage; admit and commit do not
 * allocate. A bit is set only after successful AEAD.
 */
#ifndef DMP_REPLAY_WINDOW_H
#define DMP_REPLAY_WINDOW_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define DMP_REPLAY_WINDOW_MIN 64u
#ifndef DMP_REPLAY_WINDOW_MAX
#define DMP_REPLAY_WINDOW_MAX 1024u
#endif
#define DMP_REPLAY_WINDOW_DEFAULT 1024u
#define DMP_REPLAY_WINDOW_BYTES (DMP_REPLAY_WINDOW_MAX / 8u)

_Static_assert(DMP_REPLAY_WINDOW_MAX >= DMP_REPLAY_WINDOW_MIN,
               "replay ceiling is below the SEC-1 minimum");
_Static_assert(DMP_REPLAY_WINDOW_MAX <= 65536u,
               "replay ceiling is above the SEC-1 maximum");
_Static_assert((DMP_REPLAY_WINDOW_MAX & (DMP_REPLAY_WINDOW_MAX - 1u)) == 0u,
               "replay ceiling must be a power of two");
_Static_assert(DMP_REPLAY_WINDOW_DEFAULT >= DMP_REPLAY_WINDOW_MIN,
               "default replay window is below the SEC-1 minimum");
_Static_assert(DMP_REPLAY_WINDOW_DEFAULT <= DMP_REPLAY_WINDOW_MAX,
               "default replay window exceeds the build ceiling");
_Static_assert((DMP_REPLAY_WINDOW_DEFAULT & (DMP_REPLAY_WINDOW_DEFAULT - 1u)) == 0u,
               "default replay window must be a power of two");

typedef struct dmp_replay_window {
    uint64_t highest;
    uint32_t width;
    int open;
    uint8_t bits[DMP_REPLAY_WINDOW_BYTES];
} dmp_replay_window;

void dmp_replay_window_init(dmp_replay_window *window, uint32_t width);
void dmp_replay_window_clear(dmp_replay_window *window);
/* Nonzero when the packet number is not already a cheap reject. */
int dmp_replay_window_admit(const dmp_replay_window *window, uint64_t pn);
/* Nonzero when this packet number was newly marked. */
int dmp_replay_window_commit(dmp_replay_window *window, uint64_t pn);

#ifdef __cplusplus
}
#endif

#endif
