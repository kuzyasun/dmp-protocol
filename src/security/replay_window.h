/* Private S6 receive window. Not a public libdmp header.
 *
 * W is the configured power of two in [64, 65536]. SEC-1 names 1024 as the
 * default. The bitmap lives in caller-owned storage; admit and commit do not
 * allocate. A bit is set only after successful AEAD.
 */
#ifndef DMP_REPLAY_WINDOW_H
#define DMP_REPLAY_WINDOW_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define DMP_REPLAY_WINDOW_MIN 64u
#define DMP_REPLAY_WINDOW_MAX 65536u
#define DMP_REPLAY_WINDOW_DEFAULT 1024u
#define DMP_REPLAY_WINDOW_BYTES (DMP_REPLAY_WINDOW_MAX / 8u)

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
