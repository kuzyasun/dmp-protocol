#ifndef DMP_NOISE_OWNER_FIXTURE_H
#define DMP_NOISE_OWNER_FIXTURE_H

#include <noise/protocol.h>

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Private test driver for one real Noise endpoint and prerecorded peer flights. */
typedef struct dmp_noise_owner {
    NoiseHandshakeState *handshake;
    NoiseCipherState *send;
    NoiseCipherState *receive;
    size_t fixture_index;
    size_t next_flight;
    int role;
    unsigned writes;
    int sent;
} dmp_noise_owner;

size_t dmp_owner_fixture_count(void);
int dmp_owner_create(dmp_noise_owner *owner, size_t index, int role);
int dmp_owner_step(dmp_noise_owner *owner, int corrupt);
int dmp_owner_complete(dmp_noise_owner *owner);
int dmp_owner_send_once(dmp_noise_owner *owner);
int dmp_owner_receive(dmp_noise_owner *owner, int corrupt);
int dmp_owner_close(dmp_noise_owner *owner);

#ifdef __cplusplus
}
#endif

#endif
