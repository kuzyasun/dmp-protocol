/* Private P01 laboratory helper; public fixture credentials, never production. */
#ifndef DMP_BOUNDARY_PEER_H
#define DMP_BOUNDARY_PEER_H
#include <noise/protocol.h>
#include <stddef.h>
#include <stdint.h>

/* mode=1 NNpsk0, mode=2 XX. generation=0 reproduces the independent fixture.
 * 1..255 deterministically changes both ATTEMPT_ID/prologue and ephemeral
 * keys for laboratory restart checks; it is not a production RNG. */
int boundary_peer_new(NoiseHandshakeState **state, unsigned mode, int role,
                      unsigned generation, int wrong_psk);
int boundary_peer_pin(unsigned mode, int role, uint8_t public_key[32]);
size_t boundary_flight_size(unsigned mode, unsigned flight);
int boundary_fixture_flight(unsigned mode, unsigned flight,
                            const uint8_t *bytes, size_t size);
int boundary_fixture_hash(unsigned mode, const uint8_t hash[32]);
#endif
