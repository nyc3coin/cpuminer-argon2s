#ifndef ARGON2S_GATE_H__
#define ARGON2S_GATE_H__

#include "algo-gate-api.h"
#include <stdint.h>

bool register_argon2s_algo( algo_gate_t* gate );

void argon2s_hash( void *state, const void *input );

int scanhash_argon2s( int thr_id, struct work *work, uint32_t max_nonce,
                    uint64_t *hashes_done );
#endif

