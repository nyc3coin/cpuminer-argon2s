#include "argon2s-gate.h"
#include "argon2s/argon2.h"

static const size_t INPUT_BYTES = 80;  // Lenth of a block header in bytes. Input Length = Salt Length (salt = input)
static const size_t OUTPUT_BYTES = 32; // Length of output needed for a 256-bit hash
static const unsigned int DEFAULT_ARGON2_FLAG = 2; //Same as ARGON2_DEFAULT_FLAGS

void argon2s_hash( void *output, const void *input )
{
        char outhash[32];

        argon2_context context;
        context.out = (uint8_t*)outhash;
        context.outlen = (uint32_t)OUTPUT_BYTES;
        context.pwd = (uint8_t*)input;
        context.pwdlen = (uint32_t)INPUT_BYTES;
        context.salt = (uint8_t *)input;
        context.saltlen = (uint32_t)INPUT_BYTES;
        context.secret = NULL;
        context.secretlen = 0;
        context.ad = NULL;
        context.adlen = 0;
        context.allocate_cbk = NULL;
        context.free_cbk = NULL;
        context.flags = DEFAULT_ARGON2_FLAG;
        context.m_cost = 8192;
        context.lanes = 2;
        context.threads = 1;
        context.t_cost = 2;
        context.version = ARGON2_VERSION_13;
        argon2_ctx( &context, Argon2_d );

        memcpy(output,outhash,32);
}

int scanhash_argon2s( int thr_id, struct work *work, uint32_t max_nonce,
                      uint64_t *hashes_done )
{
        uint32_t _ALIGN(64) endiandata[20];
        uint32_t _ALIGN(64) hash[8];
        uint32_t *pdata = work->data;
        uint32_t *ptarget = work->target;

        const uint32_t first_nonce = pdata[19];
        const uint32_t Htarg = ptarget[7];

        uint32_t nonce = first_nonce;

        swab32_array( endiandata, pdata, 20 );

        do {
                be32enc(&endiandata[19], nonce);
                argon2s_hash( hash, endiandata );
                if ( hash[7] <= Htarg && fulltest( hash, ptarget ) )
                {
                        pdata[19] = nonce;
                        *hashes_done = pdata[19] - first_nonce;
                        work_set_target_ratio(work, hash);
                        return 1;
                }
                nonce++;
        } while (nonce < max_nonce && !work_restart[thr_id].restart);

        pdata[19] = nonce;
        *hashes_done = pdata[19] - first_nonce + 1;
        return 0;
}

bool register_argon2s_algo( algo_gate_t* gate )
{
        gate->scanhash = (void*)&scanhash_argon2s;
        gate->hash = (void*)&argon2s_hash;
        gate->set_target = (void*)&scrypt_set_target;
        gate->optimizations = SSE2_OPT | AVX2_OPT | AVX512_OPT;
        return true;
}
