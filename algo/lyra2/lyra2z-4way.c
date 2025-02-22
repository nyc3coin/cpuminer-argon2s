#include "lyra2-gate.h"

#ifdef LYRA2Z_4WAY

#include <memory.h>
#include <mm_malloc.h>
#include "lyra2.h"
#include "algo/blake/sph_blake.h"
#include "algo/blake/blake-hash-4way.h"

__thread uint64_t* lyra2z_4way_matrix;

bool lyra2z_4way_thread_init()
{
 return ( lyra2z_4way_matrix = _mm_malloc( LYRA2Z_MATRIX_SIZE, 64 ) );
}

static __thread blake256_4way_context l2z_4way_blake_mid;

void lyra2z_4way_midstate( const void* input )
{
       blake256_4way_init( &l2z_4way_blake_mid );
       blake256_4way( &l2z_4way_blake_mid, input, 64 );
}

void lyra2z_4way_hash( void *state, const void *input )
{
     uint32_t hash0[8] __attribute__ ((aligned (64)));
     uint32_t hash1[8] __attribute__ ((aligned (64)));
     uint32_t hash2[8] __attribute__ ((aligned (64)));
     uint32_t hash3[8] __attribute__ ((aligned (64)));
     uint32_t vhash[8*4] __attribute__ ((aligned (64)));
     blake256_4way_context ctx_blake __attribute__ ((aligned (64)));

     memcpy( &ctx_blake, &l2z_4way_blake_mid, sizeof l2z_4way_blake_mid );
     blake256_4way( &ctx_blake, input + (64*4), 16 );
     blake256_4way_close( &ctx_blake, vhash );

     mm128_deinterleave_4x32( hash0, hash1, hash2, hash3, vhash, 256 );

     LYRA2Z( lyra2z_4way_matrix, hash0, 32, hash0, 32, hash0, 32, 8, 8, 8 );
     LYRA2Z( lyra2z_4way_matrix, hash1, 32, hash1, 32, hash1, 32, 8, 8, 8 );
     LYRA2Z( lyra2z_4way_matrix, hash2, 32, hash2, 32, hash2, 32, 8, 8, 8 );
     LYRA2Z( lyra2z_4way_matrix, hash3, 32, hash3, 32, hash3, 32, 8, 8, 8 );

     memcpy( state,    hash0, 32 );
     memcpy( state+32, hash1, 32 );
     memcpy( state+64, hash2, 32 );
     memcpy( state+96, hash3, 32 );
}

int scanhash_lyra2z_4way( int thr_id, struct work *work, uint32_t max_nonce,
                          uint64_t *hashes_done, struct thr_info *mythr )
{
   uint32_t hash[8*4] __attribute__ ((aligned (64)));
   uint32_t vdata[20*4] __attribute__ ((aligned (64)));
   uint32_t _ALIGN(64) edata[20];
   uint32_t *pdata = work->data;
   uint32_t *ptarget = work->target;
   const uint32_t Htarg = ptarget[7];
   const uint32_t first_nonce = pdata[19];
   uint32_t n = first_nonce;
   __m128i  *noncev = (__m128i*)vdata + 19;   // aligned
   /* int */ thr_id = mythr->id;  // thr_id arg is deprecated

   if ( opt_benchmark )
      ptarget[7] = 0x0000ff;

   casti_m128i( edata, 0 ) = mm128_bswap_32( casti_m128i( pdata, 0 ) );
   casti_m128i( edata, 1 ) = mm128_bswap_32( casti_m128i( pdata, 1 ) );
   casti_m128i( edata, 2 ) = mm128_bswap_32( casti_m128i( pdata, 2 ) );
   casti_m128i( edata, 3 ) = mm128_bswap_32( casti_m128i( pdata, 3 ) );
   casti_m128i( edata, 4 ) = mm128_bswap_32( casti_m128i( pdata, 4 ) );
   mm128_interleave_4x32( vdata, edata, edata, edata, edata, 640 );

   lyra2z_4way_midstate( vdata );

   do {
      *noncev = mm128_bswap_32( _mm_set_epi32( n+3, n+2, n+1, n ) );

      lyra2z_4way_hash( hash, vdata );
      pdata[19] = n;

      for ( int i = 0; i < 4; i++ )
      if ( (hash+(i<<3))[7] <= Htarg && fulltest( hash+(i<<3), ptarget ) )
      {
          pdata[19] = n+i;         
          work_set_target_ratio( work, hash+(i<<3) );
          if ( submit_work( mythr, work ) )
              applog( LOG_NOTICE, "Share %d submitted by thread %d, lane %d.",
                             accepted_share_count + rejected_share_count + 1,
                             thr_id, i );
          else
              applog( LOG_WARNING, "Failed to submit share." );
      }
      n += 4;
   } while ( (n < max_nonce-4) && !work_restart[thr_id].restart);

   *hashes_done = n - first_nonce + 1;
   return 0;
}

#endif

#if defined(LYRA2Z_8WAY)

__thread uint64_t* lyra2z_8way_matrix;

bool lyra2z_8way_thread_init()
{
 return ( lyra2z_8way_matrix = _mm_malloc( LYRA2Z_MATRIX_SIZE, 64 ) );
}

static __thread blake256_8way_context l2z_8way_blake_mid;

void lyra2z_8way_midstate( const void* input )
{
       blake256_8way_init( &l2z_8way_blake_mid );
       blake256_8way( &l2z_8way_blake_mid, input, 64 );
}

void lyra2z_8way_hash( void *state, const void *input )
{
     uint32_t hash0[8] __attribute__ ((aligned (64)));
     uint32_t hash1[8] __attribute__ ((aligned (64)));
     uint32_t hash2[8] __attribute__ ((aligned (64)));
     uint32_t hash3[8] __attribute__ ((aligned (64)));
     uint32_t hash4[8] __attribute__ ((aligned (64)));
     uint32_t hash5[8] __attribute__ ((aligned (64)));
     uint32_t hash6[8] __attribute__ ((aligned (64)));
     uint32_t hash7[8] __attribute__ ((aligned (64)));
     uint32_t vhash[8*8] __attribute__ ((aligned (64)));
     blake256_8way_context ctx_blake __attribute__ ((aligned (64)));

     memcpy( &ctx_blake, &l2z_8way_blake_mid, sizeof l2z_8way_blake_mid );
     blake256_8way( &ctx_blake, input + (64*8), 16 );
     blake256_8way_close( &ctx_blake, vhash );

     mm256_deinterleave_8x32( hash0, hash1, hash2, hash3,
                              hash4, hash5, hash6, hash7, vhash, 256 );

     LYRA2Z( lyra2z_8way_matrix, hash0, 32, hash0, 32, hash0, 32, 8, 8, 8 );
     LYRA2Z( lyra2z_8way_matrix, hash1, 32, hash1, 32, hash1, 32, 8, 8, 8 );
     LYRA2Z( lyra2z_8way_matrix, hash2, 32, hash2, 32, hash2, 32, 8, 8, 8 );
     LYRA2Z( lyra2z_8way_matrix, hash3, 32, hash3, 32, hash3, 32, 8, 8, 8 );
     LYRA2Z( lyra2z_8way_matrix, hash4, 32, hash4, 32, hash4, 32, 8, 8, 8 );
     LYRA2Z( lyra2z_8way_matrix, hash5, 32, hash5, 32, hash5, 32, 8, 8, 8 );
     LYRA2Z( lyra2z_8way_matrix, hash6, 32, hash6, 32, hash6, 32, 8, 8, 8 );
     LYRA2Z( lyra2z_8way_matrix, hash7, 32, hash7, 32, hash7, 32, 8, 8, 8 );

     memcpy( state,     hash0, 32 );
     memcpy( state+ 32, hash1, 32 );
     memcpy( state+ 64, hash2, 32 );
     memcpy( state+ 96, hash3, 32 );
     memcpy( state+128, hash4, 32 );
     memcpy( state+160, hash5, 32 );
     memcpy( state+192, hash6, 32 );
     memcpy( state+224, hash7, 32 );
}

int scanhash_lyra2z_8way( int thr_id, struct work *work, uint32_t max_nonce,
                          uint64_t *hashes_done, struct thr_info *mythr )
{
   uint32_t hash[8*8] __attribute__ ((aligned (64)));
   uint32_t vdata[20*8] __attribute__ ((aligned (64)));
   uint32_t _ALIGN(64) edata[20];
   uint32_t *pdata = work->data;
   uint32_t *ptarget = work->target;
   const uint32_t Htarg = ptarget[7];
   const uint32_t first_nonce = pdata[19];
   uint32_t n = first_nonce;
   __m256i  *noncev = (__m256i*)vdata + 19;   // aligned
   /* int */ thr_id = mythr->id;  // thr_id arg is deprecated

   if ( opt_benchmark )
      ptarget[7] = 0x0000ff;

   casti_m256i( edata, 0 ) = mm256_bswap_32( casti_m256i( pdata, 0 ) );
   casti_m256i( edata, 1 ) = mm256_bswap_32( casti_m256i( pdata, 1 ) );
   casti_m128i( edata, 4 ) = mm128_bswap_32( casti_m128i( pdata, 4 ) );

   mm256_interleave_8x32( vdata, edata, edata, edata, edata,
                                 edata, edata, edata, edata, 640 );

   lyra2z_8way_midstate( vdata );

   do {
      *noncev = mm256_bswap_32(
                 _mm256_set_epi32( n+7, n+6, n+5, n+4, n+3, n+2, n+1, n ) );
      lyra2z_8way_hash( hash, vdata );
      pdata[19] = n;

      for ( int i = 0; i < 8; i++ )
      if ( (hash+(i<<3))[7] <= Htarg && fulltest( hash+(i<<3), ptarget ) )
      {
          pdata[19] = n+i;         
          submit_solution( work, hash+(i<<3), mythr, i );
      }
      n += 8;
   } while ( (n < max_nonce-8) && !work_restart[thr_id].restart);

   *hashes_done = n - first_nonce + 1;
   return 0;
}


#endif
