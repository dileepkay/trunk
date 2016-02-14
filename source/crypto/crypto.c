#include "../config/config.h"

const char *pers = "polarSSL_crypto_example";
entropy_context entropy;
ctr_drbg_context ctr_drbg;



int PrngGenerateBytes( void *pOutput, uint16 nOutputLength )
{
   int ret;
   if( ( ret = ctr_drbg_random (&ctr_drbg, (unsigned char *) pOutput, nOutputLength ) ) != 0 )
   {
      proj_printf( " failed\n  ! ctr_drbg_random returned -0x%x\n", -ret );
   }
   return ret;
}

////////////////////////////////////////////////////////////////////////////
//
// AES Encryption / Decryption - CBC
//
////////////////////////////////////////////////////////////////////////////
int AESCryptCBC( uint8 *key, uint8 keyLen, uint8 mode, uint8 *iv, uint8 inLen, uint8 *in, uint8 *out )
{
   aes_context aes_ctx;
   int ret;

   if(inLen % 16)
   {
      proj_printf("ERROR: Length is incorrect");
      return inLen;
   }

   if ( mode == AES_ENCRYPT )
   {
      aes_setkey_enc(&aes_ctx, key, keyLen*8); //PolarSSL takes key length in bits
      if ( ( ret = aes_crypt_cbc(&aes_ctx, mode, inLen, iv, in, out) ) != aes_pass )
      {
         return ( FAIL );
      }
   }
   else if ( mode == AES_DECRYPT )
   {
      aes_setkey_dec(&aes_ctx, key, keyLen*8); //PolarSSL takes key length in bits
      if ( (aes_crypt_cbc (&aes_ctx, mode, inLen, iv, in, out)) != aes_pass )
      {
         return (FAIL);
      }
   }
   else
   {
      return ( FAIL );
   }
   return ( PASS );
}

////////////////////////////////////////////////////////////////////////////
//
// AES Encryption / Decryption - ECB
//
////////////////////////////////////////////////////////////////////////////
int AESCryptECB( uint8 *key, uint8 keyLen, uint8 mode, uint8 *in, uint8 *out )
{
   int ret;
   aes_context aes_ctx;

   if( mode == AES_ENCRYPT )
   {
      aes_setkey_enc(&aes_ctx, key, keyLen*8);  //PolarSSL takes key length in bits
      if ( (ret = aes_crypt_ecb (&aes_ctx, AES_ENCRYPT, in, out)) != aes_pass )
      {
         return (FAIL);
      }
   }
   else if ( mode == AES_DECRYPT )
   {
      aes_setkey_dec(&aes_ctx, key, keyLen*8);  //PolarSSL takes key length in bits
      if ( (aes_crypt_ecb (&aes_ctx, AES_DECRYPT, in, out)) != aes_pass )
      {
         return (FAIL);
      }
   }
   else
   {
      return ( FAIL );
   }
   return (PASS);
}

////////////////////////////////////////////////////////////////////////////
//
// AES Encryption / Decryption - ECB Blocks
//
////////////////////////////////////////////////////////////////////////////
int AESCryptECB_Blocks( uint8 *key, uint8 keyLen, uint8 mode, uint8 nBlocks, uint8 *in, uint8 *out )
{
   int i;
   aes_context aes_ctx;

   if( mode == AES_ENCRYPT )
   {
      aes_setkey_enc(&aes_ctx, key, keyLen*8); //PolarSSL takes key length in bits
   }
   else if( mode == AES_DECRYPT )
   {
      aes_setkey_dec(&aes_ctx, key, keyLen*8); //PolarSSL takes key length in bits
   }
   else
   {
      return (FAIL);
   }

   for( i = 0; i < nBlocks; i++)
   {
      if ( aes_crypt_ecb(&aes_ctx, mode, in, out) != aes_pass )
      {
         return (FAIL);
      }
      out += AES_BLOCK_SIZE;
      in += AES_BLOCK_SIZE;
   }
   return ( PASS );
}

////////////////////////////////////////////////////////////////////////////
//
// AES Encryption / Decryption - ECB Blocks
//
////////////////////////////////////////////////////////////////////////////
status TestAESCrypto( void )
{
   uint8 ret;
   uint8 buffer[512]; // AES - CBC can take less than 256 bytes as input

   uint8 key[16];    // Key can be 16 bytes ~ 128 AES or 32 bytes 256 AES
   uint8 iv[16];     // iv fixed random value of 16 bytes
   uint8 updated_iv[16];

   entropy_init( &entropy );
   if( ( ctr_drbg_init( &ctr_drbg, entropy_func, &entropy,
                         (const unsigned char *) pers,
                          strlen( pers ) ) ) != 0 )
   {
      proj_printf( " failed\n  ! ctr_drbg_init returned -0x%x\n", -ret );
      return ( FAIL );
   }

   //DRBG test
   proj_printf("INF: DRBG test - generate Random number");
   PrngGenerateBytes( buffer, sizeof(buffer));
   print_buffer(buffer,sizeof(buffer));

   // Setting key, iv and buffer values
   memset(buffer, 0xA5, sizeof(buffer));
   print_buffer(buffer,sizeof(buffer));

   PrngGenerateBytes(key,sizeof(key));
   print_buffer(key,sizeof(key));

   PrngGenerateBytes(iv,sizeof(iv));
   print_buffer(iv,sizeof(iv));

   // AES -CBC test
   memcpy(updated_iv, iv, sizeof(iv));

   AESCryptCBC( key, sizeof(key), AES_ENCRYPT, updated_iv, sizeof(buffer), buffer, buffer );
   print_buffer(buffer, sizeof(buffer));

   AESCryptCBC( key, sizeof(key), AES_DECRYPT, iv, sizeof(buffer), buffer, buffer );
   print_buffer(buffer, sizeof(buffer));

   // AES - ECB
   AESCryptECB( key, sizeof(key), AES_ENCRYPT, buffer, buffer );
   print_buffer(buffer, sizeof(buffer));

   AESCryptECB( key, sizeof(key), AES_DECRYPT, buffer, buffer );
   print_buffer(buffer, sizeof(buffer));

   // AES - ECB Blocks
   AESCryptECB_Blocks( key, sizeof(key), AES_ENCRYPT, sizeof(buffer)/16, buffer, buffer );
   print_buffer(buffer, sizeof(buffer));

   AESCryptECB_Blocks( key, sizeof(key), AES_DECRYPT, sizeof(buffer)/16, buffer, buffer );
   print_buffer(buffer, sizeof(buffer));

   return ( PASS );
}

////////////////////////////////////////////////////////////////////////////
//
// Hasing algorithms
//
////////////////////////////////////////////////////////////////////////////
static unsigned char sha256_test_buf[3][57] =
{
    { "abc" },
    { "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq" },
    { "" }
};

static const int sha256_test_buflen[3] =
{
    4, 56, 1000
};

static const unsigned char sha256_test_sum[3][32] =
{
    /*
     * SHA-256 test vectors
     */
    { 0xBA, 0x78, 0x16, 0xBF, 0x8F, 0x01, 0xCF, 0xEA,
      0x41, 0x41, 0x40, 0xDE, 0x5D, 0xAE, 0x22, 0x23,
      0xB0, 0x03, 0x61, 0xA3, 0x96, 0x17, 0x7A, 0x9C,
      0xB4, 0x10, 0xFF, 0x61, 0xF2, 0x00, 0x15, 0xAD },
    { 0x24, 0x8D, 0x6A, 0x61, 0xD2, 0x06, 0x38, 0xB8,
      0xE5, 0xC0, 0x26, 0x93, 0x0C, 0x3E, 0x60, 0x39,
      0xA3, 0x3C, 0xE4, 0x59, 0x64, 0xFF, 0x21, 0x67,
      0xF6, 0xEC, 0xED, 0xD4, 0x19, 0xDB, 0x06, 0xC1 },
    { 0xCD, 0xC7, 0x6E, 0x5C, 0x99, 0x14, 0xFB, 0x92,
      0x81, 0xA1, 0xC7, 0xE2, 0x84, 0xD7, 0x3E, 0x67,
      0xF1, 0x80, 0x9A, 0x48, 0xA4, 0x97, 0x20, 0x0E,
      0x04, 0x6D, 0x39, 0xCC, 0xC7, 0x11, 0x2C, 0xD0 }
};

void testHash()
{
   unsigned char Digest[32];
   sha256_context ctx;

   sha256_init( &ctx );
   sha256_starts( &ctx, 0 );
   sha256_update( &ctx, sha256_test_buf[0], sha256_test_buflen[0] );
   sha256_finish( &ctx, Digest );

   print_buffer(Digest, sizeof(Digest));
   memset(Digest, 0, sizeof(Digest));

   uint8 buffer[1];
   sha256_init( &ctx );
   sha256_starts( &ctx, 0 );

   buffer[0] = 'a';
   sha256_update( &ctx, buffer, 1 );

   buffer[0] = 'b';
   sha256_update( &ctx, buffer, 1 );

   buffer[0] = 'c';
   sha256_update( &ctx, buffer, 1 );

   buffer[0] = '\0';
   sha256_update( &ctx, buffer, 1 );

   sha256_finish( &ctx, Digest );

   print_buffer(Digest, sizeof(Digest));


}



/*
 * RFC 4231 test vectors
 */
static unsigned char sha256_hmac_test_key[7][26] =
{
    { "\x0B\x0B\x0B\x0B\x0B\x0B\x0B\x0B\x0B\x0B\x0B\x0B\x0B\x0B\x0B\x0B"
      "\x0B\x0B\x0B\x0B" },
    { "Jefe" },
    { "\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA"
      "\xAA\xAA\xAA\xAA" },
    { "\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0A\x0B\x0C\x0D\x0E\x0F\x10"
      "\x11\x12\x13\x14\x15\x16\x17\x18\x19" },
    { "\x0C\x0C\x0C\x0C\x0C\x0C\x0C\x0C\x0C\x0C\x0C\x0C\x0C\x0C\x0C\x0C"
      "\x0C\x0C\x0C\x0C" },
    { "" }, /* 0xAA 131 times */
    { "" }
};

static const int sha256_hmac_test_keylen[7] =
{
    20, 4, 20, 25, 20, 131, 131
};

static unsigned char sha256_hmac_test_buf[7][153] =
{
    { "Hi There" },
    { "what do ya want for nothing?" },
    { "\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD"
      "\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD"
      "\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD"
      "\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD"
      "\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD" },
    { "\xCD\xCD\xCD\xCD\xCD\xCD\xCD\xCD\xCD\xCD"
      "\xCD\xCD\xCD\xCD\xCD\xCD\xCD\xCD\xCD\xCD"
      "\xCD\xCD\xCD\xCD\xCD\xCD\xCD\xCD\xCD\xCD"
      "\xCD\xCD\xCD\xCD\xCD\xCD\xCD\xCD\xCD\xCD"
      "\xCD\xCD\xCD\xCD\xCD\xCD\xCD\xCD\xCD\xCD" },
    { "Test With Truncation" },
    { "Test Using Larger Than Block-Size Key - Hash Key First" },
    { "This is a test using a larger than block-size key "
      "and a larger than block-size data. The key needs to "
      "be hashed before being used by the HMAC algorithm." }
};

static const int sha256_hmac_test_buflen[7] =
{
    8, 28, 50, 50, 20, 54, 152
};

static const unsigned char sha256_hmac_test_sum[14][32] =
{
    /*
     * HMAC-SHA-256 test vectors
     */
    { 0xB0, 0x34, 0x4C, 0x61, 0xD8, 0xDB, 0x38, 0x53,
      0x5C, 0xA8, 0xAF, 0xCE, 0xAF, 0x0B, 0xF1, 0x2B,
      0x88, 0x1D, 0xC2, 0x00, 0xC9, 0x83, 0x3D, 0xA7,
      0x26, 0xE9, 0x37, 0x6C, 0x2E, 0x32, 0xCF, 0xF7 },
    { 0x5B, 0xDC, 0xC1, 0x46, 0xBF, 0x60, 0x75, 0x4E,
      0x6A, 0x04, 0x24, 0x26, 0x08, 0x95, 0x75, 0xC7,
      0x5A, 0x00, 0x3F, 0x08, 0x9D, 0x27, 0x39, 0x83,
      0x9D, 0xEC, 0x58, 0xB9, 0x64, 0xEC, 0x38, 0x43 },
    { 0x77, 0x3E, 0xA9, 0x1E, 0x36, 0x80, 0x0E, 0x46,
      0x85, 0x4D, 0xB8, 0xEB, 0xD0, 0x91, 0x81, 0xA7,
      0x29, 0x59, 0x09, 0x8B, 0x3E, 0xF8, 0xC1, 0x22,
      0xD9, 0x63, 0x55, 0x14, 0xCE, 0xD5, 0x65, 0xFE },
    { 0x82, 0x55, 0x8A, 0x38, 0x9A, 0x44, 0x3C, 0x0E,
      0xA4, 0xCC, 0x81, 0x98, 0x99, 0xF2, 0x08, 0x3A,
      0x85, 0xF0, 0xFA, 0xA3, 0xE5, 0x78, 0xF8, 0x07,
      0x7A, 0x2E, 0x3F, 0xF4, 0x67, 0x29, 0x66, 0x5B },
    { 0xA3, 0xB6, 0x16, 0x74, 0x73, 0x10, 0x0E, 0xE0,
      0x6E, 0x0C, 0x79, 0x6C, 0x29, 0x55, 0x55, 0x2B },
    { 0x60, 0xE4, 0x31, 0x59, 0x1E, 0xE0, 0xB6, 0x7F,
      0x0D, 0x8A, 0x26, 0xAA, 0xCB, 0xF5, 0xB7, 0x7F,
      0x8E, 0x0B, 0xC6, 0x21, 0x37, 0x28, 0xC5, 0x14,
      0x05, 0x46, 0x04, 0x0F, 0x0E, 0xE3, 0x7F, 0x54 },
    { 0x9B, 0x09, 0xFF, 0xA7, 0x1B, 0x94, 0x2F, 0xCB,
      0x27, 0x63, 0x5F, 0xBC, 0xD5, 0xB0, 0xE9, 0x44,
      0xBF, 0xDC, 0x63, 0x64, 0x4F, 0x07, 0x13, 0x93,
      0x8A, 0x7F, 0x51, 0x53, 0x5C, 0x3A, 0x35, 0xE2 }
};

void test_SHA256_HMAC(void)
{
   uint8 buf[131];
   int buflen;
   unsigned char Digest[32];
   sha256_context ctx;

   sha256_hmac_starts( &ctx, sha256_hmac_test_key[6], sha256_hmac_test_keylen[6], 0 );

   //memset( buf, '\xAA', buflen = 131 );
   //sha256_hmac_starts( &ctx, buf, buflen, 0 );

   sha256_hmac_update( &ctx, sha256_hmac_test_buf[6], sha256_hmac_test_buflen[6] );
   sha256_hmac_finish( &ctx, Digest );

   print_buffer(Digest, sizeof(Digest));
}


