#include "../config/config.h"

int main_crypto( void )
{
#if CRYPTO_TESTS
    printf("main_crypto()       ok\n\n");

   //TestAESCrypto();
   //testHash();
   test_SHA256_HMAC( );
#else
    printf("main_crypto()       skipped \n");
#endif
}
