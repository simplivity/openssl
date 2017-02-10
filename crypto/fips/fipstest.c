#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../e_os.h"

#include <openssl/opensslconf.h> 
#include <openssl/crypto.h>
#include <openssl/bio.h>
#include <openssl/bn.h>
#include <openssl/rsa.h>
#include <openssl/objects.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <openssl/err.h>

#ifndef OPENSSL_FIPS
int main(int argc, char *argv[])
{
    printf("No FIPS support\n");
    return (0);
}
#else
static BIO *out;

# ifdef OPENSSL_SYS_WIN16
#  define MS_CALLBACK     _far _loadds
# else
#  define MS_CALLBACK
# endif

static int MS_CALLBACK genrsa_cb(int p, int n, BN_GENCB *cb)
{
    char c = '*';

    if (p == 0)
        c = '.';
    if (p == 1)
        c = '+';
    if (p == 2)
        c = '*';
    if (p == 3)
        c = '\n';
    BIO_write(cb->arg, &c, 1);
    (void)BIO_flush(cb->arg);
    return 1;
}

/*
 * Attempts to create a new RSA key pair.  When FIPS
 * is enabled, the FOM will do a pairwise test after
 * creating the key, ensuring the key is good.
 *
 * Returns 0 on success
 */
static int fips_test_create_rsa_key(int bits, int exponent)
{
    int ret = 1;
    RSA *rsa = NULL;
    BIGNUM *e = NULL;
    BN_GENCB cb;

    rsa = RSA_new();
    if (!rsa) 
    {
        ERR_print_errors(out);
        BIO_printf(out, "  RSA_new() failed.\n");
        goto err;
    }

    e = BN_new();
    if (!e) 
    {
        ERR_print_errors(out);
        BIO_printf(out, "  BN_new() failed.\n");
        goto err;
    }
    BN_set_word(e, exponent);

    BN_GENCB_set(&cb, genrsa_cb, out);

    if (!RSA_generate_key_ex(rsa, bits, e, &cb)) 
    {
        ERR_print_errors(out);
        BIO_printf(out, "  RSA keygen failed.\n");
        goto err;
    }

    ret = 0;
err:
    if (rsa) RSA_free(rsa);
    if (e) BN_free(e);
    return ret;
}

/*
 * Runs all the RSA key generation test cases
 *
 * Returns 0 on success
 */
static int fips_test_rsa_keygen()
{
    BIO_printf(out, " RSA key generation tests...\n");

    /*
     * Test #1, create a 2048 bit keypair with FIPS enabled
     * expect: success
     */
    BIO_printf(out, "  testing 2048 bit keypair generation...\n");
    if (fips_test_create_rsa_key(2048, 65537))
    {
        BIO_printf(out, "  2048 bit keypair generation test failed!!!\n");
        return 1;
    }

    /*
     * Test #2, create a 3072 bit keypair with FIPS enabled
     * expect: success
     */
    BIO_printf(out, "  testing 3072 bit keypair generation...\n");
    if (fips_test_create_rsa_key(3072, 65537))
    {
        BIO_printf(out, "  3072 bit keypair generation test failed!!!\n");
        return 1;
    }

    /*
     * Test #3, create a 1024 bit keypair with FIPS enabled
     * expect: fail 
     */
    BIO_printf(out, "  testing 1024 bit keypair generation (should FAIL)...\n");
    if (!fips_test_create_rsa_key(1024, 65537))
    {
        BIO_printf(out, "  1024 bit keypair generation didn't fail!!!\n");
        return 1;
    }

    /*
     * Test #4, create a 4096 bit keypair with FIPS enabled
     * expect: fail 
     */
    BIO_printf(out, "  testing 4096 bit keypair generation (should FAIL)...\n");
    if (!fips_test_create_rsa_key(4096, 65537))
    {
        BIO_printf(out, "  4096 bit keypair generation didn't fail!!!\n");
        return 1;
    }

    /*
     * Test #5, create 2048 bit keypair with small exponent
     * expect: fail
     */
    BIO_printf(out, "  testing small exponent keypair generation (should FAIL)...\n");
    if (!fips_test_create_rsa_key(2048, 3))
    {
        BIO_printf(out, "  small exponent keypair generation didn't fail!!!\n");
        return 1;
    }

    /*
     * Test #6, create 2048 bit keypair with even exponent
     * expect: fail
     */
    BIO_printf(out, "  testing even exponent keypair generation (should FAIL)...\n");
    if (!fips_test_create_rsa_key(2048, 65538))
    {
        BIO_printf(out, "  even exponent keypair generation didn't fail!!!\n");
        return 1;
    }

    /*
     * All tests have passed, return success
     */
    return 0;
}

int main(int argc, char *argv[])
{
    int ret = 1;

    CRYPTO_malloc_debug_init();
    CRYPTO_dbg_set_options(V_CRYPTO_MDEBUG_ALL);
    CRYPTO_mem_ctrl(CRYPTO_MEM_CHECK_ON);

# ifdef OPENSSL_SYS_WIN32
    CRYPTO_malloc_init();
# endif

    out = BIO_new(BIO_s_file());
    if (out == NULL) EXIT(1);
    BIO_set_fp(out, stdout, BIO_NOCLOSE);

    printf("Running FIPS test suite...\n");
    if (!FIPS_mode_set(1)) 
    {
        ERR_print_errors(out);
        BIO_printf(out, "Failed to enter FIPS mode - test failed.\n");
        goto err;
    }
    if (fips_test_rsa_keygen())
    {
        goto err;
    }

    printf("FIPS test suite passed.\n");
    ret = 0;

 err:
    ERR_print_errors_fp(stderr);
    BIO_free(out);
    CRYPTO_cleanup_all_ex_data();
    ERR_remove_thread_state(NULL);
    CRYPTO_mem_leaks_fp(stderr);
    EXIT(ret);
    return (ret);
}

#endif
