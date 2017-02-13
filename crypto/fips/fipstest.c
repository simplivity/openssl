#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../e_os.h"

#include <openssl/opensslconf.h> 
#include <openssl/crypto.h>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/rsa.h>
#include <openssl/dsa.h>
#include <openssl/cmac.h>
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

/*
 * These are the testcase identifiers as they are configured
 * in testrails for each test case covered in this module.
 */
#define TESTRAILS_TC_RSA2048    201893
#define TESTRAILS_TC_RSA3072    201895
#define TESTRAILS_TC_RSA1024    201896
#define TESTRAILS_TC_RSA4096    201897
#define TESTRAILS_TC_SMALL_E    201898
#define TESTRAILS_TC_EVEN_E     201899
#define TESTRAILS_TC_AESCFB     201913
#define TESTRAILS_TC_AESOFB     201914
#define TESTRAILS_TC_3DESCFB    201915
#define TESTRAILS_TC_3DESOFB    201916
#define TESTRAILS_TC_DESCFB     201917
#define TESTRAILS_TC_DESOFB     201918
#define TESTRAILS_TC_DESECB     201919
#define TESTRAILS_TC_DESCBC     201920
#define TESTRAILS_TC_DSA        201921
#define TESTRAILS_TC_P224       201922
#define TESTRAILS_TC_P521       201923
#define TESTRAILS_TC_P256       201924
#define TESTRAILS_TC_P384       201925
#define TESTRAILS_TC_CMAC       201926



/*
 * The TESTRAILS_RESULT enum aligns with the values defined
 * by the TESTRAILS REST API:
 * http://docs.gurock.com/testrail-api2/reference-results#add_result
*/
typedef enum
{
    TEST_PASSED = 1,
    TEST_BLOCKED,
    TEST_UNTESTED,
    TEST_RETEST,
    TEST_FAILED
} TESTRAILS_RESULT;

#define TESTRAILS_USER      "svtautomation"
#define TESTRAILS_PWD       "svtrfs29LAB"
#define TESTRAILS_SERVER    "testrail.us-east01.simplivt.local"
/*
 * This function will use the Testrails REST API to update the result
 * for a single test case.  The TESTRAILS_RUN_ID environment variable needs to be
 * set before running this test suite.  If the run ID isn't known, then
 * this function will be a no-op.
 */
static void fips_update_testrails(int testcase_id, TESTRAILS_RESULT result,
        char *comment)
{
    char cmd[1024];    
    int run_id;
    char *run_env;

    /*
     * The TESTRAILS_RUN_ID environment variable must be set to update
     * testrails.  If it's not set, we bail.
     */
    run_env = getenv("TESTRAILS_RUN_ID");
    if (!run_env) return;
    run_id = atoi(run_env);

    /*
     * Issue a Curl command to pop the Testrails REST API with the test result
     */
    snprintf(cmd, 1024,
        "curl --insecure -H \"Content-Type: application/json\" "
        "-u \"%s:%s\" "
        "-d '{ \"status_id\": %d, \"comment\": \"%s\", \"elapsed\": "
        "\"1s\", \"version\": \"%s\" }' "
        "\"https://%s//testrail/index.php?/api/v2/add_result_for_case/%d/%d\"",
        TESTRAILS_USER, TESTRAILS_PWD,
        result, comment, 
        SSLeay_version(SSLEAY_VERSION), 
        TESTRAILS_SERVER,
        run_id, testcase_id);
    //printf("%s\n", cmd);
    system(cmd);
}

/*
 * Marks all test cases as with same result in Testrails
 */
static void fips_testrails_set_all(TESTRAILS_RESULT result, char *comment)
{
    fips_update_testrails(TESTRAILS_TC_RSA2048, result, comment);
    fips_update_testrails(TESTRAILS_TC_RSA3072, result, comment);
    fips_update_testrails(TESTRAILS_TC_RSA1024, result, comment);
    fips_update_testrails(TESTRAILS_TC_RSA4096, result, comment);
    fips_update_testrails(TESTRAILS_TC_SMALL_E, result, comment);
    fips_update_testrails(TESTRAILS_TC_EVEN_E, result, comment);
    fips_update_testrails(TESTRAILS_TC_AESCFB, result, comment);
    fips_update_testrails(TESTRAILS_TC_AESOFB, result, comment);
    fips_update_testrails(TESTRAILS_TC_3DESCFB, result, comment);
    fips_update_testrails(TESTRAILS_TC_3DESOFB, result, comment);
    fips_update_testrails(TESTRAILS_TC_DESCFB, result, comment);
    fips_update_testrails(TESTRAILS_TC_DESOFB, result, comment);
    fips_update_testrails(TESTRAILS_TC_DESECB, result, comment);
    fips_update_testrails(TESTRAILS_TC_DESCBC, result, comment);
    fips_update_testrails(TESTRAILS_TC_DSA, result, comment);
    fips_update_testrails(TESTRAILS_TC_P224, result, comment);
    fips_update_testrails(TESTRAILS_TC_P256, result, comment);
    fips_update_testrails(TESTRAILS_TC_P384, result, comment);
    fips_update_testrails(TESTRAILS_TC_P521, result, comment);
    fips_update_testrails(TESTRAILS_TC_CMAC, result, comment);
}


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
        fips_update_testrails(TESTRAILS_TC_RSA2048, TEST_FAILED, "keygen failed");
        return 1;
    }
    fips_update_testrails(TESTRAILS_TC_RSA2048, TEST_PASSED, "keygen passed");

    /*
     * Test #2, create a 3072 bit keypair with FIPS enabled
     * expect: success
     */
    BIO_printf(out, "  testing 3072 bit keypair generation...\n");
    if (fips_test_create_rsa_key(3072, 65537))
    {
        BIO_printf(out, "  3072 bit keypair generation test failed!!!\n");
        fips_update_testrails(TESTRAILS_TC_RSA3072, TEST_FAILED, "keygen failed");
        return 1;
    }
    fips_update_testrails(TESTRAILS_TC_RSA3072, TEST_PASSED, "keygen passed");

    /*
     * Test #3, create a 1024 bit keypair with FIPS enabled
     * expect: fail 
     */
    BIO_printf(out, "  testing 1024 bit keypair generation (should FAIL)...\n");
    if (!fips_test_create_rsa_key(1024, 65537))
    {
        BIO_printf(out, "  1024 bit keypair generation didn't fail!!!\n");
        fips_update_testrails(TESTRAILS_TC_RSA1024, TEST_FAILED, "1024 not blocked");
        return 1;
    }
    fips_update_testrails(TESTRAILS_TC_RSA1024, TEST_PASSED, "1024 blocked as expected");

    /*
     * Test #4, create a 4096 bit keypair with FIPS enabled
     * expect: fail 
     */
    BIO_printf(out, "  testing 4096 bit keypair generation (should FAIL)...\n");
    if (!fips_test_create_rsa_key(4096, 65537))
    {
        BIO_printf(out, "  4096 bit keypair generation didn't fail!!!\n");
        fips_update_testrails(TESTRAILS_TC_RSA4096, TEST_FAILED, "4096 not blocked");
        return 1;
    }
    fips_update_testrails(TESTRAILS_TC_RSA4096, TEST_PASSED, "4096 blocked as expected");

    /*
     * Test #5, create 2048 bit keypair with small exponent
     * expect: fail
     */
    BIO_printf(out, "  testing small exponent keypair generation (should FAIL)...\n");
    if (!fips_test_create_rsa_key(2048, 3))
    {
        BIO_printf(out, "  small exponent keypair generation didn't fail!!!\n");
        fips_update_testrails(TESTRAILS_TC_SMALL_E, TEST_FAILED, "small exponent not blocked");
        return 1;
    }
    fips_update_testrails(TESTRAILS_TC_SMALL_E, TEST_PASSED, "small exponent failed as expected");

    /*
     * Test #6, create 2048 bit keypair with even exponent
     * expect: fail
     */
    BIO_printf(out, "  testing even exponent keypair generation (should FAIL)...\n");
    if (!fips_test_create_rsa_key(2048, 65538))
    {
        BIO_printf(out, "  even exponent keypair generation didn't fail!!!\n");
        fips_update_testrails(TESTRAILS_TC_EVEN_E, TEST_FAILED, "even exponent not blocked");
        return 1;
    }
    fips_update_testrails(TESTRAILS_TC_EVEN_E, TEST_PASSED, "even exponent blocked as expected");

    /*
     * All tests have passed, return success
     */
    return 0;
}

/*
 * Returns 0 if the cipher failed to initialize
 */
static int fips_test_evp_cipher_disabled(char *name)
{
    const EVP_CIPHER *cipher = NULL;
    EVP_CIPHER_CTX ctx;

    cipher = EVP_get_cipherbyname(name);
    if (!cipher)
    {
        BIO_printf(out, "  Unable to locate cipher %s, test not completed!!!\n", name);
        return 1;
    }
    EVP_CIPHER_CTX_init(&ctx);
    if (EVP_CipherInit_ex(&ctx, cipher, NULL, NULL, NULL, 1)) 
    {
        BIO_printf(out, "  Cipher %s didn't fail!!!\n", name);
        return 1;
    }
    EVP_CIPHER_CTX_cleanup(&ctx);
    return 0;
}

/*
 * Tests disabled symmetric algorithms in FIPS mode.
 * OMNI-16587.
 *
 * Returns 0 on success
 */
static int fips_test_disabled_sym_algs()
{
    BIO_printf(out, " Symmetric algorithms tests...\n");

    /*
     * Test that AES-CFB mode is disabled.
     */
    BIO_printf(out, "  testing AES-CFB disabled (should FAIL)...\n");
    if (fips_test_evp_cipher_disabled("AES-128-CFB8")) 
    {
        fips_update_testrails(TESTRAILS_TC_AESCFB, TEST_FAILED, "cipher not disabled");
        return 1;
    }
    fips_update_testrails(TESTRAILS_TC_AESCFB, TEST_PASSED, "cipher is disabled");

    /*
     * Test that AES-OFB mode is disabled with FIPS on.
     */
    BIO_printf(out, "  testing AES-OFB disabled (should FAIL)...\n");
    if (fips_test_evp_cipher_disabled("AES-128-OFB")) 
    {
        fips_update_testrails(TESTRAILS_TC_AESOFB, TEST_FAILED, "cipher not disabled");
        return 1;
    }
    fips_update_testrails(TESTRAILS_TC_AESOFB, TEST_PASSED, "cipher is disabled");

    /*
     * Test that 3DES-CFB mode is disabled with FIPS on.
     */
    BIO_printf(out, "  testing 3DES-CFB disabled (should FAIL)...\n");
    if (fips_test_evp_cipher_disabled("DES-EDE3-CFB8")) 
    {
        fips_update_testrails(TESTRAILS_TC_3DESCFB, TEST_FAILED, "cipher not disabled");
        return 1;
    }
    fips_update_testrails(TESTRAILS_TC_3DESCFB, TEST_PASSED, "cipher is disabled");

    /*
     * Test that 3DES-OFB mode is disabled with FIPS on.
     */
    BIO_printf(out, "  testing 3DES-OFB disabled (should FAIL)...\n");
    if (fips_test_evp_cipher_disabled("DES-EDE3-OFB")) 
    {
        fips_update_testrails(TESTRAILS_TC_3DESOFB, TEST_FAILED, "cipher not disabled");
        return 1;
    }
    fips_update_testrails(TESTRAILS_TC_3DESOFB, TEST_PASSED, "cipher is disabled");

    /*
     * Test that DES-CFB mode is disabled with FIPS on.
     */
    BIO_printf(out, "  testing DES-CFB disabled (should FAIL)...\n");
    if (fips_test_evp_cipher_disabled("DES-CFB8")) 
    {
        fips_update_testrails(TESTRAILS_TC_DESCFB, TEST_FAILED, "cipher not disabled");
        return 1;
    }
    fips_update_testrails(TESTRAILS_TC_DESCFB, TEST_PASSED, "cipher is disabled");

    /*
     * Test that DES-OFB mode is disabled with FIPS on.
     */
    BIO_printf(out, "  testing DES-OFB disabled (should FAIL)...\n");
    if (fips_test_evp_cipher_disabled("DES-EDE-OFB")) 
    {
        fips_update_testrails(TESTRAILS_TC_DESOFB, TEST_FAILED, "cipher not disabled");
        return 1;
    }
    fips_update_testrails(TESTRAILS_TC_DESOFB, TEST_PASSED, "cipher is disabled");

    /*
     * Test that DES-ECB mode is disabled with FIPS on.
     */
    BIO_printf(out, "  testing DES-ECB disabled (should FAIL)...\n");
    if (fips_test_evp_cipher_disabled("DES-ECB")) 
    {
        fips_update_testrails(TESTRAILS_TC_DESECB, TEST_FAILED, "cipher not disabled");
        return 1;
    }
    fips_update_testrails(TESTRAILS_TC_DESECB, TEST_PASSED, "cipher is disabled");

    /*
     * Test that DES-CBC mode is disabled with FIPS on.
     */
    BIO_printf(out, "  testing DES-CBC disabled (should FAIL)...\n");
    if (fips_test_evp_cipher_disabled("DES-CBC")) 
    {
        fips_update_testrails(TESTRAILS_TC_DESCBC, TEST_FAILED, "cipher not disabled");
        return 1;
    }
    fips_update_testrails(TESTRAILS_TC_DESCBC, TEST_PASSED, "cipher is disabled");

    return 0;
}

/*
 * Test whether an EC curve can or cannot be
 * instantiated.  Provide the NID value of the curve
 * to test, and a boolean over whether it's expected
 * to work or not.
 *
 * Returns 0 on succes
 */
static int fips_test_ec_curve(int nid, int should_work)
{
    EC_KEY *key;

    key = EC_KEY_new_by_curve_name(nid);
    if (key && !should_work) 
    {
        EC_KEY_free(key);
        return 1;
    }
    if (!key && should_work)
    {
        return 1;
    }

    EC_KEY_free(key);
    return 0;
}

/*
 * Tests disabled asymmetric algorithms in FIPS mode.
 * OMNI-16587.
 *
 * Returns 0 on success
 */
static int fips_test_disabled_asym_algs()
{
    int ret = 1;
    DSA *dsa = NULL;

    BIO_printf(out, " Asymmetric algorithms tests...\n");

    /*
     * Test that DSA is disabled with FIPS on
     */
    BIO_printf(out, "  testing DSA disabled (should FAIL)...\n");
    dsa = DSA_new();
    if (dsa)
    {
        BIO_printf(out, "  DSA didn't fail!!!\n");
        fips_update_testrails(TESTRAILS_TC_DSA, TEST_FAILED, "cipher not disabled");
        goto err;
    }
    fips_update_testrails(TESTRAILS_TC_DSA, TEST_PASSED, "cipher is disabled");

    /*
     * Test that ECDSA P-224 is disabled with FIPS on
     */
    BIO_printf(out, "  testing EC P-224 curve disabled (should FAIL)...\n");
    if (fips_test_ec_curve(NID_secp224r1, 0)) 
    {
        BIO_printf(out, "  EC P-224 curve didn't fail!!!\n");
        fips_update_testrails(TESTRAILS_TC_P224, TEST_FAILED, "cipher not disabled");
        goto err;
    }
    fips_update_testrails(TESTRAILS_TC_P224, TEST_PASSED, "cipher is disabled");
    
    /*
     * Test that ECDSA P-521 is disabled with FIPS on
     */
    BIO_printf(out, "  testing EC P-521 curve disabled (should FAIL)...\n");
    if (fips_test_ec_curve(NID_secp521r1, 0)) 
    {
        BIO_printf(out, "  EC P-521 curve didn't fail!!!\n");
        fips_update_testrails(TESTRAILS_TC_P521, TEST_FAILED, "cipher not disabled");
        goto err;
    }
    fips_update_testrails(TESTRAILS_TC_P521, TEST_PASSED, "cipher is disabled");

    /*
     * Test that ECDSA P-256 is enabled with FIPS on
     */
    BIO_printf(out, "  testing EC P-256 curve enabled...\n");
    if (fips_test_ec_curve(NID_X9_62_prime256v1, 1)) 
    {
        BIO_printf(out, "  EC P-256 curve failed!!!\n");
        fips_update_testrails(TESTRAILS_TC_P256, TEST_FAILED, "cipher not enabled");
        goto err;
    }
    fips_update_testrails(TESTRAILS_TC_P256, TEST_PASSED, "cipher is enabled");

    /*
     * Test that ECDSA P-384 is enabled with FIPS on
     */
    BIO_printf(out, "  testing EC P-384 curve enabled...\n");
    if (fips_test_ec_curve(NID_secp384r1, 1)) 
    {
        BIO_printf(out, "  EC P-384 curve failed!!!\n");
        fips_update_testrails(TESTRAILS_TC_P384, TEST_FAILED, "cipher not enabled");
        goto err;
    }
    fips_update_testrails(TESTRAILS_TC_P384, TEST_PASSED, "cipher is enabled");

    ret = 0;
err:
    if (dsa) DSA_free(dsa);
    return ret;
}

/*
 * Tests disabled MAC algorithms in FIPS mode.
 * OMNI-16587.
 *
 * Returns 0 on success
 */
static int fips_test_disabled_mac_algs()
{
    int ret = 0;
    CMAC_CTX *ctx = NULL;
    unsigned char key[16] = {0x0};

    /*
     * Test that CMAC is disabled with FIPS on
     */
    BIO_printf(out, "  testing CMAC disabled...\n");
    ctx = CMAC_CTX_new();
    if (CMAC_Init(ctx, key, 16, EVP_aes_128_cbc(), NULL)) 
    {
        BIO_printf(out, "  CMAC init didn't fail!!!\n");
        fips_update_testrails(TESTRAILS_TC_CMAC, TEST_FAILED, "cipher not disabled");
        ret = 1;
    }
    fips_update_testrails(TESTRAILS_TC_CMAC, TEST_PASSED, "cipher is disabled");
    CMAC_CTX_free(ctx);

    return ret;
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
        fips_testrails_set_all(TEST_BLOCKED, "FIPS_mode_set failed");
        goto err;
    }
    OpenSSL_add_all_algorithms();

    /*
     * Start the testing
     */
    if (fips_test_rsa_keygen())
    {
        goto err;
    }
    if (fips_test_disabled_sym_algs()) 
    {
        goto err;
    }
    if (fips_test_disabled_asym_algs()) 
    {
        goto err;
    }
    if (fips_test_disabled_mac_algs()) 
    {
        goto err;
    }

    printf("FIPS test suite passed.\n");
    ret = 0;

 err:
    ERR_print_errors_fp(stderr);
    ERR_free_strings(); 
    OBJ_cleanup(); 
    EVP_cleanup(); 
    RAND_cleanup(); 
    CRYPTO_cleanup_all_ex_data();
    BIO_free(out);
    ERR_remove_thread_state(NULL);
    CRYPTO_mem_leaks_fp(stderr);
    EXIT(ret);
    return (ret);
}

#endif
