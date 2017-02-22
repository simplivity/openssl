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
#include <openssl/pem.h>
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


#define FIPS_RSA_KEY_1024   "keyP1.ss"  //Assumes tests are run from the test directory
#define FIPS_RSA_DATA       "the cow jumped over the moon."
#define FIPS_RSA_DATA_LEN   29
/*
 * Expected signature when using SHA-256 with keyP1.ss
 */
static unsigned char fips_rsa_sig[] = 
{
    0x31,0x8e,0x2e,0x6f,0xe5,0x42,0x74,0x4b,
    0x9d,0x64,0x07,0x90,0x3b,0x9a,0xb7,0x01,
    0x46,0x76,0x58,0xfe,0xf4,0x46,0xe0,0x1b,
    0x98,0x86,0x24,0x67,0x6b,0xac,0xe0,0x72,
    0xa4,0xe2,0x79,0xf7,0xed,0x36,0x31,0x2d,
    0x94,0x97,0xb7,0x5b,0x75,0xc1,0xab,0x2d,
    0x47,0x80,0xc9,0x4d,0xb2,0x4e,0xf0,0x1a,
    0x66,0xf2,0x9e,0x34,0xa0,0xaf,0x49,0x9e,
    0xf6,0x6f,0x14,0x48,0xfe,0xe1,0xd5,0xbe,
    0x21,0x1e,0x2e,0xa3,0x13,0x0e,0xc8,0x75,
    0x8e,0x9f,0x16,0x53,0x1b,0xb3,0x5b,0x99,
    0xbb,0xea,0x84,0xd3,0x9e,0x02,0x03,0xae,
    0x15,0x4e,0x39,0x81,0x74,0x3c,0xc9,0x82,
    0xe1,0x10,0xdd,0x2f,0xe8,0x54,0x4f,0xd3,
    0xa7,0x22,0x65,0x8e,0x24,0xae,0xa0,0x89,
    0xa4,0xa8,0xed,0x46,0x45,0xfe,0xa7,0xf3
};

/*
 * Runs all the RSA sign/verify tests to ensure
 * SP800-131a minimum key size constraints.
 *
 * Returns 0 on success
 */
static int fips_test_rsa_signverify()
{
    EVP_MD_CTX mctx;
    EVP_PKEY *key = NULL;
    BIO *b = NULL;
    int rv = 1;
    const EVP_MD *md = EVP_sha256();
    unsigned int s_len;
    unsigned char sig[256];

    BIO_printf(out, " RSA SP800-131a sign/verify tests...\n");

    /*
     * Read in the 1024 bit key. Since we can't create a 1024-bit
     * key while in FIPS mode, we load one from disk.
     */
    BIO_printf(out, "  loading static 1024-bit key from disk...\n");
    b = BIO_new(BIO_s_file());
    if (!b)
    {
        ERR_print_errors(out);
        goto err;
    }
    if (BIO_read_filename(b, FIPS_RSA_KEY_1024) <= 0) 
    {
        BIO_printf(out, "  Error opening %s, are you running fipstest from the test directory?\n", 
                FIPS_RSA_KEY_1024);
        ERR_print_errors(out);
        goto err;
    }
    key = PEM_read_bio_PrivateKey(b, NULL, NULL, NULL);
    if (!key) 
    {
        BIO_printf(out, "  Error reading %s\n", FIPS_RSA_KEY_1024);
        ERR_print_errors(out);
        goto err;
    }

    /*
     * Test #1, attempt signing using 1024 bit key
     */
    BIO_printf(out, "  attempt 1024 RSA signature generation (should FAIL)...\n");
    EVP_MD_CTX_init(&mctx);
    if (!EVP_SignInit_ex(&mctx, md, NULL))
    {
        BIO_printf(out, "  EVP_SignInit_ex failed\n");
        ERR_print_errors(out);
        goto err;
    }
    if (!EVP_SignUpdate(&mctx, FIPS_RSA_DATA, FIPS_RSA_DATA_LEN))
    {
        BIO_printf(out, "  EVP_SignUpdate failed\n");
        ERR_print_errors(out);
        goto err;
    }
    if (!EVP_SignFinal(&mctx, sig, &s_len, key)) 
    {
        BIO_printf(out, "  RSA signature generation failed as expected.\n");
        ERR_print_errors(out);
    } else {
        BIO_printf(out, "  RSA signing did not fail, test case failed!!!!\n");
        goto err;
    }
    EVP_MD_CTX_cleanup(&mctx);


    /*
     * Test #2, attempt verify using 1024 bit key
     */
    BIO_printf(out, "  attempt 1024 RSA verify (should succeed)...\n");
    EVP_MD_CTX_init(&mctx);
    if (!EVP_VerifyInit_ex(&mctx, md, NULL))
    {
        BIO_printf(out, "  EVP_VerifyInit_ex failed\n");
        ERR_print_errors(out);
        goto err;
    }
    if (!EVP_VerifyUpdate(&mctx, FIPS_RSA_DATA, FIPS_RSA_DATA_LEN))
    {
        BIO_printf(out, "  EVP_VerifyUpdate failed\n");
        ERR_print_errors(out);
        goto err;
    }
    if (EVP_VerifyFinal(&mctx, fips_rsa_sig, 128, key) <= 0) 
    {
        BIO_printf(out, "  RSA verify failed, test case failed!!!\n");
        ERR_print_errors(out);
        goto err;
    } else {
        BIO_printf(out, "  RSA verify succeeded, test case passed.\n");
    }
    EVP_MD_CTX_cleanup(&mctx);

    /*
     * All tests have passed, return success
     */
    rv = 0;

err:
    if (b != NULL) BIO_free(b);
    if (key != NULL) EVP_PKEY_free(key);

    return rv;
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


/*
 * This is used for Diffie-Hellman testing
 */
static DH *get_dh1024()
{
    static unsigned char dh1024_p[] = {
        0xF8, 0x81, 0x89, 0x7D, 0x14, 0x24, 0xC5, 0xD1, 0xE6, 0xF7, 0xBF, 0x3A,
        0xE4, 0x90, 0xF4, 0xFC, 0x73, 0xFB, 0x34, 0xB5, 0xFA, 0x4C, 0x56, 0xA2,
        0xEA, 0xA7, 0xE9, 0xC0, 0xC0, 0xCE, 0x89, 0xE1, 0xFA, 0x63, 0x3F, 0xB0,
        0x6B, 0x32, 0x66, 0xF1, 0xD1, 0x7B, 0xB0, 0x00, 0x8F, 0xCA, 0x87, 0xC2,
        0xAE, 0x98, 0x89, 0x26, 0x17, 0xC2, 0x05, 0xD2, 0xEC, 0x08, 0xD0, 0x8C,
        0xFF, 0x17, 0x52, 0x8C, 0xC5, 0x07, 0x93, 0x03, 0xB1, 0xF6, 0x2F, 0xB8,
        0x1C, 0x52, 0x47, 0x27, 0x1B, 0xDB, 0xD1, 0x8D, 0x9D, 0x69, 0x1D, 0x52,
        0x4B, 0x32, 0x81, 0xAA, 0x7F, 0x00, 0xC8, 0xDC, 0xE6, 0xD9, 0xCC, 0xC1,
        0x11, 0x2D, 0x37, 0x34, 0x6C, 0xEA, 0x02, 0x97, 0x4B, 0x0E, 0xBB, 0xB1,
        0x71, 0x33, 0x09, 0x15, 0xFD, 0xDD, 0x23, 0x87, 0x07, 0x5E, 0x89, 0xAB,
        0x6B, 0x7C, 0x5F, 0xEC, 0xA6, 0x24, 0xDC, 0x53,
    };
    static unsigned char dh1024_g[] = {
        0x02,
    };
    DH *dh;

    if ((dh = DH_new()) == NULL)
        return (NULL);
    dh->p = BN_bin2bn(dh1024_p, sizeof(dh1024_p), NULL);
    dh->g = BN_bin2bn(dh1024_g, sizeof(dh1024_g), NULL);
    if ((dh->p == NULL) || (dh->g == NULL)) {
        DH_free(dh);
        return (NULL);
    }
    return (dh);
}


/*
 * Tests Diffie-Hellman meets SP800-131a minimum key
 * size requirements. 
 *
 * Returns 0 on success
 */
static int fips_test_dh()
{
    DH *dh = NULL;

    BIO_printf(out, "  testing DH minimum key size...\n");
    dh = get_dh1024();
    if (!dh) 
    {
        BIO_printf(out, "  Unable to load 1024-bit DH parameters!!!\n");
        return 1;
    }

    /*
     * Test that 1024 bit diffie-hellman no longer works 
     * when FIPS is enabled.
     */
    if (DH_generate_key(dh))
    {
        BIO_printf(out, "  DH key generation succeed when it should fail, test case failed!!!\n");
        return 1;
    }
    BIO_printf(out, "  DH key generation failed as expected, test case passed.\n");

    if (dh) DH_free(dh);
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
        fips_testrails_set_all(TEST_BLOCKED, "FIPS_mode_set failed");
        goto err;
    }
    OpenSSL_add_all_algorithms();

    /*
     * Start the testing
     */
    if (fips_test_dh())
    {
        goto err;
    }
    if (fips_test_rsa_signverify())
    {
        goto err;
    }
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
