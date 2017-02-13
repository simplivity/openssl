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
