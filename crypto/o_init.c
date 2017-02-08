/* o_init.c */
/*
 * Written by Dr Stephen N Henson (steve@openssl.org) for the OpenSSL
 * project.
 */
/* ====================================================================
 * Copyright (c) 2011 The OpenSSL Project.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *
 * 3. All advertising materials mentioning features or use of this
 *    software must display the following acknowledgment:
 *    "This product includes software developed by the OpenSSL Project
 *    for use in the OpenSSL Toolkit. (http://www.openssl.org/)"
 *
 * 4. The names "OpenSSL Toolkit" and "OpenSSL Project" must not be used to
 *    endorse or promote products derived from this software without
 *    prior written permission. For written permission, please contact
 *    openssl-core@openssl.org.
 *
 * 5. Products derived from this software may not be called "OpenSSL"
 *    nor may "OpenSSL" appear in their names without prior written
 *    permission of the OpenSSL Project.
 *
 * 6. Redistributions of any form whatsoever must retain the following
 *    acknowledgment:
 *    "This product includes software developed by the OpenSSL Project
 *    for use in the OpenSSL Toolkit (http://www.openssl.org/)"
 *
 * THIS SOFTWARE IS PROVIDED BY THE OpenSSL PROJECT ``AS IS'' AND ANY
 * EXPRESSED OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE OpenSSL PROJECT OR
 * ITS CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 * ====================================================================
 *
 */

#include <e_os.h>
#include <openssl/err.h>
#ifdef OPENSSL_FIPS
# include <openssl/fips.h>
# include <openssl/rand.h>
# ifndef OPENSL_SYS_WIN32
#  include <stdio.h>
#  include <string.h>
#  include <errno.h>
# endif
#endif


#ifdef OPENSSL_SYS_WIN32
# define snprintf(buf, len, format, ...) _snprintf_s(buf, len, len, format, __VA_ARGS__)
# define SVT_CFG_FILE "Simplivity\\Simplivity Arbiter\\var\\svtfs\\0\\myconf\\static\\svtarb.xml"
#else
# define SVT_CFG_FILE "/var/svtfs/0/myconf/static/svtfs.xml"
#endif
#define SVT_CFG_LINE_MAX 4096
#define SVT_CFG_FIPS_KNOB "<FIPSMode>"

static void init_fips_mode_from_svtcfg(void)
{
    char buf[SVT_CFG_LINE_MAX];
    char cfg_file_nm[1024];
    FILE *cfg_file;
    int found_knob = 0;

#ifdef OPENSSL_SYS_WIN32
    snprintf(cfg_file_nm, 1024, "%s\\%s", getenv("ProgramFiles"), SVT_CFG_FILE);
#else
    snprintf(cfg_file_nm, 256, "%s", SVT_CFG_FILE);
#endif
	
    if (getenv("SVT_FORCE_FIPS_MODE") != NULL) 
    {
        if (!FIPS_mode_set(1))
        {
            CRYPTOerr(CRYPTO_F_INIT_FIPS_MODE_FROM_SVTCFG, CRYPTO_R_FIPS_MODE_NOT_SUPPORTED);
            ERR_add_error_data(1, "Failed to enter FIPS mode.");
        }
    } 
    else 
    { 
        /* 
         * Open SVT config file and look for desired FIPS state
         */
        cfg_file = fopen(cfg_file_nm, "r"); 
        if (cfg_file > 0) 
        {
            while (fgets(buf, SVT_CFG_LINE_MAX, cfg_file)) 
            {
                /*
                 * Check if this line contains the FIPS setting
                 */
                if (strstr(buf, SVT_CFG_FIPS_KNOB)) 
                {
                    found_knob = 1;
                    /*
                     * See if FIPS should be enabled
                     */
                    if (strstr(buf, "true")) 
                    {
                        if (!FIPS_mode_set(1))
                        {
                            CRYPTOerr(CRYPTO_F_INIT_FIPS_MODE_FROM_SVTCFG, CRYPTO_R_FIPS_MODE_NOT_SUPPORTED);
                            ERR_add_error_data(1, "Failed to enter FIPS mode.");
                        }
                        break;
                    }
                }
            }
            fclose(cfg_file);
        } 
        else 
        {	
            fprintf(stderr,"Unable to determine desired FIPS mode: unable to open %s\n", cfg_file_nm);
            CRYPTOerr(CRYPTO_F_INIT_FIPS_MODE_FROM_SVTCFG, CRYPTO_R_FIPS_MODE_NOT_SUPPORTED);
            ERR_add_error_data(2, "OpenSSL unable open SVT configuration: ", strerror(errno));
        }   
        if (!found_knob)
        {
            CRYPTOerr(CRYPTO_F_INIT_FIPS_MODE_FROM_SVTCFG, CRYPTO_R_FIPS_MODE_NOT_SUPPORTED);
            ERR_add_error_data(1, "WARNING: FIPSMode setting not in SVT config.");
        }
    }
}

/*
 * Perform any essential OpenSSL initialization operations. Currently only
 * sets FIPS callbacks
 */

void OPENSSL_init(void)
{
    static int done = 0;
    if (done)
        return;
    done = 1;
#ifdef OPENSSL_FIPS
    FIPS_set_locking_callbacks(CRYPTO_lock, CRYPTO_add_lock);
# ifndef OPENSSL_NO_DEPRECATED
    FIPS_crypto_set_id_callback(CRYPTO_thread_id);
# endif
    FIPS_set_error_callbacks(ERR_put_error, ERR_add_error_vdata);
    FIPS_set_malloc_callbacks(CRYPTO_malloc, CRYPTO_free);
    RAND_init_fips();
    init_fips_mode_from_svtcfg();
#endif
#if 0
    fprintf(stderr, "Called OPENSSL_init\n");
#endif
}
