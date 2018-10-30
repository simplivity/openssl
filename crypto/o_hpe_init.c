/* o_svt_init.c */

# include <e_os.h>
# include <openssl/err.h>
#ifdef OPENSSL_FIPS
# include <openssl/fips.h>
# include <openssl/rand.h>

# ifndef OPENSL_SYS_WIN32
#  include <stdio.h>
#  include <string.h>
#  include <errno.h>
# endif

#ifdef OPENSSL_SYS_WIN32
# define snprintf(buf, len, format, ...) _snprintf_s(buf, len, len, format, __VA_ARGS__)
# define SVT_CFG_FILE "Simplivity\\Simplivity Arbiter\\var\\svtfs\\0\\myconf\\static\\svtarb.xml"
#else
# define SVT_CFG_FILE "/var/svtfs/0/myconf/static/svtfs.xml"
#endif
#define SVT_CFG_LINE_MAX 4096
#define SVT_CFG_FIPS_KNOB "<FIPSMode>"

void init_fips_mode_from_svtcfg(void)
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
            CRYPTOerr(CRYPTO_F_INIT_FIPS_MODE_FROM_SVTCFG, CRYPTO_R_FIPS_MODE_NOT_SUPPORTED);
            ERR_add_error_data(4, "OpenSSL unable to open SVT configuration: ", cfg_file_nm, " Error: ", strerror(errno));
        }
        if (!found_knob)
        {
            CRYPTOerr(CRYPTO_F_INIT_FIPS_MODE_FROM_SVTCFG, CRYPTO_R_FIPS_MODE_NOT_SUPPORTED);
            ERR_add_error_data(1, "WARNING: FIPSMode setting not in SVT config.");
        }
    }
}
#endif
