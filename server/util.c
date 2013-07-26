/* Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/*
 * util.c: string utility things
 *
 * 3/21/93 Rob McCool
 * 1995-96 Many changes by the Apache Software Foundation
 *
 */

/* Debugging aid:
 * #define DEBUG            to trace all cfg_open*()/cfg_closefile() calls
 * #define DEBUG_CFG_LINES  to trace every line read from the config files
 */

#include "apr.h"
#include "apr_strings.h"
#include "apr_lib.h"

#define APR_WANT_STDIO
#define APR_WANT_STRFUNC
#include "apr_want.h"

#if APR_HAVE_UNISTD_H
#include <unistd.h>
#endif
#if APR_HAVE_NETDB_H
#include <netdb.h>              /* for gethostbyname() */
#endif

#define CORE_PRIVATE

#include "ap_config.h"
#include "apr_base64.h"
#include "httpd.h"
#include "http_main.h"
#include "http_log.h"
#include "http_protocol.h"
#include "http_config.h"
#include "util_ebcdic.h"

#ifdef HAVE_PWD_H
#include <pwd.h>
#endif
#ifdef HAVE_GRP_H
#include <grp.h>
#endif

/* A bunch of functions in util.c scan strings looking for certain characters.
 * To make that more efficient we encode a lookup table.  The test_char_table
 * is generated automatically by gen_test_char.c.
 */
#include "test_char.h"

/* we assume the folks using this ensure 0 <= c < 256... which means
 * you need a cast to (unsigned char) first, you can't just plug a
 * char in here and get it to work, because if char is signed then it
 * will first be sign extended.
 */
#define TEST_CHAR(c, f)        (test_char_table[(unsigned)(c)] & (f))

/* Win32/NetWare/OS2 need to check for both forward and back slashes
 * in ap_getparents() and ap_escape_url.
 */
#ifdef CASE_BLIND_FILESYSTEM
#define IS_SLASH(s) ((s == '/') || (s == '\\'))
#else
#define IS_SLASH(s) (s == '/')
#endif

/* 浏览器和关键字查询数据结构定义 */
#define COLUMN_NAME           0
#define COLUMN_DOMAINNAME     1
#define COLUMN_ENCODED        2

#define BROWSER_REGEX_NUM     7
#define RECONNECT_NUM         3

typedef enum {
    ANDROID,
    MAEMO,
    LINU,
    WPS,
    CYGWIN62,
    WNT62,
    WIN8,
    CYGWIN61,
    WNT61,
    WIN7,
    CYGWIN60,
    WNT60,
    WINVISTA,
    CYGWIN52,
    WNT52,
    WINSERVER,
    CYGWIN51,
    WNT51,
    WINXP,
    CYGWIN50,
    WNT50,
    WIN2000,
    CYGWIN40,
    WNT40,
    WINNT,
    WINDOWSNT,
    CYGWINME49,
    WIN9X49,
    WINME,
    CYGWIN9841,
    WIN98,
    WINDOWS98,
    CYGWIN9540,
    WIN32,
    WIN95,
    WINDOWS95,
    WINPOS,
    IEMOBILE,
    WINDOWSMB,
    WINDOWSCE,
    IPOD,
    IPAD,
    IPHONE,
    IOS1,
    DARWIN,
    MACINTOSH,
    POWERMAC,
    MACPOWER,
    MACPPC,
    PPC,
    MACPOWERPC,
    MACOS,
    WEBOS,
    PALMWEBOS,
    PALMOS,
    PALM_OS,
    BB10,
    BLACKBERRY,
    RIMTOS,
    ONX,
    SYMBOS,
    SYMBIANOS,
    SYMBIAN_OS,
    BADA,
    SUNOS,
    AIX1,
    HP_UX,
    OPENVMS,
    FREEDSD,
    NETBSD,
    OPENBSD,
    DRAGONFLY,
    SYLLABLE,
    NINWII,
    NITRO,
    NINDS,
    NINDSI,
    PSPORT,
    PSTATION3,
    IRIX,
    OSF1,
    OS21,
    BEOS,
    AMIGA,
    AMIGAOS
} os_type_t;

typedef enum {
    AND,
    MAE,
    LIN,
    WPH,
    WI8,
    WI7,
    WVI,
    WS3,
    WXP,
    W2K,
    WNT,
    WME,
    W98,
    W95,
    WMO,
    WCE,
    IPD,
    IPA,
    IPH,
    IOS,
    MAC,
    WOS,
    POS,
    BBX,
    BLB,
    QNX,
    SYM,
    SBA,
    SOS,
    AIX,
    HPX,
    VMS,
    BSD,
    NBS,
    OBS,
    DFB,
    SYL,
    WII,
    NDS,
    DSI,
    PSP,
    PS3,
    IRI,
    T64,
    OS2,
    BEO,
    AMI
} os_id_t;

typedef enum {
    ABROWSE,
    AMAYA,
    AMIGAVOY,
    AMIGA_AWEB,
    ARORA,
    BEONEX,
    BLACKBERRY1,
    BB101,
    PLAYBOOK,
    BROWSEX,
    CHIMERA,
    CAMINO,
    CHESHIRE,
    CRMO,
    CHROME,
    CHROMEFRAME,
    COMETBIRD,
    DILLO,
    ELINKS,
    EPIPHANY,
    FENNEC,
    DOLFIN,
    PHOENIX,
    MOZILLAFB,
    FIREBIRD,
    BONECHO,
    MINEFIELD,
    NAMOROKA,
    SHIRETOKO,
    GRANPA,
    ICEWS,
    ICECAT,
    FIREFOX,
    FLOCK,
    FLUID,
    GALEON,
    GOOGLEEH,
    HANA,
    HOTJAVA,
    IBROWSE,
    ICAB,
    MSIE,
    MINEXP,
    INEXP,
    IRON,
    KAPIKO,
    KAZEHA,
    KMELEON,
    KONQUEROR,
    LINKS,
    LYNX,
    MIDORI,
    MOZILLA,
    GNUZILLA,
    ICEAPE,
    SEAMY,
    MOSAIC,
    NCSAMC,
    NAVIGATOR,
    NETSP6,
    NETSP,
    OMNIWEB,
    NIOPERA,
    OPERA,
    REKONQ,
    SQFARI,
    APPWEBKIT,
    TITANIUM,
    WEBOS1,
    WEBPRO,
    SEIE,
    SEWK,
    QQBROWSER,
    MAXTHON,
    TAOBAO,
    QIHU,
    TENCENT
} browser_type_t;

typedef enum {
    AB, 
    AM, 
    AV, 
    AW, 
    AR, 
    BE,  
    BB, 
    B2, 
    BP, 
    BX, 
    CA,
    CS, 
    CH, 
    CF, 
    CO, 
    DI, 
    EL, 
    EP, 
    FE, 
    DF, 
    PX, 
    FB, 
    FX, 
    FL, 
    FD, 
    GA, 
    GE, 
    HA, 
    HJ, 
    IB, 
    IC, 
    IE, 
    IR, 
    KP, 
    KZ, 
    KM, 
    KO, 
    LI, 
    LX, 
    MI, 
    MO, 
    SM, 
    MC, 
    NS, 
    OW, 
    OP, 
    RK, 
    SF, 
    TI, 
    WO, 
    WP, 
    SE,
    SK,
    QQ, 
    MT, 
    TB, 
    QT, 
    TT,
    S6
} browser_id_t;

enum SEARCH_ENGINE_ID {
    ENGINE_MIN = 0,
    ENGINE_GOOGLE = ENGINE_MIN,
    ENGINE_BAIDU,
    ENGINE_SOSO,
    ENGINE_SOGOU,
    ENGINE_YAHOO_COM,
    ENGINE_YAHOO_CN,
    ENGINE_YOUDAO,
    ENGINE_BING,
    ENGINE_YISOU,
    ENGINE_JIKE,
    ENGINE_LYCOS,
    ENGINE_360SO,
    ENGINE_MAX = ENGINE_360SO,
    ENGINE_UNKNOW,
};

typedef enum WEB_ACCESS_TYPE_E {
    ACCESS_MIN = 1,
    ACCESS_DIRECT = ACCESS_MIN,
    ACCESS_SEARCH,
    ACCESS_WEB,
    ACCESS_AD,
    ACCESS_MAX = ACCESS_AD
} WEB_ACCESS_TYPE_T;

typedef struct os_member_s {
    int id;
    char *name;
    char *short_name;
    char *os_family;
} os_member_t;

typedef struct browser_member_s {
    int id;
    char *name;
    int major_number;
    int minor_number;
    char *version;
    char *browser_family;
} browser_member_t;

char *browser_type[] = {
    "abrowse",
    "amaya",
    "amigavoyager",
    "amiga-aweb",
    "arora",
    "beonex",
    "blackberry",
    "bb10",
    "playbook",
    "browsex",
    "chimera",
    "camino",
    "cheshire",
    "crmo",
    "chrome",
    "chromeframe",
    "cometbird",
    "dillo",
    "elinks",
    "epiphany",
    "fennec",
    "dolfin",
    "phoenix",
    "mozilla firebird",
    "firebird",
    "bonecho",
    "minefield",
    "namoroka",
    "shiretoko",
    "granparadiso",
    "iceweasel",
    "icecat",
    "firefox",
    "flock",
    "fluid",
    "galeon",
    "google earth",
    "hana",
    "hotjava",
    "ibrowse",
    "icab",
    "msie",
    "microsoft internet explorer",
    "internet explorer",
    "iron",
    "kapiko",
    "kazehakase",
    "k-meleon",
    "konqueror",
    "links",
    "lynx",
    "midori",
    "mozilla",
    "gnuzilla",
    "iceape",
    "seamonkey",
    "mosaic",
    "ncsa mosaic",
    "navigator",
    "netscape6",
    "netscape",
    "omniweb",
    "nitro) opera",
    "opera",
    "rekonq",
    "safari",
    "applewebkit",
    "titanium",
    "webos",
    "webpro",
    "se",
    "qqbrowser",
    "maxthon",
    "taobrowser",
    "qihu theworld",
    "tencenttraveler"
};

char *os_type[] = {
    "Android",
    "Maemo",
    "Linux",
    "WP7",
    "CYGWIN_NT-6.2",
    "Windows NT 6.2",
    "Windows 8",
    "CYGWIN_NT-6.1",
    "Windows NT 6.1",
    "Windows 7",
    "CYGWIN_NT-6.0",
    "Windows NT 6.0",
    "Windows Vista",
    "CYGWIN_NT-5.2",
    "Windows NT 5.2",
    "Windows Server 2003 / XP x64",
    "CYGWIN_NT-5.1",
    "Windows NT 5.1",
    "Windows XP",
    "CYGWIN_NT-5.0",
    "Windows NT 5.0",
    "Windows 2000",
    "CYGWIN_NT-4.0",
    "Windows NT 4.0",
    "WinNT",
    "Windows NT",
    "CYGWIN_ME-4.90",
    "Win 9x 4.90",
    "Windows ME",
    "CYGWIN_98-4.10",
    "Win98",
    "Windows 98",
    "CYGWIN_95-4.0",
    "Win32",
    "Win95",
    "Windows 95",
    "Windows Phone OS",
    "IEMobile",
    "Windows Mobile",
    "Windows CE",
    "iPod",
    "iPad",
    "iPhone",
    "iOS",
    "Darwin",
    "Macintosh",
    "Power Macintosh",
    "Mac_PowerPC",
    "Mac PPC",
    "PPC",
    "Mac PowerPC",
    "Mac OS",
    "webOS",
    "Palm webOS",
    "PalmOS",
    "Palm OS",
    "BB10",
    "BlackBerry",
    "RIM Tablet OS",
    "QNX",
    "SymbOS",
    "Symbian OS",
    "SymbianOS",
    "bada",
    "SunOS",
    "AIX",
    "HP-UX",
    "OpenVMS",
    "FreeBSD",
    "NetBSD",
    "OpenBSD",
    "DragonFly",
    "Syllable",
    "Nintendo Wii",
    "Nitro",
    "Nintendo DS",
    "Nintendo DSi",
    "PlayStation Portable",
    "PlayStation 3",
    "IRIX",
    "OSF1",
    "OS/2",
    "BEOS",
    "Amiga",
    "AmigaOS"
};

char *browser_name[] = {
    "ABrowse",
    "Amaya",
    "AmigaVoyager",
    "Amiga AWeb",
    "Arora",
    "Beonex", 
    "BlackBerry",
    "BlackBerry",
    "PlayBook",
    "BrowseX",
    "Chimera",
    "Cheshire",
    "Chrome",
    "Chrome Frame",
    "CometBird",
    "Dillo",
    "ELinks",
    "Epiphany",
    "Fennec",
    "Dolfin",
    "Phoenix",
    "Firebird",
    "Firefox",
    "Flock",
    "Fluid",
    "Galeon",
    "Google Earth",
    "Hana",
    "HotJava",
    "IBrowse",
    "iCab",
    "Internet Explorer",
    "Iron",
    "Kapiko",
    "Kazehakase",
    "K-Meleon",
    "Konqueror",
    "Links",
    "Lynx",
    "Midori",
    "Mozilla",
    "SeaMonkey",
    "NCSA Mosaic",
    "Netscape",
    "OmniWeb",
    "Opera",
    "Rekonq",
    "Safari",
    "Titanium",
    "Palm webOS",
    "WebPro",
    "Sogou",
    "Sogou",
    "QQBrowser",
    "Maxthon",
    "TaoBrowser",
    "Theworld",
    "TencentTraveler",
    "360 browser"
};

char *os_name[] = {
    "Android",
    "Maemo",
    "Linux",
    "Windows Phone OS",
    "Windows 8",
    "Windows 7",
    "Windows Vista",
    "Windows Server 2003 / XP x64",
    "Windows XP",
    "Windows 2000",
    "Windows NT",
    "Windows Me",
    "Windows 98",
    "Windows 95",
    "Windows Mobile",
    "Windows CE",
    "iPod",
    "iPad",
    "iPhone",
    "iOS",
    "Mac OS",
    "Palm webOS",
    "Palm OS",
    "BB10",
    "BlackBerry",
    "QNX",
    "SymbianOS",
    "bada",
    "SunOS",
    "AIX",
    "HP-UX",
    "OpenVMS",
    "FreeBSD",
    "NetBSD",
    "OpenBSD",
    "DragonFly",
    "Syllable",
    "Nintendo Wii",
    "Nintendo DS",
    "Nintendo DSi",
    "PlayStation Portable",
    "PlayStation 3",
    "IRIX",
    "Tru64",
    "OS/2",
    "BeOS",
    "AmigaOS"
};


static char *g_search_engine_info[][3] = { \
        {"google", "google.com", "UTF-8"}, \
        {"baidu", "baidu.com", "GBK"}, \
        {"soso", "soso.com", "GBK"}, \
        {"sogou", "sogou.com", "GBK"}, \
        {"yahoo", "yahoo.com", "UTF-8"}, \
        {"yahoo", "yahoo.cn", "UTF-8"}, \
        {"youdao", "youdao.com", "UTF-8"}, \
        {"bing", "bing.com", "UTF-8"}, \
        {"yisou", "yisou.com", "UTF-8"}, \
        {"jike", "jike.com", "UTF-8"}, \
        {"lycos", "lycos.com", "UTF-8"}, \
        {"360so", "so.com", "UTF-8"}, \
    };

static ap_regex_t *g_browser_regex[BROWSER_REGEX_NUM];
/*
 * Examine a field value (such as a media-/content-type) string and return
 * it sans any parameters; e.g., strip off any ';charset=foo' and the like.
 */
AP_DECLARE(char *) ap_field_noparam(apr_pool_t *p, const char *intype)
{
    const char *semi;

    if (intype == NULL) return NULL;

    semi = ap_strchr_c(intype, ';');
    if (semi == NULL) {
        return apr_pstrdup(p, intype);
    }
    else {
        while ((semi > intype) && apr_isspace(semi[-1])) {
            semi--;
        }
        return apr_pstrndup(p, intype, semi - intype);
    }
}

AP_DECLARE(char *) ap_ht_time(apr_pool_t *p, apr_time_t t, const char *fmt,
                              int gmt)
{
    apr_size_t retcode;
    char ts[MAX_STRING_LEN];
    char tf[MAX_STRING_LEN];
    apr_time_exp_t xt;

    if (gmt) {
        const char *f;
        char *strp;

        apr_time_exp_gmt(&xt, t);
        /* Convert %Z to "GMT" and %z to "+0000";
         * on hosts that do not have a time zone string in struct tm,
         * strftime must assume its argument is local time.
         */
        for(strp = tf, f = fmt; strp < tf + sizeof(tf) - 6 && (*strp = *f)
            ; f++, strp++) {
            if (*f != '%') continue;
            switch (f[1]) {
            case '%':
                *++strp = *++f;
                break;
            case 'Z':
                *strp++ = 'G';
                *strp++ = 'M';
                *strp = 'T';
                f++;
                break;
            case 'z': /* common extension */
                *strp++ = '+';
                *strp++ = '0';
                *strp++ = '0';
                *strp++ = '0';
                *strp = '0';
                f++;
                break;
            }
        }
        *strp = '\0';
        fmt = tf;
    }
    else {
        apr_time_exp_lt(&xt, t);
    }

    /* check return code? */
    apr_strftime(ts, &retcode, MAX_STRING_LEN, fmt, &xt);
    ts[MAX_STRING_LEN - 1] = '\0';
    return apr_pstrdup(p, ts);
}

/* Roy owes Rob beer. */
/* Rob owes Roy dinner. */

/* These legacy comments would make a lot more sense if Roy hadn't
 * replaced the old later_than() routine with util_date.c.
 *
 * Well, okay, they still wouldn't make any sense.
 */

/* Match = 0, NoMatch = 1, Abort = -1
 * Based loosely on sections of wildmat.c by Rich Salz
 * Hmmm... shouldn't this really go component by component?
 */
AP_DECLARE(int) ap_strcmp_match(const char *str, const char *expected)
{
    int x, y;

    for (x = 0, y = 0; expected[y]; ++y, ++x) {
        if ((!str[x]) && (expected[y] != '*'))
            return -1;
        if (expected[y] == '*') {
            while (expected[++y] == '*');
            if (!expected[y])
                return 0;
            while (str[x]) {
                int ret;
                if ((ret = ap_strcmp_match(&str[x++], &expected[y])) != 1)
                    return ret;
            }
            return -1;
        }
        else if ((expected[y] != '?') && (str[x] != expected[y]))
            return 1;
    }
    return (str[x] != '\0');
}

AP_DECLARE(int) ap_strcasecmp_match(const char *str, const char *expected)
{
    int x, y;

    for (x = 0, y = 0; expected[y]; ++y, ++x) {
        if (!str[x] && expected[y] != '*')
            return -1;
        if (expected[y] == '*') {
            while (expected[++y] == '*');
            if (!expected[y])
                return 0;
            while (str[x]) {
                int ret;
                if ((ret = ap_strcasecmp_match(&str[x++], &expected[y])) != 1)
                    return ret;
            }
            return -1;
        }
        else if (expected[y] != '?'
                 && apr_tolower(str[x]) != apr_tolower(expected[y]))
            return 1;
    }
    return (str[x] != '\0');
}

/* We actually compare the canonical root to this root, (but we don't
 * waste time checking the case), since every use of this function in
 * httpd-2.1 tests if the path is 'proper', meaning we've already passed
 * it through apr_filepath_merge, or we haven't.
 */
AP_DECLARE(int) ap_os_is_path_absolute(apr_pool_t *p, const char *dir)
{
    const char *newpath;
    const char *ourdir = dir;
    if (apr_filepath_root(&newpath, &dir, 0, p) != APR_SUCCESS
            || strncmp(newpath, ourdir, strlen(newpath)) != 0) {
        return 0;
    }
    return 1;
}

AP_DECLARE(int) ap_is_matchexp(const char *str)
{
    register int x;

    for (x = 0; str[x]; x++)
        if ((str[x] == '*') || (str[x] == '?'))
            return 1;
    return 0;
}

/*
 * Here's a pool-based interface to the POSIX-esque ap_regcomp().
 * Note that we return ap_regex_t instead of being passed one.
 * The reason is that if you use an already-used ap_regex_t structure,
 * the memory that you've already allocated gets forgotten, and
 * regfree() doesn't clear it. So we don't allow it.
 */

static apr_status_t regex_cleanup(void *preg)
{
    ap_regfree((ap_regex_t *) preg);
    return APR_SUCCESS;
}

AP_DECLARE(ap_regex_t *) ap_pregcomp(apr_pool_t *p, const char *pattern,
                                     int cflags)
{
    ap_regex_t *preg = apr_palloc(p, sizeof *preg);

    if (ap_regcomp(preg, pattern, cflags)) {
        return NULL;
    }

    apr_pool_cleanup_register(p, (void *) preg, regex_cleanup,
                              apr_pool_cleanup_null);

    return preg;
}

AP_DECLARE(void) ap_pregfree(apr_pool_t *p, ap_regex_t *reg)
{
    ap_regfree(reg);
    apr_pool_cleanup_kill(p, (void *) reg, regex_cleanup);
}

/*
 * Similar to standard strstr() but we ignore case in this version.
 * Based on the strstr() implementation further below.
 */
AP_DECLARE(char *) ap_strcasestr(const char *s1, const char *s2)
{
    char *p1, *p2;
    if (*s2 == '\0') {
        /* an empty s2 */
        return((char *)s1);
    }
    while(1) {
        for ( ; (*s1 != '\0') && (apr_tolower(*s1) != apr_tolower(*s2)); s1++);
        if (*s1 == '\0') {
            return(NULL);
        }
        /* found first character of s2, see if the rest matches */
        p1 = (char *)s1;
        p2 = (char *)s2;
        for (++p1, ++p2; apr_tolower(*p1) == apr_tolower(*p2); ++p1, ++p2) {
            if (*p1 == '\0') {
                /* both strings ended together */
                return((char *)s1);
            }
        }
        if (*p2 == '\0') {
            /* second string ended, a match */
            break;
        }
        /* didn't find a match here, try starting at next character in s1 */
        s1++;
    }
    return((char *)s1);
}

/*
 * Returns an offsetted pointer in bigstring immediately after
 * prefix. Returns bigstring if bigstring doesn't start with
 * prefix or if prefix is longer than bigstring while still matching.
 * NOTE: pointer returned is relative to bigstring, so we
 * can use standard pointer comparisons in the calling function
 * (eg: test if ap_stripprefix(a,b) == a)
 */
AP_DECLARE(const char *) ap_stripprefix(const char *bigstring,
                                        const char *prefix)
{
    const char *p1;

    if (*prefix == '\0')
        return bigstring;

    p1 = bigstring;
    while (*p1 && *prefix) {
        if (*p1++ != *prefix++)
            return bigstring;
    }
    if (*prefix == '\0')
        return p1;

    /* hit the end of bigstring! */
    return bigstring;
}

/* This function substitutes for $0-$9, filling in regular expression
 * submatches. Pass it the same nmatch and pmatch arguments that you
 * passed ap_regexec(). pmatch should not be greater than the maximum number
 * of subexpressions - i.e. one more than the re_nsub member of ap_regex_t.
 *
 * input should be the string with the $-expressions, source should be the
 * string that was matched against.
 *
 * It returns the substituted string, or NULL on error.
 *
 * Parts of this code are based on Henry Spencer's regsub(), from his
 * AT&T V8 regexp package.
 */

AP_DECLARE(char *) ap_pregsub(apr_pool_t *p, const char *input,
                              const char *source, size_t nmatch,
                              ap_regmatch_t pmatch[])
{
    const char *src = input;
    char *dest, *dst;
    char c;
    size_t no;
    int len;

    if (!source)
        return NULL;
    if (!nmatch)
        return apr_pstrdup(p, src);

    /* First pass, find the size */

    len = 0;

    while ((c = *src++) != '\0') {
        if (c == '&')
            no = 0;
        else if (c == '$' && apr_isdigit(*src))
            no = *src++ - '0';
        else
            no = 10;

        if (no > 9) {                /* Ordinary character. */
            if (c == '\\' && (*src == '$' || *src == '&'))
                src++;
            len++;
        }
        else if (no < nmatch && pmatch[no].rm_so < pmatch[no].rm_eo) {
            len += pmatch[no].rm_eo - pmatch[no].rm_so;
        }

    }

    dest = dst = apr_pcalloc(p, len + 1);

    /* Now actually fill in the string */

    src = input;

    while ((c = *src++) != '\0') {
        if (c == '&')
            no = 0;
        else if (c == '$' && apr_isdigit(*src))
            no = *src++ - '0';
        else
            no = 10;

        if (no > 9) {                /* Ordinary character. */
            if (c == '\\' && (*src == '$' || *src == '&'))
                c = *src++;
            *dst++ = c;
        }
        else if (no < nmatch && pmatch[no].rm_so < pmatch[no].rm_eo) {
            len = pmatch[no].rm_eo - pmatch[no].rm_so;
            memcpy(dst, source + pmatch[no].rm_so, len);
            dst += len;
        }

    }
    *dst = '\0';

    return dest;
}

/*
 * Parse .. so we don't compromise security
 */
AP_DECLARE(void) ap_getparents(char *name)
{
    char *next;
    int l, w, first_dot;

    /* Four paseses, as per RFC 1808 */
    /* a) remove ./ path segments */
    for (next = name; *next && (*next != '.'); next++) {
    }

    l = w = first_dot = next - name;
    while (name[l] != '\0') {
        if (name[l] == '.' && IS_SLASH(name[l + 1])
            && (l == 0 || IS_SLASH(name[l - 1])))
            l += 2;
        else
            name[w++] = name[l++];
    }

    /* b) remove trailing . path, segment */
    if (w == 1 && name[0] == '.')
        w--;
    else if (w > 1 && name[w - 1] == '.' && IS_SLASH(name[w - 2]))
        w--;
    name[w] = '\0';

    /* c) remove all xx/../ segments. (including leading ../ and /../) */
    l = first_dot;

    while (name[l] != '\0') {
        if (name[l] == '.' && name[l + 1] == '.' && IS_SLASH(name[l + 2])
            && (l == 0 || IS_SLASH(name[l - 1]))) {
            register int m = l + 3, n;

            l = l - 2;
            if (l >= 0) {
                while (l >= 0 && !IS_SLASH(name[l]))
                    l--;
                l++;
            }
            else
                l = 0;
            n = l;
            while ((name[n] = name[m]))
                (++n, ++m);
        }
        else
            ++l;
    }

    /* d) remove trailing xx/.. segment. */
    if (l == 2 && name[0] == '.' && name[1] == '.')
        name[0] = '\0';
    else if (l > 2 && name[l - 1] == '.' && name[l - 2] == '.'
             && IS_SLASH(name[l - 3])) {
        l = l - 4;
        if (l >= 0) {
            while (l >= 0 && !IS_SLASH(name[l]))
                l--;
            l++;
        }
        else
            l = 0;
        name[l] = '\0';
    }
}

AP_DECLARE(void) ap_no2slash(char *name)
{
    char *d, *s;

    s = d = name;

#ifdef HAVE_UNC_PATHS
    /* Check for UNC names.  Leave leading two slashes. */
    if (s[0] == '/' && s[1] == '/')
        *d++ = *s++;
#endif

    while (*s) {
        if ((*d++ = *s) == '/') {
            do {
                ++s;
            } while (*s == '/');
        }
        else {
            ++s;
        }
    }
    *d = '\0';
}


/*
 * copy at most n leading directories of s into d
 * d should be at least as large as s plus 1 extra byte
 * assumes n > 0
 * the return value is the ever useful pointer to the trailing \0 of d
 *
 * MODIFIED FOR HAVE_DRIVE_LETTERS and NETWARE environments,
 * so that if n == 0, "/" is returned in d with n == 1
 * and s == "e:/test.html", "e:/" is returned in d
 * *** See also directory_walk in modules/http/http_request.c

 * examples:
 *    /a/b, 0  ==> /  (true for all platforms)
 *    /a/b, 1  ==> /
 *    /a/b, 2  ==> /a/
 *    /a/b, 3  ==> /a/b/
 *    /a/b, 4  ==> /a/b/
 *
 *    c:/a/b 0 ==> /
 *    c:/a/b 1 ==> c:/
 *    c:/a/b 2 ==> c:/a/
 *    c:/a/b 3 ==> c:/a/b
 *    c:/a/b 4 ==> c:/a/b
 */
AP_DECLARE(char *) ap_make_dirstr_prefix(char *d, const char *s, int n)
{
    if (n < 1) {
        *d = '/';
        *++d = '\0';
        return (d);
    }

    for (;;) {
        if (*s == '\0' || (*s == '/' && (--n) == 0)) {
            *d = '/';
            break;
        }
        *d++ = *s++;
    }
    *++d = 0;
    return (d);
}


/*
 * return the parent directory name including trailing / of the file s
 */
AP_DECLARE(char *) ap_make_dirstr_parent(apr_pool_t *p, const char *s)
{
    const char *last_slash = ap_strrchr_c(s, '/');
    char *d;
    int l;

    if (last_slash == NULL) {
        return apr_pstrdup(p, "");
    }
    l = (last_slash - s) + 1;
    d = apr_palloc(p, l + 1);
    memcpy(d, s, l);
    d[l] = 0;
    return (d);
}


AP_DECLARE(int) ap_count_dirs(const char *path)
{
    register int x, n;

    for (x = 0, n = 0; path[x]; x++)
        if (path[x] == '/')
            n++;
    return n;
}

AP_DECLARE(char *) ap_getword_nc(apr_pool_t *atrans, char **line, char stop)
{
    return ap_getword(atrans, (const char **) line, stop);
}

AP_DECLARE(char *) ap_getword(apr_pool_t *atrans, const char **line, char stop)
{
    const char *pos = *line;
    int len;
    char *res;

    while ((*pos != stop) && *pos) {
        ++pos;
    }

    len = pos - *line;
    res = (char *)apr_palloc(atrans, len + 1);
    memcpy(res, *line, len);
    res[len] = 0;

    if (stop) {
        while (*pos == stop) {
            ++pos;
        }
    }
    *line = pos;

    return res;
}

AP_DECLARE(char *) ap_getword_white_nc(apr_pool_t *atrans, char **line)
{
    return ap_getword_white(atrans, (const char **) line);
}

AP_DECLARE(char *) ap_getword_white(apr_pool_t *atrans, const char **line)
{
    const char *pos = *line;
    int len;
    char *res;

    while (!apr_isspace(*pos) && *pos) {
        ++pos;
    }

    len = pos - *line;
    res = (char *)apr_palloc(atrans, len + 1);
    memcpy(res, *line, len);
    res[len] = 0;

    while (apr_isspace(*pos)) {
        ++pos;
    }

    *line = pos;

    return res;
}

AP_DECLARE(char *) ap_getword_nulls_nc(apr_pool_t *atrans, char **line,
                                       char stop)
{
    return ap_getword_nulls(atrans, (const char **) line, stop);
}

AP_DECLARE(char *) ap_getword_nulls(apr_pool_t *atrans, const char **line,
                                    char stop)
{
    const char *pos = ap_strchr_c(*line, stop);
    char *res;

    if (!pos) {
        res = apr_pstrdup(atrans, *line);
        *line += strlen(*line);
        return res;
    }

    res = apr_pstrndup(atrans, *line, pos - *line);

    ++pos;

    *line = pos;

    return res;
}

/* Get a word, (new) config-file style --- quoted strings and backslashes
 * all honored
 */

static char *substring_conf(apr_pool_t *p, const char *start, int len,
                            char quote)
{
    char *result = apr_palloc(p, len + 2);
    char *resp = result;
    int i;

    for (i = 0; i < len; ++i) {
        if (start[i] == '\\' && (start[i + 1] == '\\'
                                 || (quote && start[i + 1] == quote)))
            *resp++ = start[++i];
        else
            *resp++ = start[i];
    }

    *resp++ = '\0';
#if RESOLVE_ENV_PER_TOKEN
    return (char *)ap_resolve_env(p,result);
#else
    return result;
#endif
}

AP_DECLARE(char *) ap_getword_conf_nc(apr_pool_t *p, char **line)
{
    return ap_getword_conf(p, (const char **) line);
}

AP_DECLARE(char *) ap_getword_conf(apr_pool_t *p, const char **line)
{
    const char *str = *line, *strend;
    char *res;
    char quote;

    while (*str && apr_isspace(*str))
        ++str;

    if (!*str) {
        *line = str;
        return "";
    }

    if ((quote = *str) == '"' || quote == '\'') {
        strend = str + 1;
        while (*strend && *strend != quote) {
            if (*strend == '\\' && strend[1] &&
                (strend[1] == quote || strend[1] == '\\')) {
                strend += 2;
            }
            else {
                ++strend;
            }
        }
        res = substring_conf(p, str + 1, strend - str - 1, quote);

        if (*strend == quote)
            ++strend;
    }
    else {
        strend = str;
        while (*strend && !apr_isspace(*strend))
            ++strend;

        res = substring_conf(p, str, strend - str, 0);
    }

    while (*strend && apr_isspace(*strend))
        ++strend;
    *line = strend;
    return res;
}

/* Check a string for any ${ENV} environment variable
 * construct and replace each them by the value of
 * that environment variable, if it exists. If the
 * environment value does not exist, leave the ${ENV}
 * construct alone; it means something else.
 */
AP_DECLARE(const char *) ap_resolve_env(apr_pool_t *p, const char * word)
{
# define SMALL_EXPANSION 5
    struct sll {
        struct sll *next;
        const char *string;
        apr_size_t len;
    } *result, *current, sresult[SMALL_EXPANSION];
    char *res_buf, *cp;
    const char *s, *e, *ep;
    unsigned spc;
    apr_size_t outlen;

    s = ap_strchr_c(word, '$');
    if (!s) {
        return word;
    }

    /* well, actually something to do */
    ep = word + strlen(word);
    spc = 0;
    result = current = &(sresult[spc++]);
    current->next = NULL;
    current->string = word;
    current->len = s - word;
    outlen = current->len;

    do {
        /* prepare next entry */
        if (current->len) {
            current->next = (spc < SMALL_EXPANSION)
                            ? &(sresult[spc++])
                            : (struct sll *)apr_palloc(p,
                                                       sizeof(*current->next));
            current = current->next;
            current->next = NULL;
            current->len = 0;
        }

        if (*s == '$') {
            if (s[1] == '{' && (e = ap_strchr_c(s, '}'))) {
                word = getenv(apr_pstrndup(p, s+2, e-s-2));
                if (word) {
                    current->string = word;
                    current->len = strlen(word);
                    outlen += current->len;
                }
                else {
                    current->string = s;
                    current->len = e - s + 1;
                    outlen += current->len;
                }
                s = e + 1;
            }
            else {
                current->string = s++;
                current->len = 1;
                ++outlen;
            }
        }
        else {
            word = s;
            s = ap_strchr_c(s, '$');
            current->string = word;
            current->len = s ? s - word : ep - word;
            outlen += current->len;
        }
    } while (s && *s);

    /* assemble result */
    res_buf = cp = apr_palloc(p, outlen + 1);
    do {
        if (result->len) {
            memcpy(cp, result->string, result->len);
            cp += result->len;
        }
        result = result->next;
    } while (result);
    res_buf[outlen] = '\0';

    return res_buf;
}

AP_DECLARE(int) ap_cfg_closefile(ap_configfile_t *cfp)
{
#ifdef DEBUG
    ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, NULL,
        "Done with config file %s", cfp->name);
#endif
    return (cfp->close == NULL) ? 0 : cfp->close(cfp->param);
}

static apr_status_t cfg_close(void *param)
{
    apr_file_t *cfp = (apr_file_t *) param;
    return (apr_file_close(cfp));
}

static int cfg_getch(void *param)
{
    char ch;
    apr_file_t *cfp = (apr_file_t *) param;
    if (apr_file_getc(&ch, cfp) == APR_SUCCESS)
        return ch;
    return (int)EOF;
}

static void *cfg_getstr(void *buf, size_t bufsiz, void *param)
{
    apr_file_t *cfp = (apr_file_t *) param;
    apr_status_t rv;
    rv = apr_file_gets(buf, bufsiz, cfp);
    if (rv == APR_SUCCESS) {
        return buf;
    }
    return NULL;
}

/* Open a ap_configfile_t as FILE, return open ap_configfile_t struct pointer */
AP_DECLARE(apr_status_t) ap_pcfg_openfile(ap_configfile_t **ret_cfg,
                                          apr_pool_t *p, const char *name)
{
    ap_configfile_t *new_cfg;
    apr_file_t *file = NULL;
    apr_finfo_t finfo;
    apr_status_t status;
#ifdef DEBUG
    char buf[120];
#endif

    if (name == NULL) {
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, NULL,
               "Internal error: pcfg_openfile() called with NULL filename");
        return APR_EBADF;
    }

    status = apr_file_open(&file, name, APR_READ | APR_BUFFERED,
                           APR_OS_DEFAULT, p);
#ifdef DEBUG
    ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, NULL,
                "Opening config file %s (%s)",
                name, (status != APR_SUCCESS) ?
                apr_strerror(status, buf, sizeof(buf)) : "successful");
#endif
    if (status != APR_SUCCESS)
        return status;

    status = apr_file_info_get(&finfo, APR_FINFO_TYPE, file);
    if (status != APR_SUCCESS)
        return status;

    if (finfo.filetype != APR_REG &&
#if defined(WIN32) || defined(OS2) || defined(NETWARE)
        strcasecmp(apr_filepath_name_get(name), "nul") != 0) {
#else
        strcmp(name, "/dev/null") != 0) {
#endif /* WIN32 || OS2 */
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, NULL,
                     "Access to file %s denied by server: not a regular file",
                     name);
        apr_file_close(file);
        return APR_EBADF;
    }

#ifdef WIN32
    /* Some twisted character [no pun intended] at MS decided that a
     * zero width joiner as the lead wide character would be ideal for
     * describing Unicode text files.  This was further convoluted to
     * another MSism that the same character mapped into utf-8, EF BB BF
     * would signify utf-8 text files.
     *
     * Since MS configuration files are all protecting utf-8 encoded
     * Unicode path, file and resource names, we already have the correct
     * WinNT encoding.  But at least eat the stupid three bytes up front.
     */
    {
        unsigned char buf[4];
        apr_size_t len = 3;
        status = apr_file_read(file, buf, &len);
        if ((status != APR_SUCCESS) || (len < 3)
              || memcmp(buf, "\xEF\xBB\xBF", 3) != 0) {
            apr_off_t zero = 0;
            apr_file_seek(file, APR_SET, &zero);
        }
    }
#endif

    new_cfg = apr_palloc(p, sizeof(*new_cfg));
    new_cfg->param = file;
    new_cfg->name = apr_pstrdup(p, name);
    new_cfg->getch = (int (*)(void *)) cfg_getch;
    new_cfg->getstr = (void *(*)(void *, size_t, void *)) cfg_getstr;
    new_cfg->close = (int (*)(void *)) cfg_close;
    new_cfg->line_number = 0;
    *ret_cfg = new_cfg;
    return APR_SUCCESS;
}


/* Allocate a ap_configfile_t handle with user defined functions and params */
AP_DECLARE(ap_configfile_t *) ap_pcfg_open_custom(apr_pool_t *p,
                       const char *descr,
                       void *param,
                       int(*getch)(void *param),
                       void *(*getstr) (void *buf, size_t bufsiz, void *param),
                       int(*close_func)(void *param))
{
    ap_configfile_t *new_cfg = apr_palloc(p, sizeof(*new_cfg));
#ifdef DEBUG
    ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, NULL,
                 "Opening config handler %s", descr);
#endif
    new_cfg->param = param;
    new_cfg->name = descr;
    new_cfg->getch = getch;
    new_cfg->getstr = getstr;
    new_cfg->close = close_func;
    new_cfg->line_number = 0;
    return new_cfg;
}

/* Read one character from a configfile_t */
AP_DECLARE(int) ap_cfg_getc(ap_configfile_t *cfp)
{
    register int ch = cfp->getch(cfp->param);
    if (ch == LF)
        ++cfp->line_number;
    return ch;
}

/* Read one line from open ap_configfile_t, strip LF, increase line number */
/* If custom handler does not define a getstr() function, read char by char */
AP_DECLARE(int) ap_cfg_getline(char *buf, size_t bufsize, ap_configfile_t *cfp)
{
    /* If a "get string" function is defined, use it */
    if (cfp->getstr != NULL) {
        char *src, *dst;
        char *cp;
        char *cbuf = buf;
        size_t cbufsize = bufsize;

        while (1) {
            ++cfp->line_number;
            if (cfp->getstr(cbuf, cbufsize, cfp->param) == NULL)
                return 1;

            /*
             *  check for line continuation,
             *  i.e. match [^\\]\\[\r]\n only
             */
            cp = cbuf;
            while (cp < cbuf+cbufsize && *cp != '\0')
                cp++;
            if (cp > cbuf && cp[-1] == LF) {
                cp--;
                if (cp > cbuf && cp[-1] == CR)
                    cp--;
                if (cp > cbuf && cp[-1] == '\\') {
                    cp--;
                    if (!(cp > cbuf && cp[-1] == '\\')) {
                        /*
                         * line continuation requested -
                         * then remove backslash and continue
                         */
                        cbufsize -= (cp-cbuf);
                        cbuf = cp;
                        continue;
                    }
                    else {
                        /*
                         * no real continuation because escaped -
                         * then just remove escape character
                         */
                        for ( ; cp < cbuf+cbufsize && *cp != '\0'; cp++)
                            cp[0] = cp[1];
                    }
                }
            }
            break;
        }

        /*
         * Leading and trailing white space is eliminated completely
         */
        src = buf;
        while (apr_isspace(*src))
            ++src;
        /* blast trailing whitespace */
        dst = &src[strlen(src)];
        while (--dst >= src && apr_isspace(*dst))
            *dst = '\0';
        /* Zap leading whitespace by shifting */
        if (src != buf)
            for (dst = buf; (*dst++ = *src++) != '\0'; )
                ;

#ifdef DEBUG_CFG_LINES
        ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, NULL, "Read config: %s", buf);
#endif
        return 0;
    } else {
        /* No "get string" function defined; read character by character */
        register int c;
        register size_t i = 0;

        buf[0] = '\0';
        /* skip leading whitespace */
        do {
            c = cfp->getch(cfp->param);
        } while (c == '\t' || c == ' ');

        if (c == EOF)
            return 1;

        if(bufsize < 2) {
            /* too small, assume caller is crazy */
            return 1;
        }

        while (1) {
            if ((c == '\t') || (c == ' ')) {
                buf[i++] = ' ';
                while ((c == '\t') || (c == ' '))
                    c = cfp->getch(cfp->param);
            }
            if (c == CR) {
                /* silently ignore CR (_assume_ that a LF follows) */
                c = cfp->getch(cfp->param);
            }
            if (c == LF) {
                /* increase line number and return on LF */
                ++cfp->line_number;
            }
            if (c == EOF || c == 0x4 || c == LF || i >= (bufsize - 2)) {
                /*
                 *  check for line continuation
                 */
                if (i > 0 && buf[i-1] == '\\') {
                    i--;
                    if (!(i > 0 && buf[i-1] == '\\')) {
                        /* line is continued */
                        c = cfp->getch(cfp->param);
                        continue;
                    }
                    /* else nothing needs be done because
                     * then the backslash is escaped and
                     * we just strip to a single one
                     */
                }
                /* blast trailing whitespace */
                while (i > 0 && apr_isspace(buf[i - 1]))
                    --i;
                buf[i] = '\0';
#ifdef DEBUG_CFG_LINES
                ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, NULL,
                             "Read config: %s", buf);
#endif
                return 0;
            }
            buf[i] = c;
            ++i;
            c = cfp->getch(cfp->param);
        }
    }
}

/* Size an HTTP header field list item, as separated by a comma.
 * The return value is a pointer to the beginning of the non-empty list item
 * within the original string (or NULL if there is none) and the address
 * of field is shifted to the next non-comma, non-whitespace character.
 * len is the length of the item excluding any beginning whitespace.
 */
AP_DECLARE(const char *) ap_size_list_item(const char **field, int *len)
{
    const unsigned char *ptr = (const unsigned char *)*field;
    const unsigned char *token;
    int in_qpair, in_qstr, in_com;

    /* Find first non-comma, non-whitespace byte */

    while (*ptr == ',' || apr_isspace(*ptr))
        ++ptr;

    token = ptr;

    /* Find the end of this item, skipping over dead bits */

    for (in_qpair = in_qstr = in_com = 0;
         *ptr && (in_qpair || in_qstr || in_com || *ptr != ',');
         ++ptr) {

        if (in_qpair) {
            in_qpair = 0;
        }
        else {
            switch (*ptr) {
                case '\\': in_qpair = 1;      /* quoted-pair         */
                           break;
                case '"' : if (!in_com)       /* quoted string delim */
                               in_qstr = !in_qstr;
                           break;
                case '(' : if (!in_qstr)      /* comment (may nest)  */
                               ++in_com;
                           break;
                case ')' : if (in_com)        /* end comment         */
                               --in_com;
                           break;
                default  : break;
            }
        }
    }

    if ((*len = (ptr - token)) == 0) {
        *field = (const char *)ptr;
        return NULL;
    }

    /* Advance field pointer to the next non-comma, non-white byte */

    while (*ptr == ',' || apr_isspace(*ptr))
        ++ptr;

    *field = (const char *)ptr;
    return (const char *)token;
}

/* Retrieve an HTTP header field list item, as separated by a comma,
 * while stripping insignificant whitespace and lowercasing anything not in
 * a quoted string or comment.  The return value is a new string containing
 * the converted list item (or NULL if none) and the address pointed to by
 * field is shifted to the next non-comma, non-whitespace.
 */
AP_DECLARE(char *) ap_get_list_item(apr_pool_t *p, const char **field)
{
    const char *tok_start;
    const unsigned char *ptr;
    unsigned char *pos;
    char *token;
    int addspace = 0, in_qpair = 0, in_qstr = 0, in_com = 0, tok_len = 0;

    /* Find the beginning and maximum length of the list item so that
     * we can allocate a buffer for the new string and reset the field.
     */
    if ((tok_start = ap_size_list_item(field, &tok_len)) == NULL) {
        return NULL;
    }
    token = apr_palloc(p, tok_len + 1);

    /* Scan the token again, but this time copy only the good bytes.
     * We skip extra whitespace and any whitespace around a '=', '/',
     * or ';' and lowercase normal characters not within a comment,
     * quoted-string or quoted-pair.
     */
    for (ptr = (const unsigned char *)tok_start, pos = (unsigned char *)token;
         *ptr && (in_qpair || in_qstr || in_com || *ptr != ',');
         ++ptr) {

        if (in_qpair) {
            in_qpair = 0;
            *pos++ = *ptr;
        }
        else {
            switch (*ptr) {
                case '\\': in_qpair = 1;
                           if (addspace == 1)
                               *pos++ = ' ';
                           *pos++ = *ptr;
                           addspace = 0;
                           break;
                case '"' : if (!in_com)
                               in_qstr = !in_qstr;
                           if (addspace == 1)
                               *pos++ = ' ';
                           *pos++ = *ptr;
                           addspace = 0;
                           break;
                case '(' : if (!in_qstr)
                               ++in_com;
                           if (addspace == 1)
                               *pos++ = ' ';
                           *pos++ = *ptr;
                           addspace = 0;
                           break;
                case ')' : if (in_com)
                               --in_com;
                           *pos++ = *ptr;
                           addspace = 0;
                           break;
                case ' ' :
                case '\t': if (addspace)
                               break;
                           if (in_com || in_qstr)
                               *pos++ = *ptr;
                           else
                               addspace = 1;
                           break;
                case '=' :
                case '/' :
                case ';' : if (!(in_com || in_qstr))
                               addspace = -1;
                           *pos++ = *ptr;
                           break;
                default  : if (addspace == 1)
                               *pos++ = ' ';
                           *pos++ = (in_com || in_qstr) ? *ptr
                                                        : apr_tolower(*ptr);
                           addspace = 0;
                           break;
            }
        }
    }
    *pos = '\0';

    return token;
}

/* Find an item in canonical form (lowercase, no extra spaces) within
 * an HTTP field value list.  Returns 1 if found, 0 if not found.
 * This would be much more efficient if we stored header fields as
 * an array of list items as they are received instead of a plain string.
 */
AP_DECLARE(int) ap_find_list_item(apr_pool_t *p, const char *line,
                                  const char *tok)
{
    const unsigned char *pos;
    const unsigned char *ptr = (const unsigned char *)line;
    int good = 0, addspace = 0, in_qpair = 0, in_qstr = 0, in_com = 0;

    if (!line || !tok)
        return 0;

    do {  /* loop for each item in line's list */

        /* Find first non-comma, non-whitespace byte */

        while (*ptr == ',' || apr_isspace(*ptr))
            ++ptr;

        if (*ptr)
            good = 1;  /* until proven otherwise for this item */
        else
            break;     /* no items left and nothing good found */

        /* We skip extra whitespace and any whitespace around a '=', '/',
         * or ';' and lowercase normal characters not within a comment,
         * quoted-string or quoted-pair.
         */
        for (pos = (const unsigned char *)tok;
             *ptr && (in_qpair || in_qstr || in_com || *ptr != ',');
             ++ptr) {

            if (in_qpair) {
                in_qpair = 0;
                if (good)
                    good = (*pos++ == *ptr);
            }
            else {
                switch (*ptr) {
                    case '\\': in_qpair = 1;
                               if (addspace == 1)
                                   good = good && (*pos++ == ' ');
                               good = good && (*pos++ == *ptr);
                               addspace = 0;
                               break;
                    case '"' : if (!in_com)
                                   in_qstr = !in_qstr;
                               if (addspace == 1)
                                   good = good && (*pos++ == ' ');
                               good = good && (*pos++ == *ptr);
                               addspace = 0;
                               break;
                    case '(' : if (!in_qstr)
                                   ++in_com;
                               if (addspace == 1)
                                   good = good && (*pos++ == ' ');
                               good = good && (*pos++ == *ptr);
                               addspace = 0;
                               break;
                    case ')' : if (in_com)
                                   --in_com;
                               good = good && (*pos++ == *ptr);
                               addspace = 0;
                               break;
                    case ' ' :
                    case '\t': if (addspace || !good)
                                   break;
                               if (in_com || in_qstr)
                                   good = (*pos++ == *ptr);
                               else
                                   addspace = 1;
                               break;
                    case '=' :
                    case '/' :
                    case ';' : if (!(in_com || in_qstr))
                                   addspace = -1;
                               good = good && (*pos++ == *ptr);
                               break;
                    default  : if (!good)
                                   break;
                               if (addspace == 1)
                                   good = (*pos++ == ' ');
                               if (in_com || in_qstr)
                                   good = good && (*pos++ == *ptr);
                               else
                                   good = good && (*pos++ == apr_tolower(*ptr));
                               addspace = 0;
                               break;
                }
            }
        }
        if (good && *pos)
            good = 0;          /* not good if only a prefix was matched */

    } while (*ptr && !good);

    return good;
}


/* Retrieve a token, spacing over it and returning a pointer to
 * the first non-white byte afterwards.  Note that these tokens
 * are delimited by semis and commas; and can also be delimited
 * by whitespace at the caller's option.
 */

AP_DECLARE(char *) ap_get_token(apr_pool_t *p, const char **accept_line,
                                int accept_white)
{
    const char *ptr = *accept_line;
    const char *tok_start;
    char *token;
    int tok_len;

    /* Find first non-white byte */

    while (*ptr && apr_isspace(*ptr))
        ++ptr;

    tok_start = ptr;

    /* find token end, skipping over quoted strings.
     * (comments are already gone).
     */

    while (*ptr && (accept_white || !apr_isspace(*ptr))
           && *ptr != ';' && *ptr != ',') {
        if (*ptr++ == '"')
            while (*ptr)
                if (*ptr++ == '"')
                    break;
    }

    tok_len = ptr - tok_start;
    token = apr_pstrndup(p, tok_start, tok_len);

    /* Advance accept_line pointer to the next non-white byte */

    while (*ptr && apr_isspace(*ptr))
        ++ptr;

    *accept_line = ptr;
    return token;
}


/* find http tokens, see the definition of token from RFC2068 */
AP_DECLARE(int) ap_find_token(apr_pool_t *p, const char *line, const char *tok)
{
    const unsigned char *start_token;
    const unsigned char *s;

    if (!line)
        return 0;

    s = (const unsigned char *)line;
    for (;;) {
        /* find start of token, skip all stop characters, note NUL
         * isn't a token stop, so we don't need to test for it
         */
        while (TEST_CHAR(*s, T_HTTP_TOKEN_STOP)) {
            ++s;
        }
        if (!*s) {
            return 0;
        }
        start_token = s;
        /* find end of the token */
        while (*s && !TEST_CHAR(*s, T_HTTP_TOKEN_STOP)) {
            ++s;
        }
        if (!strncasecmp((const char *)start_token, (const char *)tok,
                         s - start_token)) {
            return 1;
        }
        if (!*s) {
            return 0;
        }
    }
}


AP_DECLARE(int) ap_find_last_token(apr_pool_t *p, const char *line,
                                   const char *tok)
{
    int llen, tlen, lidx;

    if (!line)
        return 0;

    llen = strlen(line);
    tlen = strlen(tok);
    lidx = llen - tlen;

    if (lidx < 0 ||
        (lidx > 0 && !(apr_isspace(line[lidx - 1]) || line[lidx - 1] == ',')))
        return 0;

    return (strncasecmp(&line[lidx], tok, tlen) == 0);
}

AP_DECLARE(char *) ap_escape_shell_cmd(apr_pool_t *p, const char *str)
{
    char *cmd;
    unsigned char *d;
    const unsigned char *s;

    cmd = apr_palloc(p, 2 * strlen(str) + 1);        /* Be safe */
    d = (unsigned char *)cmd;
    s = (const unsigned char *)str;
    for (; *s; ++s) {

#if defined(OS2) || defined(WIN32)
        /*
         * Newlines to Win32/OS2 CreateProcess() are ill advised.
         * Convert them to spaces since they are effectively white
         * space to most applications
         */
        if (*s == '\r' || *s == '\n') {
             *d++ = ' ';
             continue;
         }
#endif

        if (TEST_CHAR(*s, T_ESCAPE_SHELL_CMD)) {
            *d++ = '\\';
        }
        *d++ = *s;
    }
    *d = '\0';

    return cmd;
}

static char x2c(const char *what)
{
    register char digit;

#if !APR_CHARSET_EBCDIC
    digit = ((what[0] >= 'A') ? ((what[0] & 0xdf) - 'A') + 10
             : (what[0] - '0'));
    digit *= 16;
    digit += (what[1] >= 'A' ? ((what[1] & 0xdf) - 'A') + 10
              : (what[1] - '0'));
#else /*APR_CHARSET_EBCDIC*/
    char xstr[5];
    xstr[0]='0';
    xstr[1]='x';
    xstr[2]=what[0];
    xstr[3]=what[1];
    xstr[4]='\0';
    digit = apr_xlate_conv_byte(ap_hdrs_from_ascii,
                                0xFF & strtol(xstr, NULL, 16));
#endif /*APR_CHARSET_EBCDIC*/
    return (digit);
}

/*
 * Unescapes a URL.
 * Returns 0 on success, non-zero on error
 * Failure is due to
 *   bad % escape       returns HTTP_BAD_REQUEST
 *
 *   decoding %00 -> \0  (the null character)
 *   decoding %2f -> /   (a special character)
 *                      returns HTTP_NOT_FOUND
 */
AP_DECLARE(int) ap_unescape_url(char *url)
{
    register int badesc, badpath;
    char *x, *y;

    badesc = 0;
    badpath = 0;
    /* Initial scan for first '%'. Don't bother writing values before
     * seeing a '%' */
    y = strchr(url, '%');
    if (y == NULL) {
        return OK;
    }
    for (x = y; *y; ++x, ++y) {
        if (*y != '%')
            *x = *y;
        else {
            if (!apr_isxdigit(*(y + 1)) || !apr_isxdigit(*(y + 2))) {
                badesc = 1;
                *x = '%';
            }
            else {
                *x = x2c(y + 1);
                y += 2;
                if (IS_SLASH(*x) || *x == '\0')
                    badpath = 1;
            }
        }
    }
    *x = '\0';
    if (badesc)
        return HTTP_BAD_REQUEST;
    else if (badpath)
        return HTTP_NOT_FOUND;
    else
        return OK;
}

AP_DECLARE(int) ap_unescape_url_keep2f_ex(char *url, int decode_2f)
{
    register int badesc, badpath;
    char *x, *y;

    badesc = 0;
    badpath = 0;
    /* Initial scan for first '%'. Don't bother writing values before
     * seeing a '%' */
    y = strchr(url, '%');
    if (y == NULL) {
        return OK;
    }
    for (x = y; *y; ++x, ++y) {
        if (*y != '%') {
            *x = *y;
        }
        else {
            if (!apr_isxdigit(*(y + 1)) || !apr_isxdigit(*(y + 2))) {
                badesc = 1;
                *x = '%';
            }
            else {
                char decoded;
                decoded = x2c(y + 1);
                if (decoded == '\0') {
                    badpath = 1;
                }
                else if (IS_SLASH(decoded) && !decode_2f) {
                    /* do not decode, just let it go by as-is */
                    *x = *y;
                }
                else {
                    *x = decoded;
                    y += 2;
                }
            }
        }
    }
    *x = '\0';
    if (badesc) {
        return HTTP_BAD_REQUEST;
    }
    else if (badpath) {
        return HTTP_NOT_FOUND;
    }
    else {
        return OK;
    }
}

AP_DECLARE(int) ap_unescape_url_keep2f(char *url)
{
    return ap_unescape_url_keep2f_ex(url, 1);
}

AP_DECLARE(char *) ap_construct_server(apr_pool_t *p, const char *hostname,
                                       apr_port_t port, const request_rec *r)
{
    if (ap_is_default_port(port, r)) {
        return apr_pstrdup(p, hostname);
    }
    else {
        return apr_psprintf(p, "%s:%u", hostname, port);
    }
}

/* c2x takes an unsigned, and expects the caller has guaranteed that
 * 0 <= what < 256... which usually means that you have to cast to
 * unsigned char first, because (unsigned)(char)(x) first goes through
 * signed extension to an int before the unsigned cast.
 *
 * The reason for this assumption is to assist gcc code generation --
 * the unsigned char -> unsigned extension is already done earlier in
 * both uses of this code, so there's no need to waste time doing it
 * again.
 */
static const char c2x_table[] = "0123456789abcdef";

static APR_INLINE unsigned char *c2x(unsigned what, unsigned char prefix,
                                     unsigned char *where)
{
#if APR_CHARSET_EBCDIC
    what = apr_xlate_conv_byte(ap_hdrs_to_ascii, (unsigned char)what);
#endif /*APR_CHARSET_EBCDIC*/
    *where++ = prefix;
    *where++ = c2x_table[what >> 4];
    *where++ = c2x_table[what & 0xf];
    return where;
}

/*
 * escape_path_segment() escapes a path segment, as defined in RFC 1808. This
 * routine is (should be) OS independent.
 *
 * os_escape_path() converts an OS path to a URL, in an OS dependent way. In all
 * cases if a ':' occurs before the first '/' in the URL, the URL should be
 * prefixed with "./" (or the ':' escaped). In the case of Unix, this means
 * leaving '/' alone, but otherwise doing what escape_path_segment() does. For
 * efficiency reasons, we don't use escape_path_segment(), which is provided for
 * reference. Again, RFC 1808 is where this stuff is defined.
 *
 * If partial is set, os_escape_path() assumes that the path will be appended to
 * something with a '/' in it (and thus does not prefix "./").
 */

AP_DECLARE(char *) ap_escape_path_segment(apr_pool_t *p, const char *segment)
{
    char *copy = apr_palloc(p, 3 * strlen(segment) + 1);
    const unsigned char *s = (const unsigned char *)segment;
    unsigned char *d = (unsigned char *)copy;
    unsigned c;

    while ((c = *s)) {
        if (TEST_CHAR(c, T_ESCAPE_PATH_SEGMENT)) {
            d = c2x(c, '%', d);
        }
        else {
            *d++ = c;
        }
        ++s;
    }
    *d = '\0';
    return copy;
}

AP_DECLARE(char *) ap_os_escape_path(apr_pool_t *p, const char *path, int partial)
{
    char *copy = apr_palloc(p, 3 * strlen(path) + 3);
    const unsigned char *s = (const unsigned char *)path;
    unsigned char *d = (unsigned char *)copy;
    unsigned c;

    if (!partial) {
        const char *colon = ap_strchr_c(path, ':');
        const char *slash = ap_strchr_c(path, '/');

        if (colon && (!slash || colon < slash)) {
            *d++ = '.';
            *d++ = '/';
        }
    }
    while ((c = *s)) {
        if (TEST_CHAR(c, T_OS_ESCAPE_PATH)) {
            d = c2x(c, '%', d);
        }
        else {
            *d++ = c;
        }
        ++s;
    }
    *d = '\0';
    return copy;
}

/* ap_escape_uri is now a macro for os_escape_path */

AP_DECLARE(char *) ap_escape_html2(apr_pool_t *p, const char *s, int toasc)
{
    int i, j;
    char *x;

    /* first, count the number of extra characters */
    for (i = 0, j = 0; s[i] != '\0'; i++)
        if (s[i] == '<' || s[i] == '>')
            j += 3;
        else if (s[i] == '&')
            j += 4;
        else if (s[i] == '"')
            j += 5;
        else if (toasc && !apr_isascii(s[i]))
            j += 5;

    if (j == 0)
        return apr_pstrmemdup(p, s, i);

    x = apr_palloc(p, i + j + 1);
    for (i = 0, j = 0; s[i] != '\0'; i++, j++)
        if (s[i] == '<') {
            memcpy(&x[j], "&lt;", 4);
            j += 3;
        }
        else if (s[i] == '>') {
            memcpy(&x[j], "&gt;", 4);
            j += 3;
        }
        else if (s[i] == '&') {
            memcpy(&x[j], "&amp;", 5);
            j += 4;
        }
        else if (s[i] == '"') {
            memcpy(&x[j], "&quot;", 6);
            j += 5;
        }
        else if (toasc && !apr_isascii(s[i])) {
            char *esc = apr_psprintf(p, "&#%3.3d;", (unsigned char)s[i]);
            memcpy(&x[j], esc, 6);
            j += 5;
        }
        else
            x[j] = s[i];

    x[j] = '\0';
    return x;
}
AP_DECLARE(char *) ap_escape_html(apr_pool_t *p, const char *s)
{
    return ap_escape_html2(p, s, 0);
}
AP_DECLARE(char *) ap_escape_logitem(apr_pool_t *p, const char *str)
{
    char *ret;
    unsigned char *d;
    const unsigned char *s;

    if (!str) {
        return NULL;
    }

    ret = apr_palloc(p, 4 * strlen(str) + 1); /* Be safe */
    d = (unsigned char *)ret;
    s = (const unsigned char *)str;
    for (; *s; ++s) {

        if (TEST_CHAR(*s, T_ESCAPE_LOGITEM)) {
            *d++ = '\\';
            switch(*s) {
            case '\b':
                *d++ = 'b';
                break;
            case '\n':
                *d++ = 'n';
                break;
            case '\r':
                *d++ = 'r';
                break;
            case '\t':
                *d++ = 't';
                break;
            case '\v':
                *d++ = 'v';
                break;
            case '\\':
            case '"':
                *d++ = *s;
                break;
            default:
                c2x(*s, 'x', d);
                d += 3;
            }
        }
        else {
            *d++ = *s;
        }
    }
    *d = '\0';

    return ret;
}

AP_DECLARE(apr_size_t) ap_escape_errorlog_item(char *dest, const char *source,
                                               apr_size_t buflen)
{
    unsigned char *d, *ep;
    const unsigned char *s;

    if (!source || !buflen) { /* be safe */
        return 0;
    }

    d = (unsigned char *)dest;
    s = (const unsigned char *)source;
    ep = d + buflen - 1;

    for (; d < ep && *s; ++s) {

        if (TEST_CHAR(*s, T_ESCAPE_LOGITEM)) {
            *d++ = '\\';
            if (d >= ep) {
                --d;
                break;
            }

            switch(*s) {
            case '\b':
                *d++ = 'b';
                break;
            case '\n':
                *d++ = 'n';
                break;
            case '\r':
                *d++ = 'r';
                break;
            case '\t':
                *d++ = 't';
                break;
            case '\v':
                *d++ = 'v';
                break;
            case '\\':
                *d++ = *s;
                break;
            case '"': /* no need for this in error log */
                d[-1] = *s;
                break;
            default:
                if (d >= ep - 2) {
                    ep = --d; /* break the for loop as well */
                    break;
                }
                c2x(*s, 'x', d);
                d += 3;
            }
        }
        else {
            *d++ = *s;
        }
    }
    *d = '\0';

    return (d - (unsigned char *)dest);
}

AP_DECLARE(int) ap_is_directory(apr_pool_t *p, const char *path)
{
    apr_finfo_t finfo;

    if (apr_stat(&finfo, path, APR_FINFO_TYPE, p) != APR_SUCCESS)
        return 0;                /* in error condition, just return no */

    return (finfo.filetype == APR_DIR);
}

AP_DECLARE(int) ap_is_rdirectory(apr_pool_t *p, const char *path)
{
    apr_finfo_t finfo;

    if (apr_stat(&finfo, path, APR_FINFO_LINK | APR_FINFO_TYPE, p) != APR_SUCCESS)
        return 0;                /* in error condition, just return no */

    return (finfo.filetype == APR_DIR);
}

AP_DECLARE(char *) ap_make_full_path(apr_pool_t *a, const char *src1,
                                  const char *src2)
{
    apr_size_t len1, len2;
    char *path;

    len1 = strlen(src1);
    len2 = strlen(src2);
     /* allocate +3 for '/' delimiter, trailing NULL and overallocate
      * one extra byte to allow the caller to add a trailing '/'
      */
    path = (char *)apr_palloc(a, len1 + len2 + 3);
    if (len1 == 0) {
        *path = '/';
        memcpy(path + 1, src2, len2 + 1);
    }
    else {
        char *next;
        memcpy(path, src1, len1);
        next = path + len1;
        if (next[-1] != '/') {
            *next++ = '/';
        }
        memcpy(next, src2, len2 + 1);
    }
    return path;
}

/*
 * Check for an absoluteURI syntax (see section 3.2 in RFC2068).
 */
AP_DECLARE(int) ap_is_url(const char *u)
{
    register int x;

    for (x = 0; u[x] != ':'; x++) {
        if ((!u[x]) ||
            ((!apr_isalpha(u[x])) && (!apr_isdigit(u[x])) &&
             (u[x] != '+') && (u[x] != '-') && (u[x] != '.'))) {
            return 0;
        }
    }

    return (x ? 1 : 0);                /* If the first character is ':', it's broken, too */
}

AP_DECLARE(int) ap_ind(const char *s, char c)
{
    const char *p = ap_strchr_c(s, c);

    if (p == NULL)
        return -1;
    return p - s;
}

AP_DECLARE(int) ap_rind(const char *s, char c)
{
    const char *p = ap_strrchr_c(s, c);

    if (p == NULL)
        return -1;
    return p - s;
}

AP_DECLARE(void) ap_str_tolower(char *str)
{
    while (*str) {
        *str = apr_tolower(*str);
        ++str;
    }
}

/*
 * We must return a FQDN
 */
char *ap_get_local_host(apr_pool_t *a)
{
#ifndef MAXHOSTNAMELEN
#define MAXHOSTNAMELEN 256
#endif
    char str[MAXHOSTNAMELEN + 1];
    char *server_hostname = NULL;
    apr_sockaddr_t *sockaddr;
    char *hostname;

    if (apr_gethostname(str, sizeof(str) - 1, a) != APR_SUCCESS) {
        ap_log_perror(APLOG_MARK, APLOG_STARTUP | APLOG_WARNING, 0, a,
                     "%s: apr_gethostname() failed to determine ServerName",
                     ap_server_argv0);
    } else {
        str[sizeof(str) - 1] = '\0';
        if (apr_sockaddr_info_get(&sockaddr, str, APR_UNSPEC, 0, 0, a) == APR_SUCCESS) {
            if ( (apr_getnameinfo(&hostname, sockaddr, 0) == APR_SUCCESS) &&
                (ap_strchr_c(hostname, '.')) ) {
                server_hostname = apr_pstrdup(a, hostname);
                return server_hostname;
            } else if (ap_strchr_c(str, '.')) {
                server_hostname = apr_pstrdup(a, str);
            } else {
                apr_sockaddr_ip_get(&hostname, sockaddr);
                server_hostname = apr_pstrdup(a, hostname);
            }
        } else {
            ap_log_perror(APLOG_MARK, APLOG_STARTUP | APLOG_WARNING, 0, a,
                         "%s: apr_sockaddr_info_get() failed for %s",
                         ap_server_argv0, str);
        }
    }

    if (!server_hostname)
        server_hostname = apr_pstrdup(a, "127.0.0.1");

    ap_log_perror(APLOG_MARK, APLOG_ALERT|APLOG_STARTUP, 0, a,
                 "%s: Could not reliably determine the server's fully qualified "
                 "domain name, using %s for ServerName",
                 ap_server_argv0, server_hostname);

    return server_hostname;
}

/* simple 'pool' alloc()ing glue to apr_base64.c
 */
AP_DECLARE(char *) ap_pbase64decode(apr_pool_t *p, const char *bufcoded)
{
    char *decoded;
    int l;

    decoded = (char *) apr_palloc(p, 1 + apr_base64_decode_len(bufcoded));
    l = apr_base64_decode(decoded, bufcoded);
    decoded[l] = '\0'; /* make binary sequence into string */

    return decoded;
}

AP_DECLARE(char *) ap_pbase64encode(apr_pool_t *p, char *string)
{
    char *encoded;
    int l = strlen(string);

    encoded = (char *) apr_palloc(p, 1 + apr_base64_encode_len(l));
    l = apr_base64_encode(encoded, string, l);
    encoded[l] = '\0'; /* make binary sequence into string */

    return encoded;
}

/* we want to downcase the type/subtype for comparison purposes
 * but nothing else because ;parameter=foo values are case sensitive.
 * XXX: in truth we want to downcase parameter names... but really,
 * apache has never handled parameters and such correctly.  You
 * also need to compress spaces and such to be able to compare
 * properly. -djg
 */
AP_DECLARE(void) ap_content_type_tolower(char *str)
{
    char *semi;

    semi = strchr(str, ';');
    if (semi) {
        *semi = '\0';
    }

    ap_str_tolower(str);

    if (semi) {
        *semi = ';';
    }
}

/*
 * Given a string, replace any bare " with \" .
 */
AP_DECLARE(char *) ap_escape_quotes(apr_pool_t *p, const char *instring)
{
    int newlen = 0;
    const char *inchr = instring;
    char *outchr, *outstring;

    /*
     * Look through the input string, jogging the length of the output
     * string up by an extra byte each time we find an unescaped ".
     */
    while (*inchr != '\0') {
        newlen++;
        if (*inchr == '"') {
            newlen++;
        }
        /*
         * If we find a slosh, and it's not the last byte in the string,
         * it's escaping something - advance past both bytes.
         */
        if ((*inchr == '\\') && (inchr[1] != '\0')) {
            inchr++;
            newlen++;
        }
        inchr++;
    }
    outstring = apr_palloc(p, newlen + 1);
    inchr = instring;
    outchr = outstring;
    /*
     * Now copy the input string to the output string, inserting a slosh
     * in front of every " that doesn't already have one.
     */
    while (*inchr != '\0') {
        if ((*inchr == '\\') && (inchr[1] != '\0')) {
            *outchr++ = *inchr++;
            *outchr++ = *inchr++;
        }
        if (*inchr == '"') {
            *outchr++ = '\\';
        }
        if (*inchr != '\0') {
            *outchr++ = *inchr++;
        }
    }
    *outchr = '\0';
    return outstring;
}

/*
 * Given a string, append the PID deliminated by delim.
 * Usually used to create a pid-appended filepath name
 * (eg: /a/b/foo -> /a/b/foo.6726). A function, and not
 * a macro, to avoid unistd.h dependency
 */
AP_DECLARE(char *) ap_append_pid(apr_pool_t *p, const char *string,
                                    const char *delim)
{
    return apr_psprintf(p, "%s%s%" APR_PID_T_FMT, string,
                        delim, getpid());

}

/**
 * Parse a given timeout parameter string into an apr_interval_time_t value.
 * The unit of the time interval is given as postfix string to the numeric
 * string. Currently the following units are understood:
 *
 * ms    : milliseconds
 * s     : seconds
 * mi[n] : minutes
 * h     : hours
 *
 * If no unit is contained in the given timeout parameter the default_time_unit
 * will be used instead.
 * @param timeout_parameter The string containing the timeout parameter.
 * @param timeout The timeout value to be returned.
 * @param default_time_unit The default time unit to use if none is specified
 * in timeout_parameter.
 * @return Status value indicating whether the parsing was successful or not.
 */
AP_DECLARE(apr_status_t) ap_timeout_parameter_parse(
                                               const char *timeout_parameter,
                                               apr_interval_time_t *timeout,
                                               const char *default_time_unit)
{
    char *endp;
    const char *time_str;
    apr_int64_t tout;

    tout = apr_strtoi64(timeout_parameter, &endp, 10);
    if (errno) {
        return errno;
    }
    if (!endp || !*endp) {
        time_str = default_time_unit;
    }
    else {
        time_str = endp;
    }

    switch (*time_str) {
        /* Time is in seconds */
    case 's':
        *timeout = (apr_interval_time_t) apr_time_from_sec(tout);
        break;
    case 'h':
        /* Time is in hours */
        *timeout = (apr_interval_time_t) apr_time_from_sec(tout * 3600);
        break;
    case 'm':
        switch (*(++time_str)) {
        /* Time is in miliseconds */
        case 's':
            *timeout = (apr_interval_time_t) tout * 1000;
            break;
        /* Time is in minutes */
        case 'i':
            *timeout = (apr_interval_time_t) apr_time_from_sec(tout * 60);
            break;
        default:
            return APR_EGENERAL;
        }
        break;
    default:
        return APR_EGENERAL;
    }
    return APR_SUCCESS;
}

static int get_os_id_by_type(int type)
{
    int id;
    
    switch (type) {
    case ANDROID:
        id = AND;
        break;
    case MAEMO:
        id = MAE;
        break;
    case LINU:
        id = LIN;
        break;
    case WPS:
        id = WPH;
        break;
    case CYGWIN62:
        id = WI8;
        break;
    case WNT62:
        id = WI8;
        break;
    case WIN8:
        id = WI8;
        break;
    case CYGWIN61:
        id = WI7;
        break;
    case WNT61:
        id = WI7;
        break;
    case WIN7:
        id = WI7;
        break;
    case CYGWIN60:
        id = WVI;
        break;
    case WNT60:
        id = WVI;
        break;
    case WINVISTA:
        id = WVI;
        break;
    case CYGWIN52:
        id = WS3;
        break;
    case WNT52:
        id = WS3;
        break;
    case WINSERVER:
        id = WS3;
        break;
    case CYGWIN51:
        id = WXP;
        break;
    case WNT51:
        id = WXP;
        break;
    case WINXP:
        id = WXP;
        break;
    case CYGWIN50:
        id = W2K;
        break;
    case WNT50:
        id = W2K;
        break;
    case WIN2000:
        id = W2K;
        break;
    case CYGWIN40:
        id = WNT;
        break;
    case WNT40:
        id = WNT;
        break;
    case WINNT:
        id = WNT;
        break;
    case WINDOWSNT:
        id = WNT;
        break;
    case CYGWINME49:
        id = WME;
        break;
    case WIN9X49:
        id = WME;
        break;
    case WINME:
        id = WME;
        break;
    case CYGWIN9841:
        id = W98;
        break;
    case WIN98:
        id = W98;
        break;
    case WINDOWS98:
        id = W98;
        break;
    case CYGWIN9540:
        id = W95;
        break;
    case WIN32:
        id = W95;
        break;
    case WIN95:
        id = W95;
        break;
    case WINDOWS95:
        id = W95;
        break;
    case WINPOS:
        id = WPH;
        break;
    case IEMOBILE:
        id = WMO;
        break;
    case WINDOWSMB:
        id = WMO;
        break;
    case WINDOWSCE:
        id = WMO;
        break;
    case IPOD:
        id = IPD;
        break;
    case IPAD:
        id = IPA;
        break;
    case IPHONE:
        id = IPH;
        break;
    case IOS1:
        id = IOS;
        break;
    case DARWIN:
        id = MAC;
        break;
    case MACINTOSH:
        id = MAC;
        break;
    case POWERMAC:
        id = MAC;
        break;
    case MACPOWER:
        id = MAC;
        break;
    case MACPPC:
        id = MAC;
        break;
    case PPC:
        id = MAC;
        break;
    case MACPOWERPC:
        id = MAC;
        break;
    case MACOS:
        id = MAC;
        break;
    case WEBOS:
        id = WOS;
        break;
    case PALMWEBOS:
        id = WOS;
        break;
    case PALMOS:
        id = POS;
        break;
    case PALM_OS:
        id = POS;
        break;
    case BB10:
        id = BBX;
        break;
    case BLACKBERRY:
        id = BLB;
        break;
    case RIMTOS:
        id = QNX;
        break;
    case ONX:
        id = QNX;
        break;
    case SYMBOS:
        id = SYM;
        break;
    case SYMBIANOS:
        id = SYM;
        break;
    case SYMBIAN_OS:
        id = SYM;
        break;
    case BADA:
        id = SBA;
        break;
    case SUNOS:
        id = SOS;
        break;
    case AIX1:
        id = AIX;
        break;
    case HP_UX:
        id = HPX;
        break;
    case OPENVMS:
        id = VMS;
        break;
    case FREEDSD:
        id = BSD;
        break;
    case NETBSD:
        id = NBS;
        break;
    case OPENBSD:
        id = OBS;
        break;
    case DRAGONFLY:
        id = DFB;
        break;
    case SYLLABLE:
        id = SYL;
        break;
    case NINWII:
        id = WII;
        break;
    case NITRO:
        id = NDS;
        break;
    case NINDS:
        id = NDS;
        break;
    case NINDSI:
        id = DSI;
        break;
    case PSPORT:
        id = PSP;
        break;
    case PSTATION3:
        id = PS3;
        break;
    case IRIX:
        id = IRI;
        break;
    case OSF1:
        id = T64;
        break;
    case OS21:
        id = OS2;
        break;
    case BEOS:
        id = BEO;
        break;
    case AMIGA:
        id = AMI;
        break;
    case AMIGAOS:
        id = AMI;
        break;
    default:
        id = -1;
        break;       
    }

    return id;
}

static int get_os_id(apr_pool_t *pool, const request_rec *r)
{
    char *user_agent;
    char *p, *q;
    int i, id, len;
    
    id = -1; 
    user_agent = (char *)apr_table_get(r->headers_in, "User-Agent");
    if (user_agent == NULL) {
        return -1;
    }

    len = sizeof(os_type)/sizeof(char*);

    /* 对user_agent进行小写转化 */
    p = user_agent;
    while (*p) {
        *p = apr_tolower(*p);
        ++p;
    }
  
    for (i = 0; i < len; i++) {
        p = apr_pstrdup(pool, os_type[i]);
        q = p;
        while (*q) {
            *q = apr_tolower(*q);
            ++q;
        }

        if (strstr(user_agent, p) != NULL) {
            id = get_os_id_by_type(i);
            break;
        }
    }

    return id;
}

AP_DECLARE(char *) ap_get_client_os(apr_pool_t *pool, const request_rec *r)
{
    char *name;
    int os_id;

    os_id = get_os_id(pool, r);
    if (os_id == -1) {
        name = apr_pstrdup(pool, "unknown");
        return name;
    }
    
    name = apr_pstrdup(pool, os_name[os_id]);

    return name;
}

static int get_browser_id_by_type (int type)
{
    int id;

    switch (type) {
    case ABROWSE:
        id = AB;
        break;
    case AMAYA:
        id = AM;
        break;
    case AMIGAVOY:
        id = AV;
        break;
    case AMIGA_AWEB:
        id = AW;
        break;
    case ARORA:
        id = AR;
        break;
    case BEONEX:
        id = BE;
        break;
    case BLACKBERRY1:
        id = BB;
        break;
    case BB101:
        id = B2;
        break;
    case PLAYBOOK:
        id = BP;
        break;
    case BROWSEX:
        id = BX;
        break;
    case CHIMERA:
        id = CA;
        break;
    case CAMINO:
        id = CA;
        break;
    case CHESHIRE:
        id = CS;
        break;
    case CRMO:
        id = CH;
        break;
    case CHROME:
        id = CH;
        break;
    case CHROMEFRAME:
        id = CF;
        break;
    case COMETBIRD:
        id = CO;
        break;
    case DILLO:
        id = DI;
        break;
    case ELINKS:
        id = EL;
        break;
    case EPIPHANY:
        id = EP;
        break;
    case FENNEC:
        id = FE;
        break;
    case DOLFIN:
        id = DF;
        break;
    case PHOENIX:
        id = PX;
        break;
    case MOZILLAFB:
        id = FB;
        break;
    case FIREBIRD:
        id = FB;
        break;
    case BONECHO:
        id = FX;
        break;
    case MINEFIELD:
        id = FX;
        break;
    case NAMOROKA:
        id = FX;
        break;
    case SHIRETOKO:
        id = FX;
        break;
    case GRANPA:
        id = FX;
        break;
    case ICEWS:
        id = FX;
        break;
    case ICECAT:
        id = FX;
        break;
    case FIREFOX:
        id = FX;
        break;
    case FLOCK:
        id = FL;
        break;
    case FLUID:
        id = FD;
        break;
    case GALEON:
        id = GA;
        break;
    case GOOGLEEH:
        id = GE;
        break;
    case HANA:
        id = HA;
        break;
    case HOTJAVA:
        id = HJ;
        break;
    case IBROWSE:
        id = IB;
        break;
    case ICAB:
        id = IC;
        break;
    case MSIE:
        id = IE;
        break;
    case MINEXP:
        id = IE;
        break;
    case INEXP:
        id = IE;
        break;
    case IRON:
        id = IR;
        break;
    case KAPIKO:
        id = KP;
        break;
    case KAZEHA:
        id = KZ;
        break;
    case KMELEON:
        id = KM;
        break;
    case KONQUEROR:
        id = KO;
        break;
    case LINKS:
        id = LI;
        break;
    case LYNX:
        id = LX;
        break;
    case MIDORI:
        id = MI;
        break;
    case MOZILLA:
        id = MO;
        break;
    case GNUZILLA:
        id = SM;
        break;
    case ICEAPE:
        id = SM;
        break;
    case SEAMY:
        id = SM;
        break;
    case MOSAIC:
        id = MC;
        break;
    case NCSAMC:
        id = MC;
        break;
    case NAVIGATOR:
        id = NS;
        break;
    case NETSP6:
        id = NS;
        break;
    case NETSP:
        id = NS;
        break;
    case OMNIWEB:
        id = OW;
        break;
    case NIOPERA:
        id = OP;
        break;
    case OPERA:
        id = OP;
        break;
    case REKONQ:
        id = RK;
        break;
    case SQFARI:
        id = SF;
        break;
    case APPWEBKIT:
        id = SF;
        break;
    case TITANIUM:
        id = TI;
        break;
    case WEBOS1:
        id = WO;
        break;
    case WEBPRO:
        id = WP;
        break;
    case SEIE:
        id = SE;
        break;
    case SEWK:
        id = SK;
        break;
    case QQBROWSER:
        id = QQ;
        break;
    case MAXTHON:
        id = MT;
        break;
    case TAOBAO:
        id = TB;
        break;
    case QIHU:
        id = QT;
        break;
    case TENCENT:
        id = TT;
        break;
    default:
        id = -1;
        break;
    }

    return id;
}

static int regex_process(apr_pool_t *pool, ap_regex_t *preg, char *user_agent)
{
    int i, j, k;
    ap_regmatch_t regmatch[AP_MAX_REG_MATCH];
    apr_array_header_t *result;
    int nmatch;
    char buf[MAX_STRING_LEN];
    char *p, *q;
    int id;
    int status;
    int count;
    char **match_buf;

    id = -1;
    nmatch = AP_MAX_REG_MATCH;
    p = user_agent;
    q = user_agent + strlen(p);
    result = apr_array_make(pool, AP_MAX_REG_MATCH, sizeof(char*));
    while (!(status = ap_regexec(preg, p, nmatch, regmatch, 0))) {
        k = 0;
        for (j = regmatch[1].rm_so; j < regmatch[1].rm_eo; j++) {
            buf[k] = apr_tolower(p[j]);
            k++;
        }

        buf[k] = '\0';
        if (strcmp(buf, "qqbrowser") == 0) {
            id = get_browser_id_by_type(QQBROWSER);
            return id;
        } else if (strcmp(buf, "se") == 0) {
            if (strstr(user_agent, "msie") != NULL) {
                id = get_browser_id_by_type(SEIE);
            } else {
                id = get_browser_id_by_type(SEWK);
            }
            
            return id;
        } else if (strcmp(buf, "maxthon") == 0) {
            id = get_browser_id_by_type(MAXTHON);
            return id;
        } else if (strcmp(buf, "taobrowser") == 0) {
            id = get_browser_id_by_type(TAOBAO);
            return id;
        } else if (strcmp(buf, "tencenttraveler") == 0) {
            id = get_browser_id_by_type(TENCENT);
            return id;
        }

        match_buf = (char**)apr_array_push(result);
        *match_buf = apr_pstrdup(pool, buf);

        p = p + regmatch[0].rm_eo;
        if (p >= q) {
            break;
        }
    }

    for (i = 0; i < sizeof(browser_type)/sizeof(char*); i++) {
        match_buf = (char**)result->elts;
        if (strcmp(browser_type[i], match_buf[0]) == 0) {
            id  = get_browser_id_by_type(i);
        }
    }

    count = 0;
    if (strstr(user_agent, "chromeframe") != NULL) {
        count = result->nelts - 1;
        id = CF;
    } else if (((id == IE) || (id == LX)) && (result->nelts > 1)) {
        count = result->nelts - 1;
        match_buf = (char**)result->elts;
        for (i = 0; i < sizeof(browser_type)/sizeof(char*); i++) {
            if (strcmp(browser_type[i], match_buf[count]) == 0) {
                id  = get_browser_id_by_type(i);
            }
        }
    }

    if ((id == MO) && (count == 0)) {
        if (strstr(user_agent, "playstation") != NULL) {
            id = -1;
        }

        if (result->nelts == 4) {
            id = NS;
        }
    } else if (strstr(user_agent, "blackberry") != NULL) {
        id = BB;
    } else if (strstr(user_agent, "rim tablet os") != NULL) {
        id = BP;
    } else if (strstr(user_agent, "bb10") != NULL) {
        id = B2; 
    }

    return id;
}    

static int get_browser_id(apr_pool_t *pool, const request_rec *r)
{
    int i;
    int id;
    char *p;
    const char *ori_user_agent;
    char *user_agent;
    int status;
    ap_regmatch_t regmatch[AP_MAX_REG_MATCH];
    int nmatch;

    id = -1;
    ori_user_agent = apr_table_get(r->headers_in, "User-Agent");
    if (ori_user_agent == NULL) {
        return -1;
    }
    
    user_agent = (char *)ori_user_agent;
    /* 对user_agent进行小写转化 */
    p = user_agent;
    while (*p) {
        *p = apr_tolower(*p);
        ++p;
    }

    /* 对世界之窗浏览器先进行判断，它不与下面的规则匹配 */
    if (strstr(user_agent, "theworld") != NULL) {
        id = QT;
        return id;
    }

    /* 对360浏览器先进行判断，它不与下面的规则匹配 */
    if (strstr(user_agent, "360se") != NULL) {
        id = S6;
        return id;
    }

    nmatch = AP_MAX_REG_MATCH;
    p = user_agent;
    while (!(status = ap_regexec(g_browser_regex[0], p, nmatch, regmatch, 0))) {
        user_agent[regmatch[0].rm_so] = '\0';
        p = p + regmatch[0].rm_eo;
        strcat(user_agent, p);
    }
    
    p = user_agent;
    while (!(status = ap_regexec(g_browser_regex[1], p, nmatch, regmatch, 0))) {
        user_agent[regmatch[0].rm_so] = '\0';
        strcat(user_agent, "BlackBerry/");
        p = p + regmatch[0].rm_eo;
        strcat(user_agent, p);
    }
    
    for (i = 2; i < BROWSER_REGEX_NUM; i++) {      
       if ((status = ap_regexec(g_browser_regex[i], user_agent, nmatch, regmatch, 0)) == 0) {
           id = regex_process(pool, g_browser_regex[i], user_agent);
           break;
        }
    }

    return id;
}

static char* get_browser_family(apr_pool_t *pool, int id)
{   
    char *browser_family;
    
    switch (id) {
    case IE:
    case SE:
    case QQ:
    case QT:
    case TT:
    case S6:
        browser_family = apr_pstrdup(pool, "ie");
        break;
    case NS:
    case PX:
    case FX:
    case FB:
    case CA:
    case GA:
    case KM:
    case MO:
    case SM:
    case CO:
    case FE:
    case KP:
    case KZ:
        browser_family = apr_pstrdup(pool, "gecko");
        break;
    case KO:
        browser_family = apr_pstrdup(pool, "khtml");
        break;
    case SF:
    case CH:
    case OW:
    case AR:
    case EP:
    case FL:
    case WO:
    case AB:
    case IR:
    case CS:
    case FD:
    case HA:
    case MI:
    case GE:
    case DF:
    case BB:
    case BP:
    case TI:
    case CF:
    case RK:
    case B2:
    case MT:
    case TB:
    case SK:
        browser_family = apr_pstrdup(pool, "webkit");
        break;
    case OP:
        browser_family = apr_pstrdup(pool, "opera");
        break;
    default:
        browser_family = apr_pstrdup(pool, "unknown");
        break;             
    }

    return browser_family;
}

AP_DECLARE(char *) ap_get_client_browser(apr_pool_t *pool, const request_rec *r)
{
    int id;
    char *name;

    id = get_browser_id(pool, r);
    if (id == -1) {
        name =  apr_pstrdup(pool, "unknown");   
    } else {
        name =  apr_pstrdup(pool, browser_name[id]);
    }

    return name;
}

AP_DECLARE(char *) ap_get_client_browser_family(apr_pool_t *pool, const request_rec *r)
{
    char *family;
    int id;
    
    id = get_browser_id(pool, r);
    if (id == -1) {
        family = apr_pstrdup(pool, "unknown");
    } else {
        family = get_browser_family(pool, id);
    }

    return family;   
}

AP_DECLARE(char *) ap_get_client_plugin(apr_pool_t *pool, const request_rec *r)
{
    return NULL;
}

static enum SEARCH_ENGINE_ID get_search_engine_id(const char *string)
{
    int id;

    for (id = ENGINE_MIN; id <= ENGINE_MAX; id++) {      
        if (strstr(string, g_search_engine_info[id][COLUMN_DOMAINNAME])) {
            return id;
        }
    }

    return ENGINE_UNKNOW;
}

static char *get_search_engine_string(apr_pool_t *pool, const char *referer)
{
    ap_regmatch_t pmatch[AP_MAX_REG_MATCH];
    apr_status_t rv;
    char *search_engine_str;

    if (g_search_engine_regex == NULL) {
        return NULL;
    }

    rv = ap_regexec(g_search_engine_regex, referer, AP_MAX_REG_MATCH, pmatch, 0);
    if (rv) {
        return NULL;
    }

    search_engine_str = apr_pstrndup(pool, referer + pmatch[0].rm_so, (apr_size_t)(pmatch[1].rm_so - pmatch[0].rm_so)); 

    return search_engine_str;
}

static char *get_url_self_encode(apr_pool_t *pool, const char *string, int s_pos, int e_pos)
{
    char *first_str;
    char *second_str;
    char *p;

    /* 查询串分割的前一段 */
    first_str = apr_pstrndup(pool, string, s_pos);
    if (first_str && (*first_str != '\0')) {
        p = first_str;
        while (*p) {
            *p = apr_toupper(*p);
            ++p;
        }

        if (strstr(first_str, "UTF-8")) {
            return "UTF-8";
        } else if (strstr(first_str, "GBK")) {
            return "GBK";
        } else if (strstr(first_str, "GB2312")) {
            return "GB2312";
        } else if (strstr(first_str, "BIG5")) {
            return "BIG5";
        } else if (strstr(first_str, "GB18030")) {
            return "GB18030";
        }
    }

    /* 查询串分割的后一段 */
    second_str = apr_pstrdup(pool, string + e_pos);
    if (second_str && (*second_str != '\0')) {
        p = second_str;
        while (*p) {
            *p = apr_toupper(*p);
            ++p;
        }

        if (strstr(second_str, "UTF-8")) {
            return "UTF-8";
        } else if (strstr(second_str, "GBK")) {
            return "GBK";
        } else if (strstr(second_str, "GB2312")) {
            return "GB2312";
        } else if (strstr(second_str, "BIG5")) {
            return "BIG5";
        } else if (strstr(second_str, "GB18030")) {
            return "GB18030";
        }
    }

    return NULL;
}

static char *get_keywords_string_and_encodedtype(apr_pool_t *pool, const char *referer, char *type, int type_len)
{
    ap_regmatch_t pmatch[AP_MAX_REG_MATCH];
    apr_status_t rv;
    char *keywords_str;
    char *search_engine_str;
    enum SEARCH_ENGINE_ID search_engine_id;
    char *url_self_encode;

    if (g_search_engine_regex == NULL) {
        return NULL;
    }

    rv = ap_regexec(g_search_engine_regex, referer, AP_MAX_REG_MATCH, pmatch, 0);
    if (rv) {
        return NULL;
    }

    search_engine_str = apr_pstrndup(pool, referer + pmatch[0].rm_so, (apr_size_t)(pmatch[1].rm_so - pmatch[0].rm_so)); 
    if (search_engine_str == NULL) {
        return NULL;
    }

    search_engine_id = get_search_engine_id(search_engine_str);
    if (search_engine_id < ENGINE_MIN || search_engine_id > ENGINE_MAX) {
        return NULL;
    } 

    url_self_encode = get_url_self_encode(pool, referer, pmatch[1].rm_so, pmatch[1].rm_eo);
    if (url_self_encode) {
        /* 如果url中带有编码，则优先使用url中的编码 */
        strncpy(type, url_self_encode, type_len);
    } else {
        strncpy(type, g_search_engine_info[search_engine_id][COLUMN_ENCODED], type_len);
    }

    keywords_str = apr_pstrndup(pool, referer + pmatch[1].rm_so, (apr_size_t)(pmatch[1].rm_eo - pmatch[1].rm_so)); 
        
    return keywords_str;
}

static int convert_encode(apr_pool_t *p, const char *from_charset, const char *to_charset,  
            char *inbuf, apr_size_t inbytes, char *outbuf, apr_size_t outbytes)
{
    apr_status_t rv;
    apr_xlate_t *convset;

    rv = 0;
    rv = apr_xlate_open(&convset, to_charset, from_charset, p);
    if (rv != APR_SUCCESS) {
        return rv;
    }

    rv = apr_xlate_conv_buffer(convset, inbuf, &inbytes, outbuf, &outbytes);
    if (rv != APR_SUCCESS) {
        outbuf = NULL;
        apr_xlate_close(convset);
        return rv;
    }
    
    apr_xlate_close(convset);

    return 0;
}

AP_DECLARE(char *) ap_convert_all_to_utf8(apr_pool_t *pool, char *string, char *encode_type)
{
    char *utf8_str;
    apr_size_t inlen, outlen;
    int rv;

    rv = 0;
    if (!strcmp(encode_type, "UTF-8")) {
        utf8_str = string;
    } else {
        inlen = (apr_size_t)strlen(string);
        outlen = (apr_size_t)((inlen + 1) * 4);
        utf8_str = apr_palloc(pool, outlen);
        memset(utf8_str, 0, outlen);
        rv = convert_encode(pool, encode_type, "UTF-8", string, inlen, utf8_str, outlen);
    }
    
    if (rv) {
        utf8_str = NULL;
    }
      
    return utf8_str;
}

static int url_decoded(char *url)
{
    register int badesc, badpath;
    char *x, *y;

    badesc = 0;
    badpath = 0;
    
    y = strchr(url, '%');
    if (y == NULL) {
        return OK;
    }
    
    for (x = y; *y; ++x, ++y) {
        if (*y != '%') {
             if (*y == '+') {
                *x = ' ';
             } else {
                *x = *y;
             }
        } else {
            if (!apr_isxdigit(*(y + 1)) || !apr_isxdigit(*(y + 2))) {
                badesc = 1;
                *x = '%';
            } else { 
                *x = x2c(y + 1);
                y += 2;
                if (IS_SLASH(*x) || *x == '\0') {
                    badpath = 1;
                }
            }
        }
    }
    
    *x = '\0';
    if (badesc) {
        return 1;
    } else if (badpath) {
        return 2;
    } else {
        return 0;
    }
}

AP_DECLARE(int) ap_get_client_access_type(apr_pool_t *pool, const request_rec *r)
{
    const char *referer;
    const char *host;
    char *search_engine_str;
    enum SEARCH_ENGINE_ID search_engine_id;
    ap_regmatch_t pmatch[AP_MAX_REG_MATCH];
    apr_status_t rv;
    char *referer_domain, *host_domain;

    referer = apr_table_get(r->headers_in, "Referer");
    if (referer == NULL) {
        goto __exit;
    }

    host = apr_table_get(r->headers_in, "Host");
    if (host == NULL) {
        goto __exit;
    }

    search_engine_str = get_search_engine_string(pool, referer);
    if (search_engine_str != NULL) {
        search_engine_id = get_search_engine_id(search_engine_str);  
        if (search_engine_id >= ENGINE_MIN && search_engine_id <= ENGINE_MAX) {
            return ACCESS_SEARCH;
        }
    }

    /* 正则进行匹配 */
    if (g_domain_name_regex == NULL) {
        goto __exit;
    }

    /* 获取Referer中的域名 最多匹配三级域名 */
    rv = ap_regexec(g_domain_name_regex, referer, AP_MAX_REG_MATCH, pmatch, 0);
    if (rv) {
        goto __exit;
    }
    referer_domain = apr_pstrndup(pool, referer + pmatch[1].rm_so, (apr_size_t)(pmatch[1].rm_eo - pmatch[1].rm_so));

    /* 获取Host中的域名 最多匹配三级域名 */
    rv = ap_regexec(g_domain_name_regex, host, AP_MAX_REG_MATCH, pmatch, 0);
    if (rv) {
        goto __exit;
    }
    host_domain = apr_pstrndup(pool, host + pmatch[1].rm_so, (apr_size_t)(pmatch[1].rm_eo - pmatch[1].rm_so));

    /* Host域名与Referer域名相同，则是通过自身网页跳转，否则就是通过广告跳转 */
    if (!strcmp(referer_domain, host_domain)) {
        return ACCESS_WEB;
    } else {
        return ACCESS_AD;
    }    

__exit:    
    return ACCESS_DIRECT;    
}

AP_DECLARE(char *) ap_get_client_search_engine(apr_pool_t *pool, const request_rec *r)
{
    const char *referer;
    char *search_engine_str;
    enum SEARCH_ENGINE_ID search_engine_id;

    referer = apr_table_get(r->headers_in, "Referer");
    if (referer == NULL) {
        return NULL;
    }
    
    search_engine_str = get_search_engine_string(pool, referer);
    if (search_engine_str == NULL) {
        return NULL;
    }

    search_engine_id = get_search_engine_id(search_engine_str);
    if (search_engine_id < ENGINE_MIN || search_engine_id > ENGINE_MAX) {
        return NULL;
    }

    return g_search_engine_info[search_engine_id][COLUMN_NAME];
}

AP_DECLARE(char *) ap_get_client_keywords(apr_pool_t *pool, const request_rec *r)
{
    const char *referer;
    char *keywords = NULL, *utf8_keywords = NULL;
    char encode_type[16] = {0};
    int rv;

    referer = apr_table_get(r->headers_in, "Referer");
    if (referer == NULL) {
        return NULL;
    }

    keywords = get_keywords_string_and_encodedtype(pool, referer, encode_type, 16);
    if (keywords == NULL) {
        return NULL;
    }

    /* url解码 */
    rv = url_decoded(keywords);
    if (rv) {
        return NULL;
    }

    /* 全部转化为utf8 */
    utf8_keywords = ap_convert_all_to_utf8(pool, keywords, encode_type);

    return utf8_keywords;
}

AP_DECLARE(const char *) ap_mk_geo_na(const char *p)
{ 
    return p ? (p[0] ? p : "N/A" ) : "N/A";
}

AP_DECLARE(int) browser_regex_compile(apr_pool_t *pool)
{
    char *regex[BROWSER_REGEX_NUM];
    int cflags;
    char *b_pattern;
    char *temp_str;
    int i;
    
    b_pattern = browser_type[0];
    for (i = 1; i < sizeof(browser_type)/sizeof(char*); i++) {
        if (strcmp(browser_type[i], "firefox") == 0 || strcmp(browser_type[i], "mozilla") == 0 ||
            strcmp(browser_type[i], "safari") == 0 || strcmp(browser_type[i], "applewebkit") == 0) {
            continue;
        }

        if (strcmp(browser_type[i], "nitro) opera") == 0) {
            temp_str = apr_pstrdup(pool, "nitro\\) opera");
            b_pattern = apr_pstrcat(pool, b_pattern, "|", temp_str, NULL);
            continue;
        }

        b_pattern = apr_pstrcat(pool, b_pattern, "|", browser_type[i], NULL);
    }

    regex[0] = apr_pstrdup(pool, "[; ]Mozilla\\/[0-9.]+ \\([^)]+\\)");
    regex[1] = apr_pstrdup(pool, "~^BlackBerry\\d+/~");
    regex[2] = apr_psprintf(pool, "(%s)[\\/\\sa-z(]*([0-9]+)([\\.0-9a-z]+)?", b_pattern);
    regex[3] = apr_pstrdup(pool, "(firefox|safari)[\\/\\sa-z(]*([0-9]+)([\\.0-9a-z]+)?");
    regex[4] = apr_pstrdup(pool, "(applewebkit)[\\/\\sa-z(]*([0-9]+)([\\.0-9a-z]+)?");
    regex[5] = apr_pstrdup(pool, "^(mozilla)\\/([0-9]+)([\\.0-9a-z-]+)?(?: \\[[a-z]{2}\\])? (?:\\([^)]*\\))$");
    regex[6] = apr_pstrdup(pool, "^(mozilla)\\/[0-9]+(?:[\\.0-9a-z-]+)?\\s\\(.* rv:([0-9]+)([.0-9a-z]+)\\)gecko(\\/[0-9]{8}|$)(?:.*)");

    cflags = AP_REG_EXTENDED;
    g_browser_regex[0] = ap_pregcomp(pool, regex[0], cflags);
    if (g_browser_regex[0] == NULL) {
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, NULL, "%s compile failed", regex[0]);
        return -1;  
    }

    g_browser_regex[1] = ap_pregcomp(pool, regex[1], cflags);
    if (g_browser_regex[1] == NULL) {
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, NULL, "%s compile failed", regex[1]);
        return -1;  
    }

    cflags = AP_REG_ICASE;
    g_browser_regex[2] = ap_pregcomp(pool, regex[2], cflags);
    if (g_browser_regex[2] == NULL) {
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, NULL, "%s compile failed", regex[2]);
        return -1;  
    }

    g_browser_regex[3] = ap_pregcomp(pool, regex[3], cflags);
    if (g_browser_regex[3] == NULL) {
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, NULL, "%s compile failed", regex[3]);
        return -1;  
    }

    g_browser_regex[4] = ap_pregcomp(pool, regex[4], cflags);
    if (g_browser_regex[4] == NULL) {
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, NULL, "%s compile failed", regex[4]);
        return -1;  
    }

    g_browser_regex[5] = ap_pregcomp(pool, regex[5], cflags);
    if (g_browser_regex[5] == NULL) {
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, NULL, "%s compile failed", regex[5]);
        return -1;  
    }

    g_browser_regex[6] = ap_pregcomp(pool, regex[6], cflags);
    if (g_browser_regex[6] == NULL) {
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, NULL, "%s compile failed", regex[6]);
        return -1;  
    }
    
    return 0;
}

AP_DECLARE(int) log_send(char *buf, int is_deffered)
{
    int rv, i;
    
    if (!buf) {
        return -1;
    }

    i = 0;
    rv = pe_log_client_write(g_log_client, is_deffered, buf, strlen(buf));
    if (rv < 0) {
        for ( i = 0; i < RECONNECT_NUM; ++i ) {
            if (!pe_log_client_check_conn(g_log_client)) {
                rv = pe_log_client_connect(g_log_client);
                if (rv != 0) {
                    continue;
                }
            }

            return pe_log_client_write(g_log_client, is_deffered, buf, strlen(buf));
        }
    }

    if (i == RECONNECT_NUM) {
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, NULL, "reconnect failure %d", rv);
    }
    
    return rv;
} 

