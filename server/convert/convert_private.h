/*
 * $Id: convert_private.h 2786 2013-07-09 16:42:55 FreeWAF Development Team $
 *
 * (C) 2013-2014 see FreeWAF Development Team
 *
 *  This Program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2, or (at your option)
 *  any later version.
 *
 *  This Program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with GNU Make; see the file LICENSE.GPLv2.  If not, write to
 *  the Free Software Foundation, 675 Mass Ave, Cambridge, MA 02139, USA.
 *  http://www.gnu.org/licenses/gpl-2.0.html
 *
 */

#ifndef _CONVERT_PRIVATE_H_
#define _CONVERT_PRIVATE_H_

#ifdef __cplusplus
extern "C" {
#endif

#include "apr.h"
#include "apr_dbd.h"
#include "apr_strings.h"
#include "apr_tables.h"

#include "bitmap.h"
#include "cli_common.h"
#include "convert_rule.h"

/* default database */
#if APU_HAVE_SQLITE3
#define SQL_TYPE            "sqlite3"
#define DEFAULT_DB          "/usr/local/inner_sec_policy.db"
#elif APU_HAVE_MYSQL
#define DEFAULT_DB          "inner_sec_policy"
#endif

/* tables' name */
#define BASIC_TAB           "basis"
#define EXTEND_TAB          "extension"

/* temporary database */
#define TEMP_DB             ":memory:"

/* tables' name */
#define SEC_POLICY_TAB      "sec_policy"
#define KEYWORD_ID_TAB      "keyword_id"
#define KEYWORD_TAB         "keyword"
#define NEW_TAB             "new"
#define WEAK_PASSWD_TAB     "weak_passwd"

#define BLACK_WHITE         "black_white"

/* phase */
#define PHASE_REQUEST       2
#define PHASE_RESPONSE      4

#define MAX_POLICY          10000

#define KEYWORD_FIRST       1
#define KEYWORD_SECOND      2

#define PLAIN               1
#define REGEX               2
#define DEF_REGEX           3
#define TYPE_ALL            4

#define KEYWORD_LEN         7168

/* sec_subpolicy */
typedef struct {
    /* sub_policy's type */
    subpolicy_type_t type;

    /* add keyword */
    int (*keyword_add)(keyword_t *k, apr_pool_t *ptemp);

    /* delete keyword */
    int (*keyword_del)(keyword_t *t, apr_pool_t *ptemp);

    /* query subpolicy */
    int (*subpolicy_query)(const char *name, apr_dbd_row_t *row,
                           apr_array_header_t **result, apr_pool_t *ptemp);

    /* delete subpolicy */
    int (*subpolicy_del)(const char *name, apr_pool_t *ptemp);

    /* list keyword */
    int (*subpolicy_list)(const char *sec_policy, apr_array_header_t **result, apr_pool_t *ptemp);
} subpolicy_t;

typedef struct {
    char    *keyword;   /* Configuration Directive */
    int     type;       /* parameters' type of Directive */
} type_t;

/* select * from basis left join extension on ... */
enum column {           /* column's name of the row */
    B_LIST_ID = 0,      /* basis.list_id */
    B_TYPE,             /* basis.type */
    B_KEYWORD,          /* basis.keyword */
    B_VAR,              /* basis.variable */
    B_OPER,             /* basis.operator */
    B_CHK_VAL,          /* basis.check_value */
    B_CHAIN,            /* basis.chain */
    B_TRANS,            /* basis.trans_func */
    B_ACT,              /* basis.action */
    B_FLAG,             /* basis.flag */
    E_LIST_ID,          /* extension.list_id */
    E_PHASE,            /* extension.phase */
    E_ID,               /* extension.id */
    E_DISRUPT,          /* extension.disruptive */
    E_LOG,              /* extension.log */
    E_MSG,              /* extension.msg */
    TOTAL               /* total num of column */
};

enum encode {
    ASCII = 0,
    ZH_CN
};

/* 数据库驱动 */
extern const apr_dbd_driver_t  *driver;
extern apr_dbd_t               *default_db;
extern apr_dbd_t               *tmp_db;

extern char *policy_type[];
extern unsigned long kw_id_flag;
extern struct bitmap nbitmap;

extern const subpolicy_t **conv_subpolicy_list;

extern apr_pool_t *pconv;
extern apr_pool_t *ptrans;

extern subpolicy_t sql_subpolicy;
extern subpolicy_t protocol_subpolicy;
extern subpolicy_t request_method_subpolicy;
extern subpolicy_t file_download_subpolicy;
extern subpolicy_t file_upload_subpolicy;
extern subpolicy_t server_version_subpolicy;
extern subpolicy_t iccard_information_subpolicy;
extern subpolicy_t idcard_information_subpolicy;
extern subpolicy_t xss_subpolicy;
extern subpolicy_t spider_scanner_subpolicy;
extern subpolicy_t keyword_filter_subpolicy;
extern subpolicy_t cookie_subpolicy;
extern subpolicy_t command_subpolicy;
extern subpolicy_t trojan_subpolicy;
extern subpolicy_t weak_passwd_subpolicy;
extern subpolicy_t cc_protect_subpolicy;
extern subpolicy_t code_subpolicy;
extern subpolicy_t csrf_subpolicy;

extern void subpolicy_init(apr_pool_t *p);
extern int keyword_check(const char *keyword, const char *flag, apr_pool_t *ptemp);

extern int modified_keyword_del(keyword_t *k, apr_pool_t *ptemp);
extern int modified_keyword_add(keyword_t *k, const char *flag, apr_pool_t *ptemp);
extern int modified_keyword_list(const char *sec_policy, int sec_subpolicy, int type,
                                 const char *flag, apr_array_header_t **result,
                                 apr_pool_t *ptemp);
extern int modified_keyword_query(const char *name, int sec_subpolicy, apr_dbd_row_t *row,
                                  int type, apr_array_header_t **result, apr_pool_t *ptemp);

extern int new_keyword_add(keyword_t *k, const char *flag, apr_pool_t *ptemp);
extern int new_keyword_del(keyword_t *k, apr_pool_t *ptemp);
extern int new_keyword_list(const char *sec_policy, int sec_subpolicy, int type,
                            const char *mod_flag, int conv_flag,  apr_array_header_t **result,
                            apr_pool_t *ptemp);
extern int new_keyword_query(const char *name, int sec_subpolicy, apr_dbd_row_t *row, int type,
                      apr_array_header_t **result, apr_pool_t *ptemp);

extern int sub_without_new_del(const char *sec_policy, int sub_policy, apr_pool_t *ptemp);

extern void combined_rule(apr_dbd_row_t *row, const char *check_val, const char *new_id,
                          apr_array_header_t **result, apr_pool_t *ptemp);

extern int add_two_keyword(keyword_t *k, apr_pool_t *ptemp);
extern int delete_two_keyword(keyword_t *k, apr_pool_t *ptemp, int flag);
extern int list_two_keyword(const char *sec_policy, int type,
                            apr_array_header_t **result, apr_pool_t *ptemp);
extern int sub_with_new_del(const char *sec_policy, int sub_policy, apr_pool_t *ptemp);
extern char *escape(const char *string, apr_pool_t *ptemp);
extern char *escape_keyword(const char *string, apr_pool_t *ptemp);
extern int query_info_leakage(const char *name, int type, char *orig_rule,
                              apr_array_header_t **result, apr_pool_t *ptemp);

/* 将CLI输入转为UTF8 */
extern char * encode_input(char *str, apr_pool_t *ptemp);

/* 将UTF8输出到CLI */
extern char * encode_output(char *str, apr_pool_t *ptemp);

/* 将输入的from_charset格式的的字符串inbuf转换为to_charset格式的输出字符串outbuf */
extern int conv_char(const char *to_charset, const char *from_charset, apr_pool_t *p,
                     const char *inbuf, char *outbuf);

/* 设置黑白名单的缺省值 */
extern int convert_access_default_set(void);

#ifdef __cplusplus
}
#endif

#endif /* !APACHE_CLI_COMMON_H */
/** @} */

