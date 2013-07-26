/*
 * $Id: convert_subpolicy.c 2786 2013-07-09 16:42:55 FreeWAF Development Team $
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
#include "convert_private.h"

const subpolicy_t **conv_subpolicy_list = NULL;

/* 检查关键字是否已经存在于内置库中 */
int keyword_check(const char *keyword, const char *flag, apr_pool_t *ptemp)
{
    int                 i, rv;
#if APU_HAVE_MYSQL
    int                 num;
#endif
    char                *state, *p, *q;
    const char          *entry;
    apr_dbd_results_t   *res = NULL;
    apr_dbd_row_t       *row = NULL;

    if ((keyword == NULL) || (flag == NULL) || (ptemp == NULL)) {
        return CONV_FAIL;
    }

    state = apr_psprintf(ptemp, "SELECT check_value from %s where flag = '%s'",
                         BASIC_TAB, flag);
    rv = apr_dbd_select(driver, ptemp, default_db, &res, state, 1);
    if (rv > 0) {
        return CONV_FAIL;
    }

    rv = apr_dbd_num_tuples(driver, res);
    if (rv == 0) {
        return CONV_OK;
    }

#if APU_HAVE_SQLITE3
    for (i = rv; i > 0; i--) {
        rv = apr_dbd_get_row(driver, ptemp, res, &row, -1);
#elif APU_HAVE_MYSQL
    num = rv;
    for (i = 1; i <= num; i++) {
        rv = apr_dbd_get_row(driver, ptemp, res, &row, i);
#endif
        if (rv == -1) {
            return CONV_FAIL;
        }

        entry = apr_dbd_get_entry(driver, row, 0);
        if (entry == NULL) {
            return CONV_FAIL;
        }

        p = (char *)entry;
        while (*p != '\0') {
            while (*p == ' ') {
                p++;;
            }

            if ((*p == '\\') && (*(p + 1) = '\'')) {       /* 字符串以\'分割 */
                p = p + 2;
                while (1) {
                    q = strchr(p, '\\');
                    if (q == NULL) {
                        break;
                    } else if (*(q + 1) == '\'') {
                        *q = '\0';
                        break;
                    }
                }
                q = q + 2;

            } else {                /* 字符串以空格分隔 */
                q = strchr(p, ' ');
                if (q != NULL) {
                    *q = '\0';
                }
            }

            if (!strcmp(p, keyword)) {
                return CONV_EXIST;
            }

            if (q == NULL) {
                break;
            }

            p = q + 1;
            while (*p == ' ') {     /* 去除后边的空白 */
                p++;
            }
        }
    }

    return CONV_OK;
}

/* 用于信息泄漏中，将'/'转换为'\/', 将'"'转换为'\"' */
char *escape(const char *string, apr_pool_t *ptemp)
{
    int i, j, len;
    char *s;

    if ((string == NULL) || (ptemp == NULL)) {
        return NULL;
    }

    len = strlen(string);
    s = apr_pcalloc(ptemp, len* 2);
    for (i = 0, j = 0; i < len; i++) {
        if ((*(string + i) != '/') && (*(string + i) != '"')) {
            *(s+j++) = *(string + i);
        } else {
            *(s+j++) = '\\';
            *(s+j++) = *(string + i);
        }
    }

    return s;
}

/* 用于规则生成中，将'"'转换为'\"' */
char *escape_keyword(const char *string, apr_pool_t *ptemp)
{
    int i, j, len;
    char *s;

    if ((string == NULL) || (ptemp == NULL)) {
        return NULL;
    }

    len = strlen(string);
    s = apr_pcalloc(ptemp, len* 2);
    for (i = 0, j = 0; i < len; i++) {
        if ((*(string + i) != '"')) {
            *(s+j++) = *(string + i);
        } else {
            *(s+j++) = '\\';
            *(s+j++) = *(string + i);
        }
    }

    return s;
}

static void add_sub_policy(subpolicy_t *sub_policy)
{
    conv_subpolicy_list[sub_policy->type] = sub_policy;
    return ;
}

void subpolicy_init(apr_pool_t *p)
{
    conv_subpolicy_list = apr_pcalloc(p, MAX_SUBPOLICY * sizeof(subpolicy_t *));

    add_sub_policy(&sql_subpolicy);
    add_sub_policy(&protocol_subpolicy);
    add_sub_policy(&request_method_subpolicy);
    add_sub_policy(&file_download_subpolicy);
    add_sub_policy(&file_upload_subpolicy);
    add_sub_policy(&server_version_subpolicy);
    add_sub_policy(&iccard_information_subpolicy);
    add_sub_policy(&idcard_information_subpolicy);
    add_sub_policy(&xss_subpolicy);
    add_sub_policy(&spider_scanner_subpolicy);
    add_sub_policy(&keyword_filter_subpolicy);
    add_sub_policy(&cookie_subpolicy);
    add_sub_policy(&command_subpolicy);
    add_sub_policy(&trojan_subpolicy);
    add_sub_policy(&weak_passwd_subpolicy);
    add_sub_policy(&cc_protect_subpolicy);
    add_sub_policy(&code_subpolicy);
    add_sub_policy(&csrf_subpolicy);
}

