/*
 * $Id: convert_protocol_param.c 2786 2013-07-09 16:42:55 FreeWAF Development Team $
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

/* 协议参数处理标签 */
static char *protocol_flag[] = {
    NULL,
    "request-header-num",
    "header-size-except-cookie",
    "cookie-size",
    "request-url-size",
    "query-string-size",
    "request-argument-num",
    "request-argument-size",
    "request-body-size",
    "request-argument-name-size",
    "request-argument-name-value-size",
};

/* 协议参数防护相关子操作 */
static int protocol_keyword_add(keyword_t *k, apr_pool_t *ptemp)
{
    return modified_keyword_add(k, protocol_flag[k->type], ptemp);
}

static int protocol_keyword_del(keyword_t *k, apr_pool_t *ptemp)
{
    return modified_keyword_del(k, ptemp);
}

static int protocol_subpolicy_query(const char *name, apr_dbd_row_t *row,
                                    apr_array_header_t **result, apr_pool_t *ptemp)
{
    int                 i;
    const char          *entry;

    if ((name == NULL) || (row == NULL) || (result == NULL)
            || (*result == NULL) || (ptemp == NULL)) {
            return CONV_FAIL;
    }

    entry = apr_dbd_get_entry(driver, row, B_FLAG);
    for (i = REQUEST_HEADER_NUM; i < END_PROTOCOL; i++ ) {
        if (!strcmp(protocol_flag[i], entry)) {
            break;
        }
    }

    if (i == END_PROTOCOL) {
        return CONV_FAIL;
    }

    return modified_keyword_query(name, PROTOCOL_PARAM, row, i, result, ptemp);
}

static int protocol_subpolicy_del(const char *sec_policy, apr_pool_t *ptemp)
{
    return sub_without_new_del(sec_policy, PROTOCOL_PARAM, ptemp);
}

static int protocol_subpolicy_list(const char *sec_policy, apr_array_header_t **result,
                                   apr_pool_t *ptemp)
{
    int                 rv, i;
    const char          *sec_name;
    apr_pool_t          *ptab;

    ptab = (*result)->pool;
    sec_name = apr_dbd_escape(driver, ptemp, sec_policy, tmp_db);
    for (i = REQUEST_HEADER_NUM; i < END_PROTOCOL; i++) {
        rv = modified_keyword_list(sec_policy, PROTOCOL_PARAM, i,
                                   protocol_flag[i], result, ptemp);
        if (rv != CONV_OK) {
            return rv;
        }
    }
    return CONV_OK;
}

/* 协议参数处理驱动结构 */
subpolicy_t protocol_subpolicy = {
    PROTOCOL_PARAM,
    protocol_keyword_add,
    protocol_keyword_del,
    protocol_subpolicy_query,
    protocol_subpolicy_del,
    protocol_subpolicy_list
};

