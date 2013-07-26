/*
 * $Id: msc_cookie_signature.c 2786 2013-07-09 16:42:55 FreeWAF Development Team $
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

#include "re.h"
#include <ctype.h>
#include "apr_lib.h"
#include "apr_strmatch.h"
#include "apr_sha1.h"
#include "msc_parsers.h"
#include "msc_cookie_key.h"

static char *get_signature_key(modsec_rec *msr)
{
    return get_cookie_key(msr);
}

static char *compute_signature(modsec_rec *msr, char *input, int input_len)
{
    unsigned char digest[APR_SHA1_DIGESTSIZE];
    apr_sha1_ctx_t context;
    char *signature;

    apr_sha1_init(&context);
    apr_sha1_update(&context, (const char *)input, input_len);
    apr_sha1_final(digest, &context);
    signature = bytes2hex(msr->mp, digest, APR_SHA1_DIGESTSIZE);

    return signature;
}

/**
 * get_cookie_signature - 获取cookie签名
 * @msr: 处理上下文
 * @cookie_name_tb: 用于生成签名的cookiename清单
 * @need_ip: 生成签名时是否需要ip
 *
 * 成功返回签名字符串，失败时返回NULL
 */
char *get_cookie_signature(modsec_rec *msr, apr_table_t *cookie_name_tb, int need_ip)
{
    const apr_array_header_t  *cookiename_arr;
    apr_table_entry_t *cookiename_te;
    char *signature_key, *pre_signature, *signature;
    int i;
    
    if (msr == NULL || cookie_name_tb == NULL) {
        return NULL;
    }

    signature_key = get_signature_key(msr);
    if (signature_key == NULL) {
        return NULL;
    }

    /* 构造预签名字符串 */
    pre_signature = NULL;
    cookiename_arr = apr_table_elts(cookie_name_tb);
    cookiename_te = (apr_table_entry_t *)cookiename_arr->elts;
    for (i = 0; i < cookiename_arr->nelts; i++) {
        pre_signature = apr_pstrcat(msr->mp, pre_signature ? pre_signature : "",
            cookiename_te[i].val ? cookiename_te[i].val : "", "|", NULL);
    }
    if (need_ip) {
        pre_signature = apr_pstrcat(msr->mp, pre_signature ? pre_signature : "", msr->remote_addr,
            "|", NULL);
    }
    pre_signature = apr_pstrcat(msr->mp, pre_signature ? pre_signature : "", signature_key, NULL);
    if (pre_signature == NULL) {
        return NULL;
    }

    /* 计算签名 */
    signature = compute_signature(msr, pre_signature, strlen(pre_signature));

    return signature;
}
