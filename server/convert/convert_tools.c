/*
 * $Id: convert_tools.c 2786 2013-07-09 16:42:55 FreeWAF Development Team $
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
#include "apr_xlate.h"
#include <ctype.h>

/* 判断输入的字符串是否全部在0到127之间 */
int is_ascii(char *str)
{
    int i, j;

    i = strlen(str);
    for (j = 0; j <= i; j++) {
        if (!isascii(str[j])) {
            return CONV_FAIL;
        }
    }

    return CONV_OK;
}

/* 将输入的from_charset格式的的字符串inbuf转换为to_charset格式的输出字符串outbuf */
int conv_char(const char *to_charset, const char *from_charset, apr_pool_t *p,
                     const char *inbuf, char *outbuf)
{
    apr_status_t rv;
    apr_xlate_t *convset;
    apr_size_t inbytes, outbytes;

    rv = 0;
    rv = apr_xlate_open(&convset, to_charset, from_charset, p);
    if (rv != APR_SUCCESS) {
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, NULL,
                     "WAF_CONVERT(%d): can't open translation %s->%s",
                     rv, from_charset, to_charset);
        return rv;
    }

    inbytes = strlen(inbuf);
    outbytes = (inbytes + 1) * 4;
    rv = apr_xlate_conv_buffer(convset, inbuf, &inbytes, outbuf, &outbytes);
    if (rv != APR_SUCCESS) {
        outbuf = NULL;
        apr_xlate_close(convset);
        return rv;
    }

    apr_xlate_close(convset);
    return CONV_OK;
}


/**
 * 将从CLI终端输入的字符串转换为UTF-8编码 
 * 转换失败则返回原来的字符串
 */
char * encode_input(char *str, apr_pool_t *ptemp)
{
    int     rv, inlen, outlen;
    char    *kw_buf;
    
    if (is_ascii(str) == CONV_OK) {
        return str;
    } else {
        inlen = strlen(str);
        outlen = (inlen + 1) * 4;
        kw_buf = apr_palloc(ptemp, outlen);
        memset(kw_buf, 0, outlen);
        rv = CONV_OK;
        switch (encode_type) {
            case UTF_8:
                return str;
            case BIG5:
                rv = conv_char("UTF-8", "BIG5", ptemp, str, kw_buf);
                break;
            case GB2312:
                rv = conv_char("UTF-8", "GB2312", ptemp, str, kw_buf);
                break;
            case GBK:
                rv = conv_char("UTF-8", "GBK", ptemp, str, kw_buf);
                break;
            case GB18030:
                rv = conv_char("UTF-8", "GB18030", ptemp, str, kw_buf);
                break;
            default:
                return str;
        }

        if (rv != CONV_OK) {
            return str;
        } else {
            return kw_buf;
        }
    }
}

/**
 * 将保存的UTF8字符转换为CLI终端可以显示的字符 
 * 转换失败则返回原来的字符串
 */
char * encode_output(char *str, apr_pool_t *ptemp)
{
    int     rv, inlen, outlen;
    char    *kw_buf;
    
    if (is_ascii(str) == CONV_OK) {
        return str;
    } else {
        inlen = strlen(str);
        outlen = (inlen + 1) * 4;
        kw_buf = apr_palloc(ptemp, outlen);
        memset(kw_buf, 0, outlen);
        rv = CONV_OK;
        switch (encode_type) {
            case UTF_8:
                return str;
            case BIG5:
                rv = conv_char("BIG5", "UTF-8", ptemp, str, kw_buf);
                break;
            case GB2312:
                rv = conv_char("GB2312", "UTF-8", ptemp, str, kw_buf);
                break;
            case GBK:
                rv = conv_char("GBK", "UTF-8", ptemp, str, kw_buf);
                break;
            case GB18030:
                rv = conv_char("GB18030", "UTF-8", ptemp, str, kw_buf);
                break;
            default:
                return str;
        }

        
        if (rv != CONV_OK) {
            return str;
        } else {
            return kw_buf;
        }
    }
}

