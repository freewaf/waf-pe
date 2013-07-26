/*
 * $Id: convert_file_upload.c 2786 2013-07-09 16:42:55 FreeWAF Development Team $
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

static char *file_upload_flag[] = {
    NULL,
    "file-upload-type",
    "individual-file-size",
    "all-file-size",
};

static int file_upload_keyword_add(keyword_t *k, apr_pool_t *ptemp)
{
    int nkeyword;

    if ((k == NULL) || (ptemp == NULL)) {
        return CONV_FAIL;
    }

    /* 关键字数目不是一个则出错 */
    nkeyword = k->keyword->nelts;
    if (nkeyword != 1) {
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, NULL, "WAF_CONVERT: too much keyword!");
        return CONV_FAIL;
    }

    /* 根据关键字类型调用不同的接口 */
    switch (k->type) {
    case FILE_TYPE:
        return new_keyword_add(k, file_upload_flag[k->type], ptemp);
    case INDIVIDUAL_FILE_SIZE:
    case ALL_FILE_SIZE:
        return modified_keyword_add(k, file_upload_flag[k->type], ptemp);
    default:
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, NULL, "WAF_CONVERT: wrong type!");
        return CONV_FAIL;
    }
}

static int file_upload_keyword_del(keyword_t *k, apr_pool_t *ptemp)
{
    int rv;

    if ((k == NULL) || (ptemp == NULL)) {
        return CONV_FAIL;
    }

    /* 关键字数目不是一个则出错 */
    rv = k->keyword->nelts ;
    if (rv != 1) {
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, NULL, "WAF_CONVERT: too much keyword!");
        return CONV_FAIL;
    }

    /* 根据关键字类型调用不同的接口 */
    switch (k->type) {
        case FILE_TYPE:
            return new_keyword_del(k, ptemp);
        case INDIVIDUAL_FILE_SIZE:
        case ALL_FILE_SIZE:
            return modified_keyword_del(k, ptemp);
        default:
            ap_log_error(APLOG_MARK, APLOG_ERR, 0, NULL, "WAF_CONVERT: wrong type!");
            return CONV_FAIL;
    }
}

static int file_upload_subpolicy_query(const char *name, apr_dbd_row_t *row,
                                    apr_array_header_t **result, apr_pool_t *ptemp)
{
    int                 i;
    const char          *entry;

    if ((name == NULL) || (row == NULL) || (result == NULL)
            || (*result == NULL) || (ptemp == NULL)) {
        return CONV_FAIL;
    }

    entry = apr_dbd_get_entry(driver, row, B_FLAG);
    for (i = FILE_TYPE; i <= ALL_FILE_SIZE; i++ ) {
        if (!strcmp(file_upload_flag[i], entry)) {
            break;
        }
    }

    if (i > ALL_FILE_SIZE) {
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, NULL, "WAF_CONVERT: wrong type!");
        return CONV_FAIL;
    }

    switch (i) {
        case FILE_TYPE:
            return new_keyword_query(name, FILE_UPLOAD, row, i, result, ptemp);
        case INDIVIDUAL_FILE_SIZE:
        case ALL_FILE_SIZE:
            return modified_keyword_query(name, FILE_UPLOAD, row, i, result, ptemp);
    }

    return CONV_FAIL;
}

static int file_upload_subpolicy_del(const char *sec_policy, apr_pool_t *ptemp)
{
    return sub_without_new_del(sec_policy, FILE_UPLOAD, ptemp);
}

static int file_upload_subpolicy_list(const char *sec_policy,
                                      apr_array_header_t **result, apr_pool_t *ptemp)
{
    int i, rv;

    if ((sec_policy == NULL) || (result == NULL) || (*result == NULL) || (ptemp == NULL)) {
        return CONV_FAIL;
    }

    for (i = FILE_TYPE; i <= ALL_FILE_SIZE; i++ ) {
        switch (i) {
            case FILE_TYPE:
                rv = new_keyword_list(sec_policy, FILE_UPLOAD, i,
                                      file_upload_flag[i], ASCII, result, ptemp);
                break;
            case INDIVIDUAL_FILE_SIZE:
            case ALL_FILE_SIZE:
                rv = modified_keyword_list(sec_policy, FILE_UPLOAD, i,
                                           file_upload_flag[i], result, ptemp);
                break;
        }

        if (rv != CONV_OK) {
            return rv;
        }
    }

    return CONV_OK;
}

/* 请求方法处理驱动结构 */
subpolicy_t file_upload_subpolicy = {
    FILE_UPLOAD,
    file_upload_keyword_add,
    file_upload_keyword_del,
    file_upload_subpolicy_query,
    file_upload_subpolicy_del,
    file_upload_subpolicy_list
};
