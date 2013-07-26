/*
 * $Id: convert_keyword_filter.c 2786 2013-07-09 16:42:55 FreeWAF Development Team $
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

/* reserved for build-in library */
static char *keyword_filter = "keyword-filter";

static char * filter_rule = "SecRule ARGS|XML:/* \"%s\" \"phase:2, t:none, t:replaceComments,"\
                         "t:removeWhitespace,t:urlDecode,t:lowercase,severity:'2', block,"\
                         "tag:'Keyword Attack', id:'%s'\"";

static int keyword_filter_subpolicy_del(const char *sec_policy, apr_pool_t *ptemp);

static int keyword_add(keyword_t *k, const char *keyword, apr_pool_t *ptemp)
{
    int                     rv, nrow, new_id;
    unsigned long           kw_id;
    char                    *state;
    const char              *sec_name;
    apr_dbd_transaction_t   *trans = NULL;

    kw_id = kw_id_flag++;
    new_id = bm_firstunset(&nbitmap);
    bm_setbit(&nbitmap, new_id);
    sec_name = apr_dbd_escape(driver, ptemp, k->sec_policy, tmp_db);

    /* 插入指定的关键字 */
    rv = apr_dbd_transaction_start(driver, ptemp, tmp_db, &trans);
    if (rv > 0) {
        kw_id_flag--;
        bm_clrbit(&nbitmap, new_id);
        return CONV_FAIL;
    }

    state = apr_psprintf(ptemp, "INSERT INTO %s VALUES (%ld, '%s', %d, %d)",
                         KEYWORD_ID_TAB, kw_id_flag, sec_name, k->sec_subpolicy, k->type);
    rv = apr_dbd_query(driver, tmp_db, &nrow, state);
    if (rv > 0) {
        kw_id_flag--;
        bm_clrbit(&nbitmap, new_id);
        apr_dbd_transaction_end(driver, ptemp, trans);
        return CONV_FAIL;
    }

    state = apr_psprintf(ptemp, "INSERT INTO %s VALUES (%ld, %d, '%s')",
                         KEYWORD_TAB, kw_id_flag, KEYWORD_FIRST, keyword);
    rv = apr_dbd_query(driver, tmp_db, &nrow, state);
    if (rv > 0) {
        kw_id_flag--;
        bm_clrbit(&nbitmap, new_id);
        apr_dbd_transaction_end(driver, ptemp, trans);
        return CONV_FAIL;
    }

    state = apr_psprintf(ptemp, "INSERT INTO %s VALUES (%ld, %d)",
                         NEW_TAB, kw_id_flag, new_id);
    rv = apr_dbd_query(driver, tmp_db, &nrow, state);
    if (rv > 0) {
        kw_id_flag--;
        bm_clrbit(&nbitmap, new_id);
        apr_dbd_transaction_end(driver, ptemp, trans);
        return CONV_FAIL;
    }

    rv = apr_dbd_transaction_end(driver, ptemp, trans);
    if (rv > 0) {
        kw_id_flag--;
        bm_clrbit(&nbitmap, new_id);
        return CONV_FAIL;
    }

    return CONV_OK;
}

static int keyword_filter_keyword_add(keyword_t *k, apr_pool_t *ptemp)
{
    int                     rv, nrows, inlen, outlen;
    char                    *state, **kw, *kw_buf, *new_id;
    const char              *sec_name, *keyword, *kw_id;
    apr_dbd_results_t       *res = NULL;
    apr_dbd_row_t           *row = NULL;

    if ((k == NULL) || (ptemp == NULL) || (k->keyword->nelts != 1)) {
        return CONV_FAIL;
    }

    kw = apr_array_pop(k->keyword);
    kw_buf = encode_input(*kw, ptemp);

    /* 查询安全子策略下是否存在此关键字 */
    sec_name = apr_dbd_escape(driver, ptemp, k->sec_policy, tmp_db);
    keyword = apr_dbd_escape(driver, ptemp, kw_buf, tmp_db);
    state = apr_psprintf(ptemp, "SELECT keyword_id FROM %s WHERE value = '%s' AND"\
                         " keyword_id IN (SELECT keyword_id FROM %s WHERE sec_policy"\
                         " = '%s' AND sec_subpolicy = %d)",
                         KEYWORD_TAB, keyword, KEYWORD_ID_TAB, sec_name, k->sec_subpolicy);
    rv = apr_dbd_select(driver, ptemp, tmp_db, &res, state, 1);
    if (rv > 0) {
        return CONV_FAIL;
    }

    rv = apr_dbd_num_tuples(driver, res);
    if (rv == -1) {
        return DECLINED;
    } else if (rv > 0) {        /* 已经存在相同的关键字 */
        return CONV_CONFLICT;
    }

    state = apr_psprintf(ptemp, "SELECT keyword_id FROM %s where sec_policy = '%s' and"\
                         " sec_subpolicy = %d and type = %d", KEYWORD_ID_TAB,
                         sec_name, k->sec_subpolicy, k->type);
    rv = apr_dbd_select(driver, ptemp, tmp_db, &res, state, 1);
    if (rv > 0) {
        return CONV_FAIL;
    }
    rv = apr_dbd_num_tuples(driver, res);
    if (rv == -1) {
        return rv;
    } else if (rv == 0) {
        /* 本子模式下不存在关键字 */
        return keyword_add(k, keyword, ptemp);
    } else if (rv > 0) {
        /* 本子模式下存在关键字 */
        new_id = NULL;
#if APU_HAVE_SQLITE3
        rv = apr_dbd_get_row(driver, ptemp, res, &row, -1);
#elif APU_HAVE_MYSQL
        rv = apr_dbd_get_row(driver, ptemp, res, &row, 1);
#endif
        if (rv == -1) {
            return CONV_FAIL;
        }

        kw_id = apr_dbd_get_entry(driver, row, 0);
        if (!kw_id) {
            return CONV_FAIL;
        }

        state = apr_psprintf(ptemp, "INSERT INTO %s VALUES (%s, %d, '%s')",
                             KEYWORD_TAB, kw_id, KEYWORD_FIRST, keyword);
        rv = apr_dbd_query(driver, tmp_db, &nrows, state);
        if (rv > 0) {
            return CONV_FAIL;
        }
    }
    return CONV_OK;
}

static int keyword_filter_keyword_del(keyword_t *k, apr_pool_t *ptemp)
{
    int                     rv, inlen, outlen;
    int                     nrow;
    char                    *state;
    const char              **kw, *kw_id, *sec_name, *keyword;
    apr_dbd_results_t       *res = NULL;
    apr_dbd_row_t           *row = NULL;

    if ((k == NULL) || (ptemp == NULL) || (k->keyword->nelts != 1)) {
        return CONV_FAIL;
    }

    if (k->flag == FLAG_ALL) {
        return keyword_filter_subpolicy_del(k->sec_policy, ptemp);
    }

    kw = apr_array_pop(k->keyword);
    if (kw == NULL || *kw == NULL) {
        return CONV_FAIL;
    }

    /* 查询安全子策略下是否存在此关键字 */
    sec_name = apr_dbd_escape(driver, ptemp, k->sec_policy, tmp_db);
    keyword = apr_dbd_escape(driver, ptemp, *kw, tmp_db);
    state = apr_psprintf(ptemp, "SELECT keyword_id FROM %s WHERE value = '%s' AND"\
                         " keyword_id IN (SELECT keyword_id FROM %s WHERE sec_policy"\
                         " = '%s' AND sec_subpolicy = %d)",
                         KEYWORD_TAB, keyword, KEYWORD_ID_TAB, sec_name, k->sec_subpolicy);
    rv = apr_dbd_select(driver, ptemp, tmp_db, &res, state, 1);
    if (rv > 0) {
        return CONV_FAIL;
    }

    rv = apr_dbd_num_tuples(driver, res);
    if (rv == -1) {
        return CONV_FAIL;
    } else if (rv == 0) {           /* 不存在此关键字 */
        return CONV_NOTEXIST;
    }

    /* 取出 keyword_id,查询关键字数量 */
#if APU_HAVE_SQLITE3
    rv = apr_dbd_get_row(driver, ptemp, res, &row, -1);
#elif APU_HAVE_MYSQL
    rv = apr_dbd_get_row(driver, ptemp, res, &row, 1);
#endif
    if (rv > 0) {
        return CONV_FAIL;
    }

    kw_id = apr_dbd_get_entry(driver, row, 0);
    if (kw_id == NULL) {
        return CONV_FAIL;
    }

    state = apr_psprintf(ptemp, "SELECT value FROM %s where keyword_id = %s", KEYWORD_TAB, kw_id);
    rv = apr_dbd_select(driver, ptemp, tmp_db, &res, state, 1);
    if (rv > 0) {
        return CONV_FAIL;
    }
    rv = apr_dbd_num_tuples(driver, res);
    if (rv == -1) {
        return rv;
    } else if (rv == 1) {           /* 有且仅有一个关键字 */
        return sub_with_new_del(k->sec_policy, KEYWORD_FILTER, ptemp);
    } else {                        /* 仅需删除关键字 */
        state = apr_psprintf(ptemp, "DELETE FROM %s where value = '%s'", KEYWORD_TAB, keyword);
        rv = apr_dbd_query(driver, tmp_db, &nrow, state);
        if (rv > 0) {
            return CONV_FAIL;
        } else {
            return CONV_OK;
        }
    }
}

/**
 * utf-8 to gb18030
 * utf-8 can be simple or traditional
 */
static int su2sg(const char *inbuf, char *outbuf, apr_pool_t *p)
{
    return conv_char("GB18030", "UTF-8", p, inbuf, outbuf);
}

/**
 * utf-8 to traditional big5
 * utf-8 can be simple or traditional
 */
static int su2tb(const char *inbuf, char *outbuf, apr_pool_t *p)
{
    int rv, inlen, outlen;
    char *buf_sg;

    inlen = strlen(inbuf);
    outlen = (inlen + 1) * 4;
    buf_sg = apr_palloc(p, outlen);
    memset(buf_sg, 0, outlen);
    rv = conv_char("GB2312", "UTF-8", p, inbuf, buf_sg);
    if (rv != APR_SUCCESS) {        /* couldn't find this utf-8 word in gb2312 */
        return conv_char("BIG5", "UTF-8", p, inbuf, outbuf);
    }

    rv = conv_char("BIG5", "GB2312", p, buf_sg, outbuf);
    if (rv != APR_SUCCESS) {        /* could convert from gb2312 to big5 */
        return conv_char("BIG5", "UTF-8", p, inbuf, outbuf);
    }

    return CONV_OK;
}

/**
 * simple utf-8 to traditional utf-8
 */
static int su2tu(const char *inbuf, char *outbuf, apr_pool_t *p)
{
    int rv, inlen, outlen;
    char *buf_tb;

    inlen = strlen(inbuf);
    outlen = (inlen + 1) * 4;
    buf_tb = apr_palloc(p, outlen);
    memset(buf_tb, 0, outlen);
    rv = su2tb(inbuf, buf_tb, p);
    if (rv != APR_SUCCESS) {        /* could convert simple utf-8 to tradional big5 */
        return rv;
    }

    return conv_char("UTF-8", "BIG5", p, buf_tb, outbuf);
}

/**
 * simple utf-8 to traditional gb18030
 */
static int su2tg(const char *inbuf, char *outbuf, apr_pool_t *p)
{
    int rv, inlen, outlen;;
    char *buf_tu;

    inlen = strlen(inbuf);
    outlen = (inlen + 1) * 4;
    buf_tu = apr_palloc(p, outlen);
    memset(buf_tu, 0, outlen);
    rv = su2tu(inbuf, buf_tu, p);
    if (rv != APR_SUCCESS) {        /* could convert simple utf-8 to tradional utf-8 */
        return rv;
    }
    
    return conv_char("GB18030", "UTF-8", p, buf_tu, outbuf);
}

static int keyword_filter_subpolicy_query(const char *name, apr_dbd_row_t *row,
        apr_array_header_t **result, apr_pool_t *ptemp)
{
    int                 i, rv, inlen, outlen;
#if APU_HAVE_MYSQL
    int                 num;
#endif
    char                *rule, **new, *state, *keyword, *convbuf;
    const char          *sec_name, *rule_id, *entry;
    apr_pool_t          *tpool;
    apr_dbd_results_t   *filter_res = NULL;
    apr_dbd_row_t       *filter_row = NULL;

    sec_name = apr_dbd_escape(driver, ptemp, name, tmp_db);
    state = apr_psprintf(ptemp, "SELECT %s.new_id, %s.value FROM %s, %s where "\
                         "%s.keyword_id = %s.keyword_id and %s.keyword_id in (SELECT "\
                         "keyword_id from %s WHERE sec_policy = '%s' and sec_subpolicy = %d)",
                         NEW_TAB, KEYWORD_TAB, NEW_TAB, KEYWORD_TAB, NEW_TAB, KEYWORD_TAB,
                         KEYWORD_TAB, KEYWORD_ID_TAB, sec_name, KEYWORD_FILTER);
    rv = apr_dbd_select(driver, ptemp, tmp_db, &filter_res, state, 1);
    if (rv > 0) {
        return CONV_FAIL;
    }
    rv = apr_dbd_num_tuples(driver, filter_res);
    if (rv == -1) {
        return CONV_FAIL;
    } else if (rv == 0){
        return CONV_OK;
    }

    tpool = (*result)->pool;
    keyword = NULL;
    rule_id = NULL;
#if APU_HAVE_SQLITE3
    for (i = rv; i > 0; i--) {
        rv = apr_dbd_get_row(driver, ptemp, filter_res, &filter_row, -1);
#elif APU_HAVE_MYSQL
    num = rv;
    for (i = 1; i <= num; i++) {
        rv = apr_dbd_get_row(driver, ptemp, filter_res, &filter_row, i);
#endif
        if (rv == -1) {
            return CONV_FAIL;
        }

        if (rule_id == NULL) {
            rule_id = apr_dbd_get_entry(driver, filter_row, 0);
        }

        /* 生成关键字序列 */
        entry = apr_dbd_get_entry(driver, filter_row, 1);

        if (is_ascii((char *)entry) == CONV_OK) {
            rule = apr_psprintf(ptemp, filter_rule, entry, rule_id);
            new = (char **)apr_array_push(*result);
            *new = apr_pstrdup(tpool, rule);
        } else {
            /* simple utf-8 */
            rule = apr_psprintf(ptemp, filter_rule, escape_keyword(entry, ptemp), rule_id);
            new = (char **)apr_array_push(*result);
            *new = apr_pstrdup(tpool, rule);

            /* simple gb18030 */
            inlen = strlen(entry);
            outlen = (inlen + 1) * 4;
            convbuf = apr_palloc(ptemp, outlen);
            memset(convbuf, 0, outlen);
            rv = su2sg(entry, convbuf, ptemp);
            if (rv == CONV_OK) {
                rule = apr_psprintf(ptemp, filter_rule, escape_keyword(convbuf, ptemp), rule_id);
                new = (char **)apr_array_push(*result);
                *new = apr_pstrdup(tpool, rule);
            }

            /* traditional big5 */
            memset(convbuf, 0, outlen);
            rv = su2tb(entry, convbuf, ptemp);
            if (rv == CONV_OK) {
                rule = apr_psprintf(ptemp, filter_rule, escape_keyword(convbuf, ptemp), rule_id);
                new = (char **)apr_array_push(*result);
                *new = apr_pstrdup(tpool, rule);
            }

            /* traditional utf-8 */
            memset(convbuf, 0, outlen);
            rv = su2tu(entry, convbuf, ptemp);
            if (rv == CONV_OK) {
                rule = apr_psprintf(ptemp, filter_rule, escape_keyword(convbuf, ptemp), rule_id);
                new = (char **)apr_array_push(*result);
                *new = apr_pstrdup(tpool, rule);
            }

            /* traditional gb18030 */
            memset(convbuf, 0, outlen);
            rv = su2tg(entry, convbuf, ptemp);
            if (rv == CONV_OK) {
                rule = apr_psprintf(ptemp, filter_rule, escape_keyword(convbuf, ptemp), rule_id);
                new = (char **)apr_array_push(*result);
                *new = apr_pstrdup(tpool, rule);
            }
        }
    }
    return CONV_OK;
}

static int keyword_filter_subpolicy_del(const char *sec_policy, apr_pool_t *ptemp)
{
    return sub_with_new_del(sec_policy, KEYWORD_FILTER, ptemp);
}

static int keyword_filter_subpolicy_list(const char *sec_policy,
        apr_array_header_t **result, apr_pool_t *ptemp)
{
    return new_keyword_list(sec_policy, KEYWORD_FILTER, 0, keyword_filter, ZH_CN, result, ptemp);
}

/* 请求方法处理驱动结构 */
subpolicy_t keyword_filter_subpolicy = {
    KEYWORD_FILTER,
    keyword_filter_keyword_add,
    keyword_filter_keyword_del,
    keyword_filter_subpolicy_query,
    keyword_filter_subpolicy_del,
    keyword_filter_subpolicy_list
};
