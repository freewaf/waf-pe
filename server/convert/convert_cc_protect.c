/*
 * $Id: convert_cc_protect.c 2786 2013-07-09 16:42:55 FreeWAF Development Team $
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

/* slow dos */
#define SLOW_DOS_CYCLE    60
#define SLOW_DOS_TIMES    10

/* dos */
#define DOS_CYCLE    60
#define DOS_TIMES    1000


/* brute force */
#define BRUTE_FORCE_CYCLE       60
#define BRUTE_FORCE_TIMES       1000

/* referer dos */
#define REFERER_DOS_CYCLE   60
#define REFERER_DOS_TIMES   500

static char *cc_flag[] = {
    NULL,
    "dos",
    "referer-dos",
    "slow-dos",
    "specific-plain-pages",
    "specific-regex-pages",
    "brute-force",
};

static char *cc_rule[] = {
    NULL,
    "SecAction \"phase:5, id:'56006',t:none,nolog,pass,setvar:'tx.dos_burst_time_slice=%s',"\
    "setvar:'tx.dos_counter_threshold=%s'\"",
    "SecAction \"phase:5, id:'56012',t:none,nolog,pass,setvar:'tx.referer_burst_time_slice=%s',"\
    "setvar:'tx.referer_counter_threshold=%s'\"",
    "SecAction \"phase:5, id:'56002',t:none,nolog,pass,setvar:'tx.slow_dos_burst_time_slice=%s',"\
    "setvar:'tx.slow_dos_counter_threshold=%s'\"",
    NULL,
    NULL,
    "SecAction \"phase:5, id:'56007',t:none,nolog,pass,setvar:'tx.brute_burst_time_slice=%s',"\
    "setvar:'tx.brute_counter_threshold=%s'\"",
};

static int check_keyword(keyword_t *k, apr_pool_t *ptemp, const char **keyword_id)
{
    int                 rv;
    char                *state, *kw;
    const char          *sec_name, *keyword, *entry;
    apr_dbd_results_t   *res = NULL;
    apr_dbd_row_t       *row = NULL;

    sec_name = apr_dbd_escape(driver, ptemp, k->sec_policy, tmp_db);
    state = apr_psprintf(ptemp, "select keyword_id from %s where sec_policy = '%s' and"\
                         " sec_subpolicy = %d and type = %d", KEYWORD_ID_TAB, sec_name,
                         CC_PROTECT, k->type);
    rv = apr_dbd_select(driver, ptemp, tmp_db, &res, state, 1);
    if (rv > 0) {
        return CONV_FAIL;
    }
    rv = apr_dbd_num_tuples(driver, res);
    entry = NULL;
    if (rv == -1) {
        return CONV_FAIL;
    } else if (rv == 0) {
        return CONV_OK;
    } else if (rv > 0) {        /* 已经存在相同的关键字ID */
#if APU_HAVE_SQLITE3
        rv = apr_dbd_get_row(driver, ptemp, res, &row, -1);
#elif APU_HAVE_MYSQL
        rv = apr_dbd_get_row(driver, ptemp, res, &row, 1);
#endif
        if (rv == -1) {
            return CONV_FAIL;
        }

        entry = apr_dbd_get_entry(driver, row, 0);
        *keyword_id = entry;
        if (k->type != CC_PLAIN_URL && k->type != CC_REGEX_URL) {
            return CONV_EXIST;
        }
    }

    kw = ((char **)k->keyword->elts)[0];
    keyword = apr_dbd_escape(driver, ptemp, kw, tmp_db);
    state = apr_psprintf(ptemp, "select * from %s where keyword_id = '%s' and value = '%s'",
                         KEYWORD_TAB, entry, keyword);
    rv = apr_dbd_select(driver, ptemp, tmp_db, &res, state, 1);
    if (rv > 0) {
        return CONV_FAIL;
    }
    rv = apr_dbd_num_tuples(driver, res);
    if (rv == -1) {
        return CONV_FAIL;
    } else if (rv > 0) {        /* 已经存在相同的关键字 */
        return CONV_CONFLICT;
    } else {                    /* 该url不存在，但存在此类型 */
        return CONV_EXIST;
    }
}

static int add_url(keyword_t *k, const char *keyword_id, apr_pool_t *ptemp)
{
    int                 rv, nrow;
    char                *state, **kw;
    const char          *keyword;

    kw = apr_array_pop(k->keyword);
    keyword = apr_dbd_escape(driver, ptemp, *kw, tmp_db);
    state = apr_psprintf(ptemp, "INSERT INTO %s VALUES (%s, %d, '%s')",
                         KEYWORD_TAB, keyword_id, KEYWORD_FIRST, keyword);
    rv = apr_dbd_query(driver, tmp_db, &nrow, state);
    if (rv > 0) {
        return CONV_FAIL;
    }

    return CONV_OK;
}

static int modified_keyword(keyword_t *k, const char *keyword_id, apr_pool_t *ptemp)
{
    int                     rv, nrow;
    char                    *state, *cycle, *times;
    apr_dbd_transaction_t   *trans = NULL;

    /* 关键字数目不是两个则出错 */
    rv = k->keyword->nelts;
    if (rv != 2) {
        return CONV_FAIL;
    }

    /* 取出关键字 */
    cycle = ((char **)k->keyword->elts)[0];
    times = ((char **)k->keyword->elts)[1];

    rv = apr_dbd_transaction_start(driver, ptemp, tmp_db, &trans);
    if (rv > 0) {
        return CONV_FAIL;
    }

    state = apr_psprintf(ptemp, "UPDATE %s SET value = '%s' WHERE number = %d AND"\
                         " keyword_id = %s", KEYWORD_TAB, cycle, KEYWORD_FIRST, keyword_id);
    rv = apr_dbd_query(driver, tmp_db, &nrow, state);
    if (rv > 0) {
        apr_dbd_transaction_end(driver, ptemp, trans);
        return CONV_FAIL;
    }

    state = apr_psprintf(ptemp, "UPDATE %s SET value = '%s' WHERE number = %d AND"\
                         " keyword_id = %s", KEYWORD_TAB, times, KEYWORD_SECOND, keyword_id);
    rv = apr_dbd_query(driver, tmp_db, &nrow, state);
    if (rv > 0) {
        apr_dbd_transaction_end(driver, ptemp, trans);
        return CONV_FAIL;
    }

    rv = apr_dbd_transaction_end(driver, ptemp, trans);
    if (rv > 0) {
        return CONV_FAIL;
    }
    return CONV_OK;
}

static int add_keyword(keyword_t *k, apr_pool_t *ptemp)
{
    int                     rv, nrow;
    char                    *state, *cycle, *times, **kw;
    const char              *keyword, *sec_name;
    apr_dbd_transaction_t   *trans = NULL;

    kw_id_flag++;

    /* 插入对应关键字 */
    rv = apr_dbd_transaction_start(driver, ptemp, tmp_db, &trans);
    if (rv > 0) {
        kw_id_flag--;
        return CONV_FAIL;
    }

    sec_name = apr_dbd_escape(driver, ptemp, k->sec_policy, tmp_db);
    state = apr_psprintf(ptemp, "INSERT INTO %s VALUES (%ld, '%s', %d, %d)",
                         KEYWORD_ID_TAB, kw_id_flag, sec_name, k->sec_subpolicy, k->type);
    rv = apr_dbd_query(driver, tmp_db, &nrow, state);
    if (rv > 0) {
        kw_id_flag--;
        apr_dbd_transaction_end(driver, ptemp, trans);
        return CONV_FAIL;
    }

    if (k->type != CC_PLAIN_URL && k->type != CC_REGEX_URL) {
        /* 取出关键字 */
        cycle = ((char **)k->keyword->elts)[0];
        times = ((char **)k->keyword->elts)[1];
        state = apr_psprintf(ptemp, "INSERT INTO %s VALUES (%ld, %d, '%s')",
                             KEYWORD_TAB, kw_id_flag, KEYWORD_FIRST, cycle);
        rv = apr_dbd_query(driver, tmp_db, &nrow, state);
        if (rv > 0) {
            kw_id_flag--;
            apr_dbd_transaction_end(driver, ptemp, trans);
            return CONV_FAIL;
        }

        state = apr_psprintf(ptemp, "INSERT INTO %s VALUES (%ld, %d, '%s')",
                             KEYWORD_TAB, kw_id_flag, KEYWORD_SECOND, times);
        rv = apr_dbd_query(driver, tmp_db, &nrow, state);
        if (rv > 0) {
            kw_id_flag--;
            apr_dbd_transaction_end(driver, ptemp, trans);
            return CONV_FAIL;
        }
    } else {                                                /* 添加url关键字 */
        kw = apr_array_pop(k->keyword);
        keyword = apr_dbd_escape(driver, ptemp, *kw, tmp_db);
        state = apr_psprintf(ptemp, "INSERT INTO %s VALUES (%ld, %d, '%s')",
                             KEYWORD_TAB, kw_id_flag, KEYWORD_FIRST, keyword);
        rv = apr_dbd_query(driver, tmp_db, &nrow, state);
        if (rv > 0) {
            kw_id_flag--;
            apr_dbd_transaction_end(driver, ptemp, trans);
            return CONV_FAIL;
        }
    }

    rv = apr_dbd_transaction_end(driver, ptemp, trans);
    if (rv > 0) {
        kw_id_flag--;
        return CONV_FAIL;
    }

    return CONV_OK;
}

static int cc_protect_keyword_add(keyword_t *k, apr_pool_t *ptemp)
{
    int         rv;
    const char  *keyword_id;

    if ((k == NULL) || (ptemp == NULL)) {
        return CONV_FAIL;
    }

    /* 检查关键字是否存在 */
    keyword_id = NULL;
    rv = check_keyword(k, ptemp, &keyword_id);
    if (rv == CONV_FAIL || rv == CONV_CONFLICT) {
        return rv;
    } else if (rv == CONV_OK) {
        return add_keyword(k, ptemp);
    }

    if (k->type != CC_PLAIN_URL && k->type != CC_REGEX_URL) {
        return modified_keyword(k, keyword_id, ptemp);
    } else {
        return add_url(k, keyword_id, ptemp);
    }
}

/* 根据CREF的描述，只能删除url */
static int cc_protect_keyword_del(keyword_t *k, apr_pool_t *ptemp)
{
    int                 rv, nrow;
    char                *state, **kw;
    const char          *keyword, *keyword_id, *sec_name;
    apr_dbd_results_t   *res = NULL;

    if (k->type != CC_PLAIN_URL && k->type != CC_REGEX_URL && k->type != CC_KEYWORD_ALL) {
        return modified_keyword_del(k, ptemp);
    }

    /* 删除url */
    if (k->flag != FLAG_ALL && k->type != CC_KEYWORD_ALL) { /* 删除指定url */
        rv = check_keyword(k, ptemp, &keyword_id);
        if (rv == CONV_FAIL) {                              /* 查询失败 */
            return rv;
        } else if (rv == CONV_OK || rv == CONV_EXIST) {     /* 关键字不存在 */
            return CONV_NOTEXIST;
        }

        kw = apr_array_pop(k->keyword);
        keyword = apr_dbd_escape(driver, ptemp, *kw, tmp_db);
        state = apr_psprintf(ptemp, "DELETE FROM %s where keyword_id = %s and value = '%s'",
                             KEYWORD_TAB, keyword_id, keyword);
        rv = apr_dbd_query(driver, tmp_db, &nrow, state);
        if (rv > 0) {
            return CONV_FAIL;
        }

        state = apr_psprintf(ptemp, "SELECT * from %s where keyword_id = %s",
                             KEYWORD_TAB, keyword_id);
        rv = apr_dbd_select(driver, ptemp, tmp_db, &res, state, 1);
        if (rv > 0) {
            return CONV_FAIL;
        }
        rv = apr_dbd_num_tuples(driver, res);
        if (rv == -1) {
            return CONV_FAIL;
        } else if (rv > 0) {
            return CONV_OK;
        }

        state = apr_psprintf(ptemp, "DELETE FROM %s where keyword_id = %s",
                             KEYWORD_ID_TAB, keyword_id);
        rv = apr_dbd_query(driver, tmp_db, &nrow, state);
        if (rv > 0) {
            return CONV_FAIL;
        }
    } else {                                        /* 删除所有url */
        sec_name = apr_dbd_escape(driver, ptemp, k->sec_policy, tmp_db);
        state = apr_psprintf(ptemp, "delete from %s where keyword_id in (select keyword_id"\
                             " from %s where sec_policy = '%s' and sec_subpolicy = %d and"\
                             " (type = %d or type = %d))",  KEYWORD_TAB, KEYWORD_ID_TAB,
                             sec_name, CC_PROTECT, CC_PLAIN_URL, CC_REGEX_URL);
        rv = apr_dbd_query(driver, tmp_db, &nrow, state);
        if (rv > 0) {
            return CONV_FAIL;
        }

        state = apr_psprintf(ptemp, "delete from %s where sec_policy = '%s' and sec_subpolicy"\
                             " = %d and (type = %d or type = %d)",  KEYWORD_ID_TAB,
                             sec_name, CC_PROTECT, CC_PLAIN_URL, CC_REGEX_URL);
        rv = apr_dbd_query(driver, tmp_db, &nrow, state);
        if (rv > 0) {
            return CONV_FAIL;
        }
    }

    return CONV_OK;
}

static int generate_rate_rule(const char *name, int type, apr_array_header_t **result,
                              apr_pool_t *ptemp)
{
    int                 rv;
    char                **new, *state, *cycle, *times, *rule;
    const char          *entry, *sec_name, *kw_id;
    apr_pool_t          *tpool;
    apr_dbd_results_t   *res = NULL;
    apr_dbd_row_t       *row = NULL;

    sec_name = apr_dbd_escape(driver, ptemp, name, tmp_db);
    state = apr_psprintf(ptemp, "select keyword_id from %s where sec_policy = '%s' and"\
                         " sec_subpolicy = %d and type = %d", KEYWORD_ID_TAB, sec_name,
                         CC_PROTECT, type);
    rv = apr_dbd_select(driver, ptemp, tmp_db, &res, state, 1);
    if (rv > 0) {
        return CONV_FAIL;
    }

    rv = apr_dbd_num_tuples(driver, res);
    cycle = NULL;
    times = NULL;
    if (rv == -1) {
        return CONV_FAIL;
    } else if (rv == 0) {       /* 取默认值 */
        switch (type) {
            case SOURCE_IP:
                cycle = apr_psprintf(ptemp, "%d", DOS_CYCLE);
                times = apr_psprintf(ptemp, "%d", DOS_TIMES);
                break;
            case STATUS_408_RATE:
                cycle = apr_psprintf(ptemp, "%d", SLOW_DOS_CYCLE);
                times = apr_psprintf(ptemp, "%d", SLOW_DOS_TIMES);
                break;
            case REFERRER_URL:
                cycle = apr_psprintf(ptemp, "%d", REFERER_DOS_CYCLE);
                times = apr_psprintf(ptemp, "%d", REFERER_DOS_TIMES);
                break;
            case URL_ACCESS_RATE:
                cycle = apr_psprintf(ptemp, "%d", BRUTE_FORCE_CYCLE);
                times = apr_psprintf(ptemp, "%d", BRUTE_FORCE_TIMES);
                break;
            default:
                return CONV_FAIL;
        }
    } else if (rv > 0) {        /* 取设定值 */
#if APU_HAVE_SQLITE3
        rv = apr_dbd_get_row(driver, ptemp, res, &row, -1);
#elif APU_HAVE_MYSQL
        rv = apr_dbd_get_row(driver, ptemp, res, &row, 1);
#endif
        if (rv == -1) {
            return CONV_FAIL;
        }

        kw_id = apr_dbd_get_entry(driver, row, 0);
        state = apr_psprintf(ptemp, "select value from keyword where keyword_id = %s order"\
                             " by number desc", kw_id);
        rv = apr_dbd_select(driver, ptemp, tmp_db, &res, state, 1);
        if (rv > 0) {
            return CONV_FAIL;
        }
        rv = apr_dbd_num_tuples(driver, res);
        if (rv != 2) {              /* 关键字必须两个都出现 */
            return CONV_FAIL;
        }

#if APU_HAVE_SQLITE3
        rv = apr_dbd_get_row(driver, ptemp, res, &row, -1);
#elif APU_HAVE_MYSQL
        rv = apr_dbd_get_row(driver, ptemp, res, &row, 1);
#endif
        if (rv == -1) {
            return CONV_FAIL;
        }

        entry = apr_dbd_get_entry(driver, row, 0);
        cycle = apr_psprintf(ptemp, "%s", entry);

#if APU_HAVE_SQLITE3
        rv = apr_dbd_get_row(driver, ptemp, res, &row, -1);
#elif APU_HAVE_MYSQL
        rv = apr_dbd_get_row(driver, ptemp, res, &row, 2);
#endif
        if (rv == -1) {
            return CONV_FAIL;
        }

        entry = apr_dbd_get_entry(driver, row, 0);
        times = apr_psprintf(ptemp, "%s", entry);
    }

    /* 生成规则 */
    tpool = (*result)->pool;
    rule = apr_psprintf(ptemp, cc_rule[type], times, cycle);
    new = (char **)apr_array_push(*result);
    *new = apr_pstrdup(tpool, rule);
    return CONV_OK;
}

static int generate_url_rule(const char *name, int type, apr_dbd_row_t *row,
                             apr_array_header_t **result, apr_pool_t *ptemp)
{
    int                 rv, i;
#if APU_HAVE_MYSQL
    int                 num;
#endif
    char                *state;
    const char          *entry, *sec_name, *kw_id, *keyword;
    apr_dbd_results_t   *sub_res = NULL;
    apr_dbd_row_t       *sub_row = NULL;

    sec_name = apr_dbd_escape(driver, ptemp, name, tmp_db);
    /* 查询是否存在自定义URL */
    state = apr_psprintf(ptemp, "select keyword_id from %s where sec_policy = '%s' and"\
                         " sec_subpolicy = %d and type = %d", KEYWORD_ID_TAB, sec_name,
                         CC_PROTECT, type);
    rv = apr_dbd_select(driver, ptemp, tmp_db, &sub_res, state, 1);
    if (rv > 0) {
        return CONV_FAIL;
    }

    rv = apr_dbd_num_tuples(driver, sub_res);
    if (rv == -1) {
        return CONV_FAIL;
    } else if (rv == 0) {
        return CONV_OK;
    }

    /* 生成规则 */
#if APU_HAVE_SQLITE3
    rv = apr_dbd_get_row(driver, ptemp, sub_res, &sub_row, -1);
#elif APU_HAVE_MYSQL
    rv = apr_dbd_get_row(driver, ptemp, sub_res, &sub_row, 1);
#endif
    if (rv == -1) {
        return CONV_FAIL;
    }

    kw_id = apr_dbd_get_entry(driver, sub_row, 0);
    state = apr_psprintf(ptemp, "select value from keyword where keyword_id = %s order"\
                         " by number", kw_id);
    rv = apr_dbd_select(driver, ptemp, tmp_db, &sub_res, state, 1);
    if (rv > 0) {
        return CONV_FAIL;
    }
    rv = apr_dbd_num_tuples(driver, sub_res);
    if (rv == 0) {
        return CONV_OK;
    }

#if APU_HAVE_SQLITE3
    for (i = rv; i > 0; i--) {
        rv = apr_dbd_get_row(driver, ptemp, sub_res, &sub_row, -1);
#elif APU_HAVE_MYSQL
    num = rv;
    for (i = 1; i <= num; i++) {
        rv = apr_dbd_get_row(driver, ptemp, sub_res, &sub_row, i);
#endif
        if (rv == -1) {
            return CONV_FAIL;
        }

        entry = apr_dbd_get_entry(driver, sub_row, 0);
        keyword = escape_keyword(entry, ptemp);
        combined_rule(row, keyword, NULL, result, ptemp);
    }

    return CONV_OK;
}

static int cc_protect_subpolicy_query(const char *name, apr_dbd_row_t *row,
        apr_array_header_t **result, apr_pool_t *ptemp)
{
    int                 i;
    const char          *entry;
    apr_pool_t          *tpool;

    if ((name == NULL) || (row == NULL) || (result == NULL)
            || (*result == NULL) || (ptemp == NULL)) {
        return CONV_FAIL;
    }

    entry = apr_dbd_get_entry(driver, row, B_FLAG);
    for (i = SOURCE_IP; i < CC_KEYWORD_ALL; i++ ) {
        if (!strcmp(cc_flag[i], entry)) {
            break;
        }
    }

    if (i == CC_KEYWORD_ALL) {
        return CONV_FAIL;
    }

    tpool = (*result)->pool;
    if (i != CC_PLAIN_URL && i != CC_REGEX_URL) {
        return generate_rate_rule(name, i, result, ptemp);
    } else {
        return generate_url_rule(name, i, row, result, ptemp);
    }
}

static int cc_protect_subpolicy_del(const char *sec_policy, apr_pool_t *ptemp)
{
    return sub_without_new_del(sec_policy, CC_PROTECT, ptemp);
}

static int list_url(int type, const char *kw_id, apr_array_header_t **result, apr_pool_t *ptemp)
{
    int                 rv, i;
#if APU_HAVE_MYSQL
    int                 num;
#endif
    char                **new, *state;
    const char          *entry;
    apr_dbd_results_t   *res = NULL;
    apr_dbd_row_t       *row = NULL;
    apr_pool_t          *ptab;
    keyword_t           *keyword, **new_keyword;

    if (kw_id == NULL) {
        return CONV_OK;
    }

    state = apr_psprintf(ptemp, "select value from keyword where keyword_id = %s", kw_id);
    rv = apr_dbd_select(driver, ptemp, tmp_db, &res, state, 1);
    if (rv > 0) {
        return CONV_FAIL;
    }

    rv = apr_dbd_num_tuples(driver, res);
    if (rv < 0) {
        return CONV_FAIL;
    } else if (rv == 0) {
        return CONV_OK;
    }

    ptab = (*result)->pool;
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
        keyword = apr_pcalloc(ptab, sizeof(keyword_t));
        keyword->type = type;
        keyword->flag = OUTER_KEYWORD;

        keyword->keyword = apr_array_make(ptab, 1, sizeof(char *));
        new = (char **)apr_array_push(keyword->keyword);
        *new = apr_pstrdup(ptab, entry);
        new_keyword = (keyword_t **)apr_array_push(* result);
        *new_keyword = keyword;
    }

    return CONV_OK;
}

static int list_rate(int type, const char *kw_id, apr_array_header_t **result, apr_pool_t *ptemp)
{
    int                 rv, flag;
    char                **new, *state, *cycle, *times;
    const char          *entry;
    apr_dbd_results_t   *res = NULL;
    apr_dbd_row_t       *row = NULL;
    apr_pool_t          *ptab;
    keyword_t           *keyword, **new_keyword;

    if (kw_id == NULL) {        /* 使用默认值 */
        flag = INNER_KEYWORD;
        switch (type) {
        case SOURCE_IP:
            cycle = apr_psprintf(ptemp, "%d", DOS_CYCLE);
            times = apr_psprintf(ptemp, "%d", DOS_TIMES);
            break;
        case STATUS_408_RATE:
            cycle = apr_psprintf(ptemp, "%d", SLOW_DOS_CYCLE);
            times = apr_psprintf(ptemp, "%d", SLOW_DOS_TIMES);
            break;
        case REFERRER_URL:
            cycle = apr_psprintf(ptemp, "%d", REFERER_DOS_CYCLE);
            times = apr_psprintf(ptemp, "%d", REFERER_DOS_TIMES);
            break;
        case URL_ACCESS_RATE:
            cycle = apr_psprintf(ptemp, "%d", BRUTE_FORCE_CYCLE);
            times = apr_psprintf(ptemp, "%d", BRUTE_FORCE_TIMES);
            break;
        default:
            return CONV_FAIL;
        }
    } else {
        flag = OUTER_KEYWORD;
        state = apr_psprintf(ptemp, "select value from keyword where keyword_id = %s order"\
                             " by number", kw_id);
        rv = apr_dbd_select(driver, ptemp, tmp_db, &res, state, 1);
        if (rv > 0) {
            return CONV_FAIL;
        }
        rv = apr_dbd_num_tuples(driver, res);
        if (rv != 2) {              /* 关键字必须两个都出现 */
            return CONV_FAIL;
        }

#if APU_HAVE_SQLITE3
        rv = apr_dbd_get_row(driver, ptemp, res, &row, -1);
#elif APU_HAVE_MYSQL
        rv = apr_dbd_get_row(driver, ptemp, res, &row, 1);
#endif
        if (rv == -1) {
            return CONV_FAIL;
        }

        entry = apr_dbd_get_entry(driver, row, 0);
        cycle = apr_psprintf(ptemp, "%s", entry);

#if APU_HAVE_SQLITE3
        rv = apr_dbd_get_row(driver, ptemp, res, &row, -1);
#elif APU_HAVE_MYSQL
        rv = apr_dbd_get_row(driver, ptemp, res, &row, 2);
#endif
        if (rv == -1) {
            return CONV_FAIL;
        }

        entry = apr_dbd_get_entry(driver, row, 0);
        times = apr_psprintf(ptemp, "%s", entry);
    }

    ptab = (*result)->pool;
    keyword = apr_pcalloc(ptab, sizeof(keyword_t));

    keyword->keyword = apr_array_make(ptab, 1, sizeof(char *));
    keyword->flag = flag;
    keyword->type = type;

    new = (char **)apr_array_push(keyword->keyword);
    *new = apr_pstrdup(ptab, cycle);

    new = (char **)apr_array_push(keyword->keyword);
    *new = apr_pstrdup(ptab, times);

    new_keyword = (keyword_t **)apr_array_push(* result);
    *new_keyword = keyword;

    return CONV_OK;
}

static int cc_protect_subpolicy_list(const char *sec_policy,
                                        apr_array_header_t **result, apr_pool_t *ptemp)
{
    int                 rv, i;
    char                *state;
    const char          *sec_name, *kw_id;
    apr_dbd_results_t   *res = NULL;
    apr_dbd_row_t       *row = NULL;

    for (i = SOURCE_IP; i <= URL_ACCESS_RATE; i++) {
        sec_name = apr_dbd_escape(driver, ptemp, sec_policy, tmp_db);
        state = apr_psprintf(ptemp, "select keyword_id from %s where sec_policy = '%s' and"\
                             " sec_subpolicy = %d and type = %d", KEYWORD_ID_TAB, sec_name,
                             CC_PROTECT, i);
        rv = apr_dbd_select(driver, ptemp, tmp_db, &res, state, 1);
        if (rv > 0) {
            return CONV_FAIL;
        }

        rv = apr_dbd_num_tuples(driver, res);
        if (rv == -1) {
            return CONV_FAIL;
        } else {
            if (rv > 0) {
#if APU_HAVE_SQLITE3
                rv = apr_dbd_get_row(driver, ptemp, res, &row, -1);
#elif APU_HAVE_MYSQL
                rv = apr_dbd_get_row(driver, ptemp, res, &row, 1);
#endif
                if (rv == -1) {
                    return CONV_FAIL;
                }

                kw_id = apr_dbd_get_entry(driver, row, 0);
            } else {
                kw_id = NULL;
            }

            if (i != CC_PLAIN_URL && i != CC_REGEX_URL) {   /* 非URL */
                rv = list_rate(i, kw_id, result, ptemp);
                if (rv != CONV_OK) {
                    return rv;
                }
            } else {
                rv = list_url(i, kw_id, result, ptemp);
                if (rv != CONV_OK) {
                    return rv;
                }
            }
        }
    }

    return CONV_OK;
}

/* 请求方法处理驱动结构 */
subpolicy_t cc_protect_subpolicy = {
    CC_PROTECT,
    cc_protect_keyword_add,
    cc_protect_keyword_del,
    cc_protect_subpolicy_query,
    cc_protect_subpolicy_del,
    cc_protect_subpolicy_list
};
