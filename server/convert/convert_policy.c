/*
 * $Id: convert_policy.c 2786 2013-07-09 16:42:55 FreeWAF Development Team $
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

/* 安全策略类型，用于控制安全策略的加载顺序 */
char *policy_type[] = {
    "2600-sql-injection-attack",
    "2200-ldap-injection-attack",
    "2300-email-injection-attack",
    "2400-command-injection-attack",
    "2500-code-injection-attack",
    "1500-null-byte-injection",
    "2700-xss-attack",
    "3100-csrf-attack",
    "1600-overflow-attack",
    "1900-file-include-attack",
    "2000-misc-attack",
    "2900-path-traversal-attack",
    "3200-directory-index",
    "1800-spider-scanner-attack",
    "3000-trojan",
    "3400-xml-attack",
    "1700-weak-password",
    "3300-server-version",
    "3301-http-status-code",
    "3302-creditcard-information",
    "3303-server-error-information",
    "3304-program-code",
    "3305-magcard-information",
    "3306-idcard-information",
    "1300-file-download",
    "1200-file-upload",
    "2100-Cookie",
    "1100-protocal-parameter",
    "1000-request-method",
    "1400-keyword-filter",
    "2800-cc",
    "0000-main",
    NULL
};

static int generate_main_config(apr_array_header_t **result, apr_pool_t *ptemp)
{
    int                 rv, i;
#if APU_HAVE_MYSQL
    int                 rule_num;
#endif
    char                *type, *state;
    apr_dbd_results_t   *res = NULL;
    apr_dbd_row_t       *row = NULL;

    type = apr_psprintf(ptemp, "%s", policy_type[MAIN_CONFIG]);

    state = apr_psprintf(ptemp, "select * from %s left join %s on %s.list_id = "\
                         "%s.list_id where type = '%s'",
                         BASIC_TAB, EXTEND_TAB, BASIC_TAB, EXTEND_TAB, type);
    rv = apr_dbd_select(driver, ptemp, default_db, &res, state, 1);
    if (rv) {
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, NULL, "WAF_CONVERT: default policy is destroyed");
        return CONV_FAIL;
    }

    rv = apr_dbd_num_tuples(driver, res);
    if (rv == -1) {
        return CONV_FAIL;
    }


#if APU_HAVE_SQLITE3
    for (i = rv; i > 0; i--) {
        rv = apr_dbd_get_row(driver, ptemp, res, &row, -1);
#elif APU_HAVE_MYSQL
    rule_num = rv;
    for (i = 1; i <= rule_num; i++) {
        rv = apr_dbd_get_row(driver, ptemp, res, &row, i);
#endif
        if (rv) {
            return CONV_FAIL;
        }
        combined_rule(row, NULL, NULL, result, ptemp);
    }
    return CONV_OK;
}

static void generate_default_rule(apr_dbd_row_t *row,
                                  apr_array_header_t **result, apr_pool_t *ptemp)
{
    int                 status;
    char                **new, *def_act;
    const char          *entry;
    apr_pool_t          *tpool;

    tpool = (* result)->pool;

    def_act = apr_psprintf(ptemp, "%s", "SecDefaultAction \"phase:2, ");

    entry = apr_dbd_get_entry(driver, row, 3);
    status = atoi(entry);
    switch (status) {
        case ACTION_DROP:
            def_act = apr_pstrcat(ptemp, def_act, "drop, ", NULL);
            break;
        case ACTION_DENY:
            def_act = apr_pstrcat(ptemp, def_act, "deny, ", NULL);
            break;
        case ACTION_PASS:
        default:
            def_act = apr_pstrcat(ptemp, def_act, "pass, ", NULL);
            break;
    }

    /* 确定缺省是否需要记录日志 */
    entry = apr_dbd_get_entry(driver, row, 4);
    status = atoi(entry);
    if (status) {
        def_act = apr_pstrcat(ptemp, def_act, "nolog,auditlog\"", NULL);
    } else {
        def_act = apr_pstrcat(ptemp, def_act, "nolog,noauditlog\"", NULL);
    }

    new = (char **)apr_array_push(*result);
    *new = apr_pstrdup(tpool, def_act);
}

static int generate_sub_rule(const char *name, int type,
                             apr_array_header_t **result, apr_pool_t *ptemp)
{
    int                 rv, i;
#if APU_HAVE_MYSQL
    int                 num;
#endif
    const char          *entry, *ptype;
    char                *state;
    apr_dbd_results_t   *res = NULL;
    apr_dbd_row_t       *row = NULL;

    /* csrf需要单独处理 */
    if (type == CSRF) {
        return conv_subpolicy_list[type]->subpolicy_query(name, NULL, result, ptemp);
    }

    entry = apr_psprintf(ptemp, "%s", policy_type[type]);

    ptype = apr_dbd_escape(driver, ptemp, entry, tmp_db);
    state = apr_psprintf(ptemp, "select * from %s left join %s on %s.list_id = "\
                         "%s.list_id where type = '%s'",
                         BASIC_TAB, EXTEND_TAB, BASIC_TAB, EXTEND_TAB, ptype);
    rv = apr_dbd_select(driver, ptemp, default_db, &res, state, 1);
    if (rv > 0) {
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, NULL, "WAF_CONVERT: default policy is destroyed");
        return CONV_FAIL;
    }

    rv = apr_dbd_num_tuples(driver, res);
    if (rv == -1) {
        return CONV_FAIL;
    } else if (rv == 0) {       /* 无内置安全策略库 */
        if (conv_subpolicy_list[type] && conv_subpolicy_list[type]->subpolicy_query) {
            rv = conv_subpolicy_list[type]->subpolicy_query(name, NULL, result, ptemp);
            if (rv) {
                return rv;
            }
        } else {
            return CONV_NOTEXIST;
        }
    }

#if APU_HAVE_SQLITE3
    for (i = rv; i > 0; i--) {
        rv = apr_dbd_get_row(driver, ptemp, res, &row, -1);
#elif APU_HAVE_MYSQL
    num = rv;
    for (i = 1; i <= num; i++) {
        rv = apr_dbd_get_row(driver, ptemp, res, &row, i);
#endif
        if (rv) {
            return CONV_FAIL;
        }

        entry = apr_dbd_get_entry(driver, row, B_FLAG);
        /* 规则中没有设置flag位 */
        if (!entry) {
            combined_rule(row, NULL, NULL, result, ptemp);
            continue;
        }

        /* 规则中有设置flag位 */
        if (conv_subpolicy_list[type] && conv_subpolicy_list[type]->subpolicy_query) {
            rv = conv_subpolicy_list[type]->subpolicy_query(name, row, result, ptemp);
            if (rv) {
                return CONV_FAIL;
            }
        }
    }
    return CONV_OK;
}

/* 添加安全子策略关键字 */
int convert_keyword_add(keyword_t *k)
{
    int rv, id;
    apr_pool_t *ptemp;

    if (k == NULL) {
        return CONV_FAIL;
    }

    rv = apr_pool_create(&ptemp, ptrans);
    if (rv) {
        return CONV_FAIL;
    }

    id = k->sec_subpolicy;

    if (id < 0 || id >= MAX_SUBPOLICY) {
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, NULL,
                     "WAF_CONVERT: wrong sub policy id %d!", id);
        apr_pool_destroy(ptemp);
        return CONV_FAIL;
    }

    if (conv_subpolicy_list[id] && conv_subpolicy_list[id]->keyword_add) {
        if (id != conv_subpolicy_list[id]->type) {
            ap_log_error(APLOG_MARK, APLOG_ERR, 0, NULL,
                         "WAF_CONVERT: sub-policy is conflict!");
            apr_pool_destroy(ptemp);
            return CONV_FAIL;
        }
        rv = conv_subpolicy_list[id]->keyword_add(k, ptemp);
        if (rv) {
            ap_log_error(APLOG_MARK, APLOG_ERR, 0, NULL,
                         "WAF_CONVERT: failure to add keyword!");
        }
        apr_pool_destroy(ptemp);
        return rv;
    }

    return CONV_OK;
}

/* 删除安全子策略关键字 */
int convert_keyword_del(keyword_t *k)
{
    int rv, id;
    apr_pool_t *ptemp;

    if (k == NULL) {
        return CONV_FAIL;
    }

    rv = apr_pool_create(&ptemp, ptrans);
    if (rv > 0) {
        return CONV_FAIL;
    }

    id = k->sec_subpolicy;
    if (id < 0 || id >= MAX_SUBPOLICY) {
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, NULL,
                     "WAF_CONVERT: wrong sub policy id %d!", id);
        apr_pool_destroy(ptemp);
        return CONV_FAIL;
    }

    if (conv_subpolicy_list[id] && conv_subpolicy_list[id]->keyword_del) {
        rv = conv_subpolicy_list[id]->keyword_del(k, ptemp);
        if (rv) {
            ap_log_error(APLOG_MARK, APLOG_ERR, 0, NULL,
                         "WAF_CONVERT: failure to delete keyword!");
            apr_pool_destroy(ptemp);
            return  rv;
        }
    }

    apr_pool_destroy(ptemp);
    return CONV_OK;
}

/* 删除安全策略 */
int convert_sec_policy_del(const char *name)
{
    int                     rv, i, j, new, nrows;
#if APU_HAVE_MYSQL
    int                 num;
#endif
    apr_pool_t              *ptemp;
    char                    *state;
    const char              *subp, *sec_policy;
    apr_dbd_results_t       *res = NULL;
    apr_dbd_row_t           *row = NULL;

    if (name == NULL) {
        return CONV_FAIL;
    }

    rv = apr_pool_create(&ptemp, ptrans);
    if (rv) {
        return CONV_FAIL;
    }

    sec_policy = apr_dbd_escape(driver, ptemp, name, tmp_db);
    state = apr_psprintf(ptemp, "SELECT sub_policy FROM %s WHERE sec_policy = '%s'",
                         SEC_POLICY_TAB, sec_policy);
    rv = apr_dbd_select(driver, ptemp, tmp_db, &res, state, 1);
    if (rv > 0) {
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, NULL,
                     "WAF_CONVERT: failure to get information about %s!", name);
        apr_pool_destroy(ptemp);
        return CONV_FAIL;
    }

    rv = apr_dbd_num_tuples(driver, res);
    if (rv == -1) {
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, NULL,
                     "WAF_CONVERT: failure to get detail about %s!", name);
        apr_pool_destroy(ptemp);
        return CONV_FAIL;
    } else if (rv == 0) {           /* 不存在此安全策略集 */
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, NULL,
                     "WAF_CONVERT: security policy %s is not exist!", name);
        apr_pool_destroy(ptemp);
        return CONV_NOTEXIST;
    }

    /* 删除安全子策略下具体配置信息 */
#if APU_HAVE_SQLITE3
    for (i = rv; i > 0; i--) {
        rv = apr_dbd_get_row(driver, ptemp, res, &row, -1);
#elif APU_HAVE_MYSQL
    num = rv;
    for (i = 1; i <= num; i++) {
        rv = apr_dbd_get_row(driver, ptemp, res, &row, i);
#endif
        if (rv == -1) {
            ap_log_error(APLOG_MARK, APLOG_ERR, 0, NULL,
                         "WAF_CONVERT: failure to get %s!", name);
            apr_pool_destroy(ptemp);
            return CONV_FAIL;
        }

        subp = apr_dbd_get_entry(driver, row, 0);
        for (j = 0; j < MAX_SUBPOLICY; j++) {
            if (!strcmp(subp, policy_type[j])) {
                new = j;
                break;
            }
        }

        if (j == MAX_SUBPOLICY) {            /* 未找到对应的安全子策略 */
            ap_log_error(APLOG_MARK, APLOG_ERR, 0, NULL,
                         "WAF_CONVERT: failure to get sub policy %s!", subp);
            apr_pool_destroy(ptemp);
            return CONV_FAIL;
        }

        if (conv_subpolicy_list[new] && conv_subpolicy_list[new]->subpolicy_del){
            rv = conv_subpolicy_list[new]->subpolicy_del(name, ptemp);
            if (rv == CONV_FAIL) {
                ap_log_error(APLOG_MARK, APLOG_ERR, 0, NULL,
                             "WAF_CONVERT: failure to delete sub_policy %s!", policy_type[new]);
                apr_pool_destroy(ptemp);
                return CONV_FAIL;
            }
        }
    }

    /* 删除所有的安全子策略主配置 */
    state = apr_psprintf(ptemp, "DELETE FROM %s WHERE sec_policy = '%s'",
                         SEC_POLICY_TAB, sec_policy);
    rv = apr_dbd_query(driver, tmp_db, &nrows, state);

    printf("%s:%s(%d): %s\n",__FILE__, __FUNCTION__, __LINE__, apr_dbd_error(driver, default_db, rv));

    if (rv > 0) {
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, NULL,
                     "WAF_CONVERT: failure to delete policy %s!", name);
        apr_pool_destroy(ptemp);
        return CONV_FAIL;
    }

    apr_pool_destroy(ptemp);
    return CONV_OK;
}

/**
 * 设置安全子策略
 * 设置成功，返回OK。
 * 否则，返回DECLINED。
 */
int convert_sec_subpolicy_set(sec_subpolicy_t *s)
{
    int                 rv, nrow;
    char                *state;
    const char          *sec_name, *sub_name;
    apr_dbd_results_t   *res = NULL;
    apr_pool_t          *ptemp;

    if (s == NULL) {
        return CONV_FAIL;
    }

    rv = apr_pool_create(&ptemp, ptrans);
    if (rv) {
        return rv;
    }

    if ((s->sec_subpolicy < SQL_INJECTION) || (s->sec_subpolicy >= MAX_SUBPOLICY)) {
        apr_pool_destroy(ptemp);
        return CONV_FAIL;
    }

    sec_name = apr_dbd_escape(driver, ptemp, s->sec_policy, tmp_db);
    sub_name = apr_dbd_escape(driver, ptemp, policy_type[s->sec_subpolicy], tmp_db);
    state = apr_psprintf(ptemp, "SELECT * FROM %s WHERE "\
                         "sec_policy = '%s' AND sub_policy = '%s'",
                         SEC_POLICY_TAB, sec_name, sub_name);
    rv = apr_dbd_select(driver, s->pool, tmp_db, &res, state, 1);
    if (rv) {
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, NULL,
                     "WAF_CONVERT: failure to get info about this policy %s!", s->sec_policy);
        apr_pool_destroy(ptemp);
        return rv;
    }

    rv = apr_dbd_num_tuples(driver, res);
    if (rv == 1) {
        /* 存在安全策略和安全子策略的信息，则更新 */
        state = apr_psprintf(ptemp, "UPDATE %s SET action = %d, "\
                             "log = %d, status = %d where "\
                             "sec_policy = '%s' and sub_policy = '%s'",
                             SEC_POLICY_TAB, s->action, s->log, s->status,
                             sec_name, sub_name);
        rv = apr_dbd_query(driver, tmp_db, &nrow, state);
        if (rv) {
            ap_log_error(APLOG_MARK, APLOG_ERR, 0, NULL,
                         "WAF_CONVERT: failure to set policy %s!", s->sec_policy);
            apr_pool_destroy(ptemp);
            return rv;
        }
    } else if (rv == 0) {
        /* 不存在安全策略和安全子策略的信息，则插入 */
        state = apr_psprintf(ptemp, "INSERT INTO %s VALUES ( '%s', '%s', " \
                             "NULL, %d, %d, %d)", SEC_POLICY_TAB, sec_name, sub_name,
                             s->action, s->log, s->status);
        rv = apr_dbd_query(driver, tmp_db, &nrow, state);
        if (rv) {
            ap_log_error(APLOG_MARK, APLOG_ERR, 0, NULL,
                         "WAF_CONVERT: failure to add policy %s!", s->sec_policy);
            apr_pool_destroy(ptemp);
            return rv;
        }
    } else {
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, NULL,
                     "WAF_CONVERT: failure to set policy %s!", s->sec_policy);
        apr_pool_destroy(ptemp);
        return rv;
    }

    return CONV_OK;
}

/**
 * 查询安全策略
 * 返回安全策略所包含的所有规则，保存在result数组里面。
 * 查询成功，返回OK。
 * 否则，返回DECLINED。
 */
int convert_sec_policy_query(const char *name, apr_array_header_t **result)
{
    int                 rv;
#if APU_HAVE_MYSQL
    int                 num;
#endif
    int                 i, j;
    int                 npolicy;
    int                 status;
    int                 type;
    char                *state;
    apr_pool_t          *ptemp;
    apr_dbd_results_t   *res = NULL;
    apr_dbd_row_t       *row = NULL;
    const char          *entry;
    const char          *sec_policy;

    if ((name == NULL) || (result == NULL) || (*result == NULL)) {
        return CONV_FAIL;
    }

    rv = apr_pool_create(&ptemp, ptrans);
    if (rv > 0) {
        return CONV_FAIL;
    }

    sec_policy = apr_dbd_escape(driver, ptemp, name, tmp_db);
    state = apr_psprintf(ptemp, "SELECT * FROM %s WHERE sec_policy = '%s' "\
                         "ORDER BY sub_policy", SEC_POLICY_TAB, sec_policy);
    rv = apr_dbd_select(driver, ptemp, tmp_db, &res, state, 1);
    if (rv) {
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, NULL,
                     "WAF_CONVERT: failure to get information about security policy!");
        apr_pool_destroy(ptemp);
        return CONV_FAIL;
    }

    rv = apr_dbd_num_tuples(driver, res);
    if (rv < 0) {
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, NULL,
                     "WAF_CONVERT: failure to get information about security policy!");
        apr_pool_destroy(ptemp);
        return CONV_FAIL;
    } else if (rv == 0) {
        apr_pool_destroy(ptemp);
        return CONV_OK;
    }

    npolicy = rv;

    /* 生成主配置文件 */
    rv = generate_main_config(result, ptemp);
    if (rv) {
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, NULL,
                     "WAF_CONVERT: failure to generate main configure!");
        apr_pool_destroy(ptemp);
        return DECLINED;
    }

#if APU_HAVE_SQLITE3
    for (i = npolicy; i > 0; i--) {
        rv = apr_dbd_get_row(driver, ptemp, res, &row, -1);
#elif APU_HAVE_MYSQL
    num = npolicy;
    for (i = 1; i <= num; i++) {
        rv = apr_dbd_get_row(driver, ptemp, res, &row, i);
#endif
        if (rv) {
            apr_pool_destroy(ptemp);
            return CONV_FAIL;
        }

        /* 根据status判断是否加载对应的安全子策略 */
        entry = apr_dbd_get_entry(driver, row, 5);
        status = atoi(entry);
        if (!status) {
            continue;
        }

        /* 生成规则 SecDefaultAction ... */
        generate_default_rule(row, result, ptemp);
        /* 获得安全子策略类别 */
        entry = apr_dbd_get_entry(driver, row, 1);
        for (j = 0; j < MAX_SUBPOLICY; j++) {
            if (!strcmp(entry, policy_type[j])) {
                type = j;
                break;
            }
        }

        if (j == MAX_SUBPOLICY) {
            apr_pool_destroy(ptemp);
            return CONV_FAIL;
        }

        /* 生成具体的规则 */
        rv = generate_sub_rule(name, type, result, ptemp);
        if (rv == CONV_NOTEXIST) {
            ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, ap_main_server,
                         "WAF_CONVERT: sub_policy %s is not existed!", policy_type[type]);
            continue;
        } else if (rv != CONV_OK) {
            ap_log_error(APLOG_MARK, APLOG_ERR, 0, NULL,
                         "WAF_CONVERT:failed to generate sub_policy %s!", policy_type[type] + 5);
            apr_pool_destroy(ptemp);
            return rv;
        }

        ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, ap_main_server,
                     "WAF_CONVERT:generate sub_policy %s succeed!", policy_type[type]);
    }

    apr_pool_destroy(ptemp);
    return CONV_OK;
}

/**
 * 查询安全子策略信息
 */
int convert_sec_policy_list(char *sec_policy, int sec_subpolicy, apr_array_header_t **result)
{
    int rv;
    apr_pool_t *ptemp;

    if ((sec_policy == NULL) || (result == NULL) || (*result == NULL)) {
        return CONV_FAIL;
    }

    if (sec_subpolicy < 0 || sec_subpolicy >= MAX_SUBPOLICY) {
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, NULL,
                     "WAF_CONVERT: wrong sub policy id %d!", sec_subpolicy);
        apr_pool_destroy(ptemp);
        return CONV_FAIL;
    }

    rv = apr_pool_create(&ptemp, ptrans);
    if (rv) {
        return CONV_FAIL;
    }

    if (conv_subpolicy_list[sec_subpolicy] && conv_subpolicy_list[sec_subpolicy]->subpolicy_list){
        rv = conv_subpolicy_list[sec_subpolicy]->subpolicy_list(sec_policy, result, ptemp);
        apr_pool_destroy(ptemp);
        return rv;
    } else {        /* 只存在内置库则返回成功 */
        apr_pool_destroy(ptemp);
        return CONV_OK;
    }
}
