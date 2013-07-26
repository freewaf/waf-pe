/*
 * $Id: combind_rule.c 2786 2013-07-09 16:42:55 FreeWAF Development Team $
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

type_t keyword_type[] = {
    {"SecRule",                         TAKE23},
    {"SecRuleUpdateTargetById",         TAKE23},
    {"SecAction",                       TAKE1},
    {"SecDefaultAction",                TAKE1},
    {"SecMarker",                       TAKE1},
    {"#!SecFlag",                       TAKE1},
    {"SecRuleInheritance",              FLAG},
    {"SecRuleScript",                   TAKE12},
    {"SecRuleUpdateActionById",         TAKE2},
    {"SecRuleRemoveByID",               ITERATE},
    {"SecRuleRemoveByTag",              ITERATE},
    {"SecRuleRemoveByMsg",              ITERATE},

    /* 保留 */
    {"SecArgumentSeparator",            TAKE1},
    {"SecCookieFormat",                 TAKE1},
    {"SecUploadFileLimit",              TAKE1},

    /* 保留默认 */
    {"SecDataDir",                      TAKE1},
    {"SecDebugLog",                     TAKE1},
    {"SecGsbLookupDB",                  TAKE1},
    {"SecUnicodeMapFile",               TAKE1},
    {"SecGeoLookupDB",                  TAKE1},
    {"SecRequestBodyAccess",            TAKE1},
    {"SecResponseBodyAccess",           TAKE1},
    {"SecTmpDir",                       TAKE1},
    {"SecUploadDir",                    TAKE1},
    {"SecUploadFileMode",               TAKE1},

    /* 保留隐藏 */
    {"SecCacheTransformations",         TAKE12},
    {"SecContentInjection",             FLAG},
    {"SecStreamOutBodyInspection",      FLAG},
    {"SecStreamInBodyInspection",       FLAG},
    {"SecDisableBackendCompression",    FLAG},
    {"SecUnicodeCodePage",              TAKE1},
    {"SecPcreMatchLimit",               TAKE1},
    {"SecPcreMatchLimitRecursion",      TAKE1},
    {"SecInterceptOnError",             TAKE1},
    {"SecReadStateLimit",               TAKE1},
    {"SecWriteStateLimit",              TAKE1},
    {"SecRequestBodyInMemoryLimit",     TAKE1},
    {"SecRequestBodyLimit",             TAKE1},
    {"SecRequestBodyNoFilesLimit",      TAKE1},
    {"SecRequestEncoding",              TAKE1},
    {"SecResponseBodyLimit",            TAKE1},
    {"SecResponseBodyLimitAction",      TAKE1},
    {"SecRequestBodyLimitAction",       TAKE1},
    {"SecResponseBodyMimeType",         ITERATE},
    {"SecResponseBodyMimeTypesClear",   RAW_ARGS},

    /* 功能改进 */
    {"SecDebugLogLevel",                TAKE1},
    {"SecRuleEngine",                   TAKE1},
    {"SecUploadKeepFiles",              TAKE1},
    {"SecWebAppId",                     TAKE1},

    /* apache命令 */
    {"<LocationMatch",                  RAW_ARGS},
    {"</LocationMatch>",                RAW_ARGS},
    {NULL,                              RAW_ARGS}
};

static void combined_secrule(apr_dbd_row_t *row, const char *check_val, const char *new_id,
                      apr_array_header_t **result, apr_pool_t *ptemp)
{
    int                 i, flag;
    const char          *entry;
    char                *rule, **new;
    apr_pool_t          *tpool;

    flag = 0;
	rule = NULL;
    for (i = B_LIST_ID; i < TOTAL; i++) {
        entry = apr_dbd_get_entry(driver, row, i);
        switch(i) {
            case B_LIST_ID:             /* basis.list_id */
            case B_TYPE:             /* basis.type */
            case B_FLAG:             /* basis.flag */
            case E_LIST_ID:            /* extension.list_id */
                break;
            case B_KEYWORD:             /* basis.keyword */
                rule = apr_psprintf(ptemp, "%s", entry);
                break;
            case B_VAR:             /* basis.variable */
                rule = apr_pstrcat(ptemp, rule, " ", entry, NULL);
                break;
            case B_OPER:             /* basis.operator */
                rule = apr_pstrcat(ptemp, rule, " \"", entry, NULL);
                break;
            case B_CHK_VAL:             /* basis.check_value */
                if (check_val) {
                    rule = apr_pstrcat(ptemp, rule, " ", check_val, "\"", NULL);
                } else {
                    rule = apr_pstrcat(ptemp, rule, " ", entry, "\"", NULL);
                }
                break;
            case B_CHAIN:             /* basis.chain */
                if (entry) {
                    rule = apr_pstrcat(ptemp, rule, " \"chain", NULL);
                    flag = 1;
                } else {
                    rule = apr_pstrcat(ptemp, rule, " \"", NULL);
                }
                break;
            case B_TRANS:             /* basis.trans_func */
            case B_ACT:             /* basis.action */
            case E_DISRUPT:            /* extension.disruptive */
            case E_LOG:            /* extension.log */
                if (entry) {
                    if (flag) {
                        rule = apr_pstrcat(ptemp, rule, ",", NULL);
                    }
                    rule = apr_pstrcat(ptemp, rule, entry, NULL);
                    flag = 1;
                }
                break;
            case E_PHASE:            /* extension.phase */
                if ( entry != NULL) {
                    if (flag) {
                        rule = apr_pstrcat(ptemp, rule, ",", NULL);
                    }
                    rule = apr_pstrcat(ptemp, rule, "phase:", entry, NULL);
                    flag = 1;
                }
                break;
            case E_ID:            /* extension.id */
                if (entry) {
                    if (flag) {
                        rule = apr_pstrcat(ptemp, rule, ",", NULL);
                    }

                    if (new_id) {
                        rule = apr_pstrcat(ptemp, rule, "id:'", new_id, "'", NULL);
                    } else {
                        rule = apr_pstrcat(ptemp, rule, "id:'", entry, "'", NULL);
                    }
                    flag = 1;
                }
                break;
            case E_MSG:            /* extension.msg */
                if (entry) {
                    if (flag) {
                        rule = apr_pstrcat(ptemp, rule, ",", NULL);
                    }
                    rule = apr_pstrcat(ptemp, rule, "msg:'", entry, "'", NULL);
                }
                break;
            default:
                break;
        }
    }

    rule = apr_pstrcat(ptemp, rule, "\"", NULL);
    tpool = (* result)->pool;
    new = (char **)apr_array_push(*result);
    *new = apr_pstrdup(tpool, rule);
    return ;
}

static void combined_take23(apr_dbd_row_t *row, const char *check_val, const char *new_id,
        apr_array_header_t **result, apr_pool_t *ptemp)
{
    char        *rule, **new;
    const char  *entry;
    apr_pool_t  *tpool;

    entry = apr_dbd_get_entry(driver, row, B_KEYWORD);     /* basis.keyword */
	tpool = (*result)->pool;
    if (strcmp(entry, "SecRule")) {
        rule = apr_psprintf(ptemp, "%s", entry);

        entry = apr_dbd_get_entry(driver, row, B_VAR);     /* basis.variable */
        rule = apr_pstrcat(ptemp, rule, " ", entry, NULL);

        entry = apr_dbd_get_entry(driver, row, B_OPER);     /* basis.operator */
        rule = apr_pstrcat(ptemp, rule, " \"", entry, "\"", NULL);

        entry = apr_dbd_get_entry(driver, row, B_CHK_VAL);     /* basis.check_value */
        rule = apr_pstrcat(ptemp, rule, " \"", entry, "\"", NULL);

        rule = apr_pstrcat(ptemp, rule, "\"", NULL);
        new = (char **)apr_array_push(*result);
        *new = apr_pstrdup(tpool, rule);

        return ;
    }
    
    combined_secrule(row, check_val, new_id, result, ptemp);
    return ;
}

static void combined_take1(apr_dbd_row_t *row, apr_array_header_t **result, apr_pool_t *ptemp)
{
    const char  *entry;
    char        *rule, **new;
    apr_pool_t  *tpool;

    entry = apr_dbd_get_entry(driver, row, B_KEYWORD);     /* basis.keyword */
    rule = apr_psprintf(ptemp, "%s", entry);

    entry = apr_dbd_get_entry(driver, row, B_VAR);     /* basis.variable */
    rule = apr_pstrcat(ptemp, rule, " ", entry, NULL);

    tpool = (* result)->pool;
    new = (char **)apr_array_push(*result);
    *new = apr_pstrdup(tpool, rule);
}

void combined_flag(apr_dbd_row_t *row, apr_array_header_t **result, apr_pool_t *ptemp)
{
    const char  *entry;
    char        *rule, **new;
    apr_pool_t  *tpool;

    entry = apr_dbd_get_entry(driver, row, B_KEYWORD);     /* basis.keyword */
    rule = apr_psprintf(ptemp, "%s", entry);

    entry = apr_dbd_get_entry(driver, row, B_VAR);     /* basis.variable */
    rule = apr_pstrcat(ptemp, rule, " ", entry, NULL);

    tpool = (* result)->pool;
    new = (char **)apr_array_push(*result);
    *new = apr_pstrdup(tpool, rule);
}

static void combined_take12(apr_dbd_row_t *row, apr_array_header_t **result, apr_pool_t *ptemp)
{
    const char  *entry;
    char        *rule, **new;
    apr_pool_t  *tpool;

    entry = apr_dbd_get_entry(driver, row, B_KEYWORD);     /* basis.keyword */
    rule = apr_psprintf(ptemp, "%s", entry);

    entry = apr_dbd_get_entry(driver, row, B_VAR);     /* basis.variable */
    rule = apr_pstrcat(ptemp, rule, " \"", entry, "\"", NULL);

    entry = apr_dbd_get_entry(driver, row, B_OPER);     /* basis.operator */
    if (entry) {
        rule = apr_pstrcat(ptemp, rule, " \"", entry, "\"", NULL);
    }

    tpool = (* result)->pool;
    new = (char **)apr_array_push(*result);
    *new = apr_pstrdup(tpool, rule);
}

static void combined_take2(apr_dbd_row_t *row, apr_array_header_t **result, apr_pool_t *ptemp)
{
    const char  *entry;
    char        *rule, **new;
    apr_pool_t  *tpool;

    entry = apr_dbd_get_entry(driver, row, B_KEYWORD);       /* basis.keyword */
    rule = apr_psprintf(ptemp, "%s", entry);

    entry = apr_dbd_get_entry(driver, row, B_VAR);          /* basis.variable */
    rule = apr_pstrcat(ptemp, rule, " ", entry, NULL);

    entry = apr_dbd_get_entry(driver, row, B_OPER);         /* basis.operator */
    rule = apr_pstrcat(ptemp, rule, " \"", entry, "\"", NULL);

    tpool = (* result)->pool;
    new = (char **)apr_array_push(*result);
    *new = apr_pstrdup(tpool, rule);
}

static void combined_iterate(apr_dbd_row_t *row, apr_array_header_t **result, apr_pool_t *ptemp)
{
    const char  *entry;
    char        *rule, **new;
    apr_pool_t  *tpool;

    entry = apr_dbd_get_entry(driver, row, B_KEYWORD);      /* basis.keyword */
    rule = apr_psprintf(ptemp, "%s", entry);

    entry = apr_dbd_get_entry(driver, row, B_VAR);          /* basis.variable */
    if (entry != NULL) {
        rule = apr_pstrcat(ptemp, rule, " ", entry, NULL);
    }

    tpool = (* result)->pool;
    new = (char **)apr_array_push(*result);
    *new = apr_pstrdup(tpool, rule);
}

void combined_rule(apr_dbd_row_t *row, const char *check_val, const char *new_id,
                   apr_array_header_t **result, apr_pool_t *ptemp)
{
    int         i;
    const char  *entry;

    if ((row == NULL) || (result == NULL) || (*result == NULL) || (ptemp == NULL)) {
        return ;
    }

    /* 获取列basis.keyword */
    entry = apr_dbd_get_entry(driver, row, B_KEYWORD);
    for (i = 0; keyword_type[i].keyword; i++) {
        if (!strcmp(keyword_type[i].keyword, entry)) {
            switch (keyword_type[i].type) {
            case TAKE23:
                return combined_take23(row, check_val, new_id, result, ptemp);
            case TAKE1:
                return combined_take1(row, result, ptemp);
            case FLAG:
                return combined_flag(row, result, ptemp);
            case TAKE12:
                return combined_take12(row, result, ptemp);
            case TAKE2:
                return combined_take2(row, result, ptemp);
            case ITERATE:
            case RAW_ARGS:
                return combined_iterate(row, result, ptemp);
            default:
                ap_log_error(APLOG_MARK, APLOG_NOTICE, 0, NULL, "WAF_CONVERT: invalid keyword");
                return ;
            }
        }
    }
}

