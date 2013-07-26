/*
 * $Id: cli_security_policy_keyword.c 2786 2013-07-09 16:42:55 FreeWAF Development Team $
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

#include "cli_security_policy.h"
#include "pe_cli.h"

/* 下面三个接口增加或删除sql关键字 */
cparser_result_t cparser_cmd_sql_keyword_plain_text_keyword(cparser_context_t *context,
                    char **keyword_ptr)
{
    apr_pool_t *ptemp;

    if (context == NULL) {
        return CPARSER_NOT_OK;
    }

    apr_pool_create(&ptemp, psec); 
    apr_pool_tag(ptemp, "ptemp");

    if (context->parser->mode != CPARSER_MODE_CONFIG) {
        keyword_c2p(context, SQL_INJECTION, ptemp);
    } else {
        if (keyword_ptr == NULL || *keyword_ptr == NULL) {
            apr_pool_destroy(ptemp);
            return CPARSER_NOT_OK;
        }   

        if (is_ascii(*keyword_ptr) != CONV_OK) {
            cli_printf_info(context, " configure error; sql keyword Can't contain Chinese characters\n");
            apr_pool_destroy(ptemp);
            return CPARSER_NOT_OK;
        }
        
        keyword_add(context, SQL_INJECTION, NO_TYPE, ptemp, keyword_ptr, NULL);
    }

    apr_pool_destroy(ptemp);
    return CPARSER_OK;
}
    
cparser_result_t cparser_cmd_sql_no_keyword_all(cparser_context_t *context)
{ 
    return cmd_no_keyword_all(context, SQL_INJECTION, NO_TYPE);
}

cparser_result_t cparser_cmd_sql_no_keyword_plain_text_keyword(cparser_context_t *context,
                    char **keyword_ptr)
{  
    return cmd_no_keyword_plain_text_keyword(context, SQL_INJECTION, NO_TYPE, keyword_ptr);
}

/* 下面两个接口删除弱密码模式下弱密码防护的网页 */
cparser_result_t cparser_cmd_wpd_no_url_all(cparser_context_t *context)
{
    apr_pool_t *ptemp;
    char sec_policy_name[NAME_LEN_MAX];
    keyword_t keyword;
    char **keyword1;
    int rv;
    char buf[COMMAND_LEN_MAX];

    if (context == NULL) {
        return CPARSER_NOT_OK;
    }

    if (context->parser->mode != CPARSER_MODE_CONFIG) {
        return CPARSER_OK;
    } else {
        apr_pool_create(&ptemp, psec); 
        apr_pool_tag(ptemp, "ptemp");

        transfer_security_policy_name(context);
        strncpy(sec_policy_name, (char *)context->cookie[context->parser->root_level], NAME_LEN_MAX);
        keyword.pool = ptemp;
        strncpy(keyword.sec_policy, sec_policy_name, NAME_LEN_MAX);
        keyword.sec_subpolicy = WEAK_PASSWORD;
        keyword.type = 0;
            
        keyword.keyword = apr_array_make(ptemp, INIT_ARR_LEN, sizeof(char*));
        keyword1 = (char**)apr_array_push(keyword.keyword); 
        *keyword1 = apr_pstrdup(ptemp, "all");
        keyword.flag = WP_NO_URL_ALL;

        rv = convert_keyword_del(&keyword);
        switch (rv) {
        case CONV_OK:
            sprintf(buf, "no url all");
            admin_log_process(context, buf);
            break;
        case CONV_FAIL:
            cli_printf_info(context, "del all keyword failure\n");
            break;
        case CONV_NOTEXIST:
            cli_printf_info(context, "del all keyword failure, keyword hasn't existed\n");
            break;
        default:
            break;
        }

        apr_pool_destroy(ptemp);
        return CPARSER_OK;
    }
}

cparser_result_t cparser_cmd_wpd_no_url_type_url_string(cparser_context_t *context, char **type_ptr,
                    char **url_string_ptr)
{
    apr_pool_t *ptemp;
    char sec_policy_name[NAME_LEN_MAX];
    keyword_t keyword;
    char **keyword1;
    int rv;
    char buf[COMMAND_LEN_MAX];

    if (context->parser->mode != CPARSER_MODE_CONFIG) {
        return CPARSER_OK;
    } else {
        apr_pool_create(&ptemp, psec); 
        apr_pool_tag(ptemp, "ptemp");

        keyword.pool = ptemp;
        transfer_security_policy_name(context);
        strncpy(sec_policy_name, (char *)context->cookie[context->parser->root_level], NAME_LEN_MAX);
        strncpy(keyword.sec_policy, sec_policy_name, NAME_LEN_MAX);
        keyword.sec_subpolicy = WEAK_PASSWORD;

        if (strcmp(*type_ptr, "plain-text") == 0) {
            keyword.type = PLAIN_URL;
        } else if (strcmp(*type_ptr, "regular-exp") == 0) {
            keyword.type = REGEX_URL;
        }

        keyword.keyword = apr_array_make(ptemp, INIT_ARR_LEN, sizeof(char*));
        keyword1 = (char**)apr_array_push(keyword.keyword);
        *keyword1 = apr_pstrdup(ptemp, *url_string_ptr);
        keyword.flag = WP_NO_URL;

        rv = convert_keyword_del(&keyword);
        switch (rv) {
        case CONV_OK:
            sprintf(buf, "no url %s %s", *type_ptr, *url_string_ptr);
            admin_log_process(context, buf);
            break;
        case CONV_FAIL:
            cli_printf_info(context, "del keyword failure\n");
            break;
        case CONV_NOTEXIST:
            cli_printf_info(context, "del keyword failure, keyword hasn't existed\n");
            break;
        default:
            break;
        }

        apr_pool_destroy(ptemp);
        return CPARSER_OK;
    }
}

cparser_result_t cparser_cmd_wp_url_no_weak_password_plain_text_string(cparser_context_t *context,
    char **string_ptr)
{
    apr_pool_t *ptemp;
    char *sec_policy_name;
    char *password_name, *url_string;
    keyword_t keyword;
    char **keyword1, **keyword2, **keyword3;
    int rv;
    const char *str;
    int url_type;
    char buf[COMMAND_LEN_MAX];

    if (context->parser->mode != CPARSER_MODE_CONFIG) {
        return CPARSER_OK;
    } else {
        apr_pool_create(&ptemp, psec); 
        apr_pool_tag(ptemp, "ptemp");

        str = apr_pstrdup(ptemp, (char *)context->cookie[context->parser->root_level]);
        sec_policy_name = ap_getword_conf(ptemp, &str);
        url_string = ap_getword_conf(ptemp, &str);
        password_name = ap_getword_conf(ptemp, &str);
        url_type = apr_atoi64(ap_getword_conf(ptemp, &str));

        keyword.pool = ptemp; 
        keyword.flag = 0;
        strncpy(keyword.sec_policy, sec_policy_name, NAME_LEN_MAX);
        keyword.sec_subpolicy = WEAK_PASSWORD;

        if (url_type == PLAIN_URL) {
            keyword.type = PLAIN_PLAIN;
        } else if (url_type == REGEX_URL) {
            keyword.type = REGEX_PLAIN;
        } 

        keyword.keyword = apr_array_make(ptemp, INIT_ARR_LEN, sizeof(char*));
            
        keyword1 = (char**)apr_array_push(keyword.keyword);
        *keyword1 = apr_pstrdup(ptemp, url_string);

        keyword2 = (char**)apr_array_push(keyword.keyword);
        *keyword2 = apr_pstrdup(ptemp, password_name);

        keyword3 = (char**)apr_array_push(keyword.keyword);
        *keyword3 = apr_pstrdup(ptemp, *string_ptr);
        keyword.flag = WP_KEYWORD;
        
        rv = convert_keyword_del(&keyword);
        switch (rv) {
        case CONV_OK:
            sprintf(buf, "no weak_password plain-text %s", *string_ptr);
            admin_log_process(context, buf);
            break;
        case CONV_FAIL:
            cli_printf_info(context, "del keyword failure\n");
            break;
        case CONV_NOTEXIST:
            cli_printf_info(context, "del keyword failure, keyword hasn't existed\n");
            break;
        default:
            break;
        }

        apr_pool_destroy(ptemp);
        return CPARSER_OK;
    }       
}

cparser_result_t cparser_cmd_wp_url_no_weak_password_regular_exp(cparser_context_t *context)
{
    apr_pool_t *ptemp;
    char *sec_policy_name;
    char *password_name, *url_string;
    keyword_t keyword;
    char **keyword1, **keyword2, **keyword3;
    int rv;
    const char *str;
    int url_type;
    char buf[COMMAND_LEN_MAX];

    if (context->parser->mode != CPARSER_MODE_CONFIG) {
        return CPARSER_OK;
    } else {
        apr_pool_create(&ptemp, psec); 
        apr_pool_tag(ptemp, "ptemp");

        str = apr_pstrdup(ptemp, (char *)context->cookie[context->parser->root_level]);
        sec_policy_name = ap_getword_conf(ptemp, &str);
        url_string = ap_getword_conf(ptemp, &str);
        password_name = ap_getword_conf(ptemp, &str);
        url_type = apr_atoi64(ap_getword_conf(ptemp, &str));

        keyword.pool = ptemp; 
        keyword.flag = 0;
        strncpy(keyword.sec_policy, sec_policy_name, NAME_LEN_MAX);
        keyword.sec_subpolicy = WEAK_PASSWORD;

        if (url_type == PLAIN_URL) {
            keyword.type = PLAIN_REGEX;
        } else if (url_type == REGEX_URL) {
            keyword.type = REGEX_REGEX;
        }

        keyword.keyword = apr_array_make(ptemp, INIT_ARR_LEN, sizeof(char*));
            
        keyword1 = (char**)apr_array_push(keyword.keyword);
        *keyword1 = apr_pstrdup(ptemp, url_string);

        keyword2 = (char**)apr_array_push(keyword.keyword);
        *keyword2 = apr_pstrdup(ptemp, password_name);

        keyword3 = (char**)apr_array_push(keyword.keyword);
        *keyword3 = apr_pstrdup(ptemp, KEYWORD_DEFAULT);
        
        keyword.flag = WP_KEYWORD;

        rv = convert_keyword_del(&keyword);
        switch (rv) {
        case CONV_OK:
            sprintf(buf, "no weak_password regular_exp");
            admin_log_process(context, buf);
            break;
        case CONV_FAIL:
            cli_printf_info(context, "del keyword failure\n");
            break;
        case CONV_NOTEXIST:
            cli_printf_info(context, "del keyword failure, keyword hasn't existed\n");
            break;
        default:
            break;
        }

        apr_pool_destroy(ptemp);
        return CPARSER_OK;
    } 
}

/* 下面三个接口用来配置弱密码的关键字 */
cparser_result_t cparser_cmd_wp_url_weak_password_type_string(cparser_context_t *context,
    char **type_ptr,
    char **string_ptr)
{
    apr_pool_t *ptemp;
    char *sec_policy_name;
    char *password_name, *url_string;
    keyword_t keyword;
    char **keyword1, **keyword2, **keyword3;
    int rv;
    const char *str;
    int url_type;
    char buf[COMMAND_LEN_MAX];

    if (context->parser->mode != CPARSER_MODE_CONFIG) {
        return CPARSER_OK;
    } else {
        if (is_ascii(*string_ptr) != CONV_OK) {
            cli_printf_info(context, " configure error; weak password keyword cann't contain Chinese characters\n");
            return CPARSER_NOT_OK;
        }

        apr_pool_create(&ptemp, psec); 
        apr_pool_tag(ptemp, "ptemp");
        
        str = apr_pstrdup(ptemp, (char *)context->cookie[context->parser->root_level]);
        sec_policy_name = ap_getword_conf(ptemp, &str);
        url_string = ap_getword_conf(ptemp, &str);
        password_name = ap_getword_conf(ptemp, &str);
        url_type = apr_atoi64(ap_getword_conf(ptemp, &str));
        
        keyword.pool = ptemp; 
        keyword.flag = 0;
        strncpy(keyword.sec_policy, sec_policy_name, NAME_LEN_MAX);
        keyword.sec_subpolicy = WEAK_PASSWORD;

        if ((strcmp(*type_ptr, "plain-text") == 0) && url_type == PLAIN_URL) {
            keyword.type = PLAIN_PLAIN;
        } else if ((strcmp(*type_ptr, "plain-text") == 0) && url_type == REGEX_URL) {
            keyword.type = REGEX_PLAIN;
        } else if ((strcmp(*type_ptr, "regular-exp") == 0) && url_type == PLAIN_URL) {
            keyword.type = PLAIN_REGEX;
        } else if ((strcmp(*type_ptr, "regular-exp") == 0) && url_type == REGEX_URL) {
            keyword.type = REGEX_REGEX;
        }

        keyword.keyword = apr_array_make(ptemp, INIT_ARR_LEN, sizeof(char*));
        
        keyword1 = (char**)apr_array_push(keyword.keyword);
        *keyword1 = apr_pstrdup(ptemp, url_string);

        keyword2 = (char**)apr_array_push(keyword.keyword);
        *keyword2 = apr_pstrdup(ptemp, password_name);

        if (strcmp(*string_ptr, "default") == 0) {
            cli_printf_info(context, "error, cann't configure default regular\n");
            apr_pool_destroy(ptemp);
            return CPARSER_OK;
            
        } else {  
            keyword3 = (char**)apr_array_push(keyword.keyword);
            *keyword3 = apr_pstrdup(ptemp, *string_ptr);
            keyword.flag = WP_KEYWORD;
        }

        rv = convert_keyword_add(&keyword);
        switch (rv) {
        case CONV_OK:
            sprintf(buf, "weak_password %s %s", *type_ptr, *string_ptr);
            admin_log_process(context, buf);
            break;
        case CONV_FAIL:
            cli_printf_info(context, "add keyword failure\n");
            break;
        case CONV_CONFLICT:
            cli_printf_info(context, "add keyword failure, keyword has existed\n");
            break;
        default:
            break;
        }

        apr_pool_destroy(ptemp);
        return CPARSER_OK;
    }
}

cparser_result_t cparser_cmd_wp_url_no_weak_password_all(cparser_context_t *context)
{
    apr_pool_t *ptemp;
    char *sec_policy_name;
    char *password_name, *url_string;
    keyword_t keyword;
    char **keyword1, **keyword2, **keyword3;
    int rv;
    const char *str;
    int url_type;
    char buf[COMMAND_LEN_MAX];

    if (context->parser->mode != CPARSER_MODE_CONFIG) {
        return CPARSER_OK;
    } else {
        apr_pool_create(&ptemp, psec); 
        apr_pool_tag(ptemp, "ptemp");

        str = apr_pstrdup(ptemp, (char *)context->cookie[context->parser->root_level]);
        sec_policy_name = ap_getword_conf(ptemp, &str);
        url_string = ap_getword_conf(ptemp, &str);
        password_name = ap_getword_conf(ptemp, &str);
        url_type = apr_atoi64(ap_getword_conf(ptemp, &str));

        keyword.pool = ptemp; 
        keyword.flag = 0;
        strncpy(keyword.sec_policy, sec_policy_name, NAME_LEN_MAX);
        keyword.sec_subpolicy = WEAK_PASSWORD;
        keyword.type = url_type;
        keyword.keyword = apr_array_make(ptemp, INIT_ARR_LEN, sizeof(char*));
            
        keyword1 = (char**)apr_array_push(keyword.keyword);
        *keyword1 = apr_pstrdup(ptemp, url_string);

        keyword2 = (char**)apr_array_push(keyword.keyword);
        *keyword2 = apr_pstrdup(ptemp, password_name);

        keyword3 = (char**)apr_array_push(keyword.keyword);
        *keyword3 = apr_pstrdup(ptemp, KEYWORD_ALL);
        keyword.flag = WP_NO_KEYWORD_ALL;

        rv = convert_keyword_del(&keyword);
        switch (rv) {
        case CONV_OK:
            sprintf(buf, "no weak_password all");
            admin_log_process(context, buf);
            break;
        case CONV_FAIL:
            cli_printf_info(context, "del all keyword failure\n");
            break;
        case CONV_NOTEXIST:
            cli_printf_info(context, "del all keyword failure, keyword hasn't existed\n");
            break;
        default:
            break;
        }

        apr_pool_destroy(ptemp);
        return CPARSER_OK;
    }
}

/* 下面三个接口用来配置命令注入的关键字 */
cparser_result_t cparser_cmd_cmd_keyword_plain_text_keyword(cparser_context_t *context,
    char **keyword_ptr)
{
    apr_pool_t *ptemp;

    if (context == NULL) {
        return CPARSER_NOT_OK;
    }

    apr_pool_create(&ptemp, psec); 
    apr_pool_tag(ptemp, "ptemp");

    if (context->parser->mode != CPARSER_MODE_CONFIG) {
        keyword_c2p(context, COMMAND_INJECTION, ptemp);
    } else {
        if (keyword_ptr == NULL || *keyword_ptr == NULL) {
            apr_pool_destroy(ptemp);
            return CPARSER_NOT_OK;
        }

        if (is_ascii(*keyword_ptr) != CONV_OK) {
            cli_printf_info(context, " configure error; command injection keyword Can't contain Chinese characters\n");
            apr_pool_destroy(ptemp);
            return CPARSER_NOT_OK;
        }
    
        keyword_add(context, COMMAND_INJECTION, NO_TYPE, ptemp, keyword_ptr, NULL);
    }

    apr_pool_destroy(ptemp);
    return CPARSER_OK;
}

cparser_result_t cparser_cmd_cmd_no_keyword_all(cparser_context_t *context)
{
    return cmd_no_keyword_all(context, COMMAND_INJECTION, NO_TYPE);
}

cparser_result_t cparser_cmd_cmd_no_keyword_plain_text_keyword(cparser_context_t *context,
    char **keyword_ptr)
{
    return cmd_no_keyword_plain_text_keyword(context, COMMAND_INJECTION, NO_TYPE, keyword_ptr);
}

/* 下面三个接口用来配置code注入的关键字 */
cparser_result_t cparser_cmd_code_keyword_plain_text_keyword(cparser_context_t *context,
    char **keyword_ptr)
{
    apr_pool_t *ptemp;

    if (context == NULL) {
        return CPARSER_NOT_OK;
    }

    apr_pool_create(&ptemp, psec); 
    apr_pool_tag(ptemp, "ptemp");

    if (context->parser->mode != CPARSER_MODE_CONFIG) {
        keyword_c2p(context, CODE_INJECTION, ptemp);
    } else {
        if (keyword_ptr == NULL || *keyword_ptr == NULL) {
            apr_pool_destroy(ptemp);
            return CPARSER_NOT_OK;
        }

        if (is_ascii(*keyword_ptr) != CONV_OK) {
            cli_printf_info(context, " configure error; code injection keyword can't contain Chinese characters\n");
            apr_pool_destroy(ptemp);
            return CPARSER_NOT_OK;
        }

        keyword_add(context, CODE_INJECTION, NO_TYPE, ptemp, keyword_ptr, NULL);
    }

    apr_pool_destroy(ptemp);
    return CPARSER_OK;
}

cparser_result_t cparser_cmd_code_no_keyword_all(cparser_context_t *context)
{
    return cmd_no_keyword_all(context, CODE_INJECTION, NO_TYPE);
}

cparser_result_t cparser_cmd_code_no_keyword_plain_text_keyword(cparser_context_t *context,
    char **keyword_ptr)
{
    return cmd_no_keyword_plain_text_keyword(context, CODE_INJECTION, NO_TYPE, keyword_ptr);
}

/* 下面三个接口用来配置xss攻击的关键字 */
cparser_result_t cparser_cmd_xss_keyword_plain_text_keyword(cparser_context_t *context,
    char **keyword_ptr)
{
    apr_pool_t *ptemp;

    if (context == NULL) {
        return CPARSER_NOT_OK;
    }

    apr_pool_create(&ptemp, psec); 
    apr_pool_tag(ptemp, "ptemp");

    if (context->parser->mode != CPARSER_MODE_CONFIG) {
        keyword_c2p(context, XSS, ptemp);
    } else {
        if (keyword_ptr == NULL || *keyword_ptr == NULL) {
            apr_pool_destroy(ptemp);
            return CPARSER_NOT_OK;
        }   

        if (is_ascii(*keyword_ptr) != CONV_OK) {
            cli_printf_info(context, " configure error; xss keyword Can't contain Chinese characters\n");
            apr_pool_destroy(ptemp);
            return CPARSER_NOT_OK;
        }
        
        keyword_add(context, XSS, NO_TYPE, ptemp, keyword_ptr, NULL);
    }

    apr_pool_destroy(ptemp);
    return CPARSER_OK;
}

cparser_result_t cparser_cmd_xss_no_keyword_all(cparser_context_t *context)
{
    return cmd_no_keyword_all(context, XSS, NO_TYPE);
}

cparser_result_t cparser_cmd_xss_no_keyword_plain_text_keyword(cparser_context_t *context,
    char **keyword_ptr)
{
    return cmd_no_keyword_plain_text_keyword(context, XSS, NO_TYPE, keyword_ptr);
}

cparser_result_t cparser_cmd_csrf_cookie_name_plain_text_cookie_name(cparser_context_t *context,
    char **cookie_name_ptr)
{
    apr_pool_t *ptemp;

    if (context == NULL) {
        return CPARSER_NOT_OK;
    }

    apr_pool_create(&ptemp, psec); 
    apr_pool_tag(ptemp, "ptemp");

    if (context->parser->mode != CPARSER_MODE_CONFIG) {
        keyword_c2p(context, CSRF, ptemp);
    } else {
        if (cookie_name_ptr == NULL || *cookie_name_ptr == NULL) {
            apr_pool_destroy(ptemp);
            return CPARSER_NOT_OK;
        }

        if (is_ascii(*cookie_name_ptr) != CONV_OK) {
            cli_printf_info(context, " configure error; csrf cookie name Can't contain Chinese characters\n");
            apr_pool_destroy(ptemp);
            return CPARSER_NOT_OK;
        }

        keyword_add(context, CSRF, CSRF_COOKIE_NAME, ptemp, cookie_name_ptr, NULL);
    }

    apr_pool_destroy(ptemp);
    return CPARSER_OK;
}

cparser_result_t cparser_cmd_csrf_no_cookie_name_all(cparser_context_t *context)
{
    return cmd_no_keyword_all(context, CSRF, CSRF_COOKIE_NAME);
}

cparser_result_t cparser_cmd_csrf_no_cookie_name_plain_text_cookie_name(cparser_context_t *context,
    char **cookie_name_ptr)
{
    return cmd_no_keyword_plain_text_keyword(context, CSRF, CSRF_COOKIE_NAME, cookie_name_ptr);
}

cparser_result_t cparser_cmd_csrf_no_url_all(cparser_context_t *context)
{
    return cmd_no_keyword_all(context, CSRF, CSRF_URL_ALL);
}

cparser_result_t cparser_cmd_csrf_no_url_type_url_string(cparser_context_t *context,
    char **type_ptr,
    char **url_string_ptr)
{
    apr_pool_t *ptemp;
    char sec_policy_name[NAME_LEN_MAX];
    keyword_t keyword;
    char **keyword1;
    int rv;
    char buf[COMMAND_LEN_MAX];

    if (context->parser->mode != CPARSER_MODE_CONFIG) {
        return CPARSER_OK;
    } else {
        apr_pool_create(&ptemp, psec); 
        apr_pool_tag(ptemp, "ptemp");

        keyword.pool = ptemp;
        transfer_security_policy_name(context);
        strncpy(sec_policy_name, (char *)context->cookie[context->parser->root_level], NAME_LEN_MAX);
        strncpy(keyword.sec_policy, sec_policy_name, NAME_LEN_MAX);
        keyword.sec_subpolicy = CSRF;

        if (strcmp(*type_ptr, "plain-text") == 0) {
            keyword.type = CSRF_URL_PLAIN;
        } else if (strcmp(*type_ptr, "regular-exp") == 0) {
            keyword.type =  CSRF_URL_REGEX;
        }

        keyword.keyword = apr_array_make(ptemp, INIT_ARR_LEN, sizeof(char*));
        keyword1 = (char**)apr_array_push(keyword.keyword);
        *keyword1 = apr_pstrdup(ptemp, *url_string_ptr);
        keyword.flag = 0;

        rv = convert_keyword_del(&keyword);
        switch (rv) {
        case CONV_OK:
            sprintf(buf, "no url %s %s", *type_ptr, *url_string_ptr);
            admin_log_process(context, buf);
            break;
        case CONV_FAIL:
            cli_printf_info(context, "del keyword failure\n");
            break;
        case CONV_NOTEXIST:
            cli_printf_info(context, "del keyword failure, keyword hasn't existed\n");
            break;
        default:
            break;
        }

        apr_pool_destroy(ptemp);
        return CPARSER_OK;
    }
}

cparser_result_t cparser_cmd_csrf_url_type_url_string(cparser_context_t *context,
    char **type_ptr,
    char **url_string_ptr)
{
    apr_pool_t *ptemp;
    int type = 0;

    if (context == NULL) {
        return CPARSER_NOT_OK;
    }

    if (context->parser->mode != CPARSER_MODE_CONFIG) {                   
        return CPARSER_OK;
    } else {
        if (is_ascii(*url_string_ptr) != CONV_OK) {
            cli_printf_info(context, " configure error; csrf url Can't contain Chinese characters\n");
            return CPARSER_NOT_OK;
        }

        apr_pool_create(&ptemp, psec); 
        apr_pool_tag(ptemp, "ptemp");
        
        if (!strcmp(*type_ptr, "plain-text")) {
            type = CSRF_URL_PLAIN;
            if ((*url_string_ptr)[0] != '/') {
                cli_printf_info(context, " url configure error, please enter absolute path\n");
                apr_pool_destroy(ptemp);
                return CPARSER_NOT_OK;
            } if ((*url_string_ptr)[1] == '/') {
                cli_printf_info(context, " url configure error, please enter correct path\n");
                apr_pool_destroy(ptemp);
                return CPARSER_NOT_OK;
            }
        } else if (!strcmp(*type_ptr, "regular-exp")){
            type = CSRF_URL_REGEX;
        }
        
        keyword_add(context, CSRF, type, ptemp, url_string_ptr, NULL);

        apr_pool_destroy(ptemp);
        return CPARSER_OK; 
    } 
}

/* 下面三个接口用来配置爬虫与扫描攻击防护相关命令的关键字 */
cparser_result_t cparser_cmd_spider_keyword_plain_text_keyword(cparser_context_t *context,
    char **keyword_ptr)
{
    apr_pool_t *ptemp;

    if (context == NULL) {
        return CPARSER_NOT_OK;
    }

    apr_pool_create(&ptemp, psec); 
    apr_pool_tag(ptemp, "ptemp");

    if (context->parser->mode != CPARSER_MODE_CONFIG) {
        keyword_c2p(context, SPIDER_SCANNER, ptemp);
    } else {
        if (keyword_ptr == NULL || *keyword_ptr == NULL) {
            apr_pool_destroy(ptemp);
            return CPARSER_NOT_OK;
        }

        if (is_ascii(*keyword_ptr) != CONV_OK) {
            cli_printf_info(context, " configure error; spider keyword Can't contain Chinese characters\n");
            apr_pool_destroy(ptemp);
            return CPARSER_NOT_OK;
        }

        keyword_add(context, SPIDER_SCANNER, NO_TYPE, ptemp, keyword_ptr, NULL);
    }

    apr_pool_destroy(ptemp);
    return CPARSER_OK;
}

cparser_result_t cparser_cmd_spider_no_keyword_all(cparser_context_t *context)
{
    return cmd_no_keyword_all(context, SPIDER_SCANNER, NO_TYPE);
}

cparser_result_t cparser_cmd_spider_no_keyword_plain_text_keyword(cparser_context_t *context,
    char **keyword_ptr)
{
    return cmd_no_keyword_plain_text_keyword(context, SPIDER_SCANNER, NO_TYPE, keyword_ptr);
}

/* 下面三个接口用来配置木马防护相关命令的关键字 */
cparser_result_t cparser_cmd_trojan_keyword_plain_text_keyword(cparser_context_t *context,
    char **keyword_ptr)
{
    apr_pool_t *ptemp;

    if (context == NULL) {
        return CPARSER_NOT_OK;
    }

    apr_pool_create(&ptemp, psec); 
    apr_pool_tag(ptemp, "ptemp");

    if (context->parser->mode != CPARSER_MODE_CONFIG) {
        keyword_c2p(context, TROJAN, ptemp);
    } else {
        if (keyword_ptr == NULL || *keyword_ptr == NULL) {
            apr_pool_destroy(ptemp);
            return CPARSER_NOT_OK;
        }
        
        if (is_ascii(*keyword_ptr) != CONV_OK) {
            cli_printf_info(context, " configure error; trojan keyword Can't contain Chinese characters\n");
            apr_pool_destroy(ptemp);
            return CPARSER_NOT_OK;
        }
        
        keyword_add(context, TROJAN, NO_TYPE, ptemp, keyword_ptr, NULL);
    }

    apr_pool_destroy(ptemp);
    return CPARSER_OK;
}

cparser_result_t cparser_cmd_trojan_no_keyword_all(cparser_context_t *context)
{
    return cmd_no_keyword_all(context, TROJAN, NO_TYPE);
}

cparser_result_t cparser_cmd_trojan_no_keyword_plain_text_keyword(cparser_context_t *context,
    char **keyword_ptr)
{
    return cmd_no_keyword_plain_text_keyword(context, TROJAN, NO_TYPE, keyword_ptr);
}

/* 下面三个接口用来配置服务器版本防护的关键字 */
cparser_result_t cparser_cmd_server_version_keyword_substitute_plain_text_new_string_for_regular_exp_old_string(cparser_context_t *context,
    char **new_string_ptr,
    char **old_string_ptr)
{
    apr_pool_t *ptemp;

    apr_pool_create(&ptemp, psec); 
    apr_pool_tag(ptemp, "ptemp");

    if (context->parser->mode != CPARSER_MODE_CONFIG) {
        keyword_c2p(context, SERVER_VERSION, ptemp);
    } else {
        if (is_ascii(*new_string_ptr) != CONV_OK || is_ascii(*old_string_ptr) != CONV_OK) {
            cli_printf_info(context, " configure error; server version keyword cann't contain Chinese characters\n");
            apr_pool_destroy(ptemp);
            return CPARSER_NOT_OK;
        }
        
        keyword_add(context, SERVER_VERSION, NO_TYPE, ptemp, new_string_ptr, old_string_ptr);
    }

    apr_pool_destroy(ptemp);
    return CPARSER_OK;
}

cparser_result_t cparser_cmd_server_version_no_keyword_all(cparser_context_t *context)
{
    return cmd_no_keyword_all(context, SERVER_VERSION, NO_TYPE);
}

cparser_result_t cparser_cmd_server_version_no_keyword_regular_exp_old_string(cparser_context_t *context,
    char **old_string_ptr)
{
    return cmd_no_keyword_plain_text_keyword(context, SERVER_VERSION, NO_TYPE, old_string_ptr);
}

/* 下面三个接口用来配置信用卡信息防护的关键字 */
cparser_result_t cparser_cmd_creditcard_keyword_substitute_plain_text_new_string_for_regular_exp_old_string(cparser_context_t *context,
    char **new_string_ptr,
    char **old_string_ptr)
{
    apr_pool_t *ptemp;

    apr_pool_create(&ptemp, psec); 
    apr_pool_tag(ptemp, "ptemp");

    if (context->parser->mode != CPARSER_MODE_CONFIG) {
        keyword_c2p(context, ICCARD_INFORMATION, ptemp);
    } else {
        if (is_ascii(*old_string_ptr) != CONV_OK || is_ascii(*new_string_ptr) != CONV_OK) {
            cli_printf_info(context, " configure error; creditcard keyword cann't contains Chinese characters\n");
            apr_pool_destroy(ptemp);
            return CPARSER_NOT_OK;
        }
        
        keyword_add(context, ICCARD_INFORMATION, NO_TYPE, ptemp, new_string_ptr, old_string_ptr);
    }

    apr_pool_destroy(ptemp);
    return CPARSER_OK;
}

cparser_result_t cparser_cmd_creditcard_no_keyword_all(cparser_context_t *context)
{
    return cmd_no_keyword_all(context, ICCARD_INFORMATION, NO_TYPE);
}

cparser_result_t cparser_cmd_creditcard_no_keyword_regular_exp_old_string(cparser_context_t *context,
    char **old_string_ptr)
{
    return cmd_no_keyword_plain_text_keyword(context, ICCARD_INFORMATION, NO_TYPE, old_string_ptr);
}

/* 下面三个接口用来配置身份证信息防护的关键字 */
cparser_result_t cparser_cmd_idcard_keyword_substitute_plain_text_new_string_for_regular_exp_old_string(cparser_context_t *context,
    char **new_string_ptr,
    char **old_string_ptr)
{
    apr_pool_t *ptemp;

    apr_pool_create(&ptemp, psec); 
    apr_pool_tag(ptemp, "ptemp");

    if (context->parser->mode != CPARSER_MODE_CONFIG) {
        keyword_c2p(context, IDCARD_INFORMATION, ptemp);
    } else {
        if (is_ascii(*old_string_ptr) != CONV_OK || is_ascii(*new_string_ptr) != CONV_OK) {
            cli_printf_info(context, " configure error; idcard keyword cann't contains Chinese characters\n");
            apr_pool_destroy(ptemp);
            return CPARSER_NOT_OK;
        }
        
        keyword_add(context, IDCARD_INFORMATION, NO_TYPE, ptemp, new_string_ptr, old_string_ptr);
    }

    apr_pool_destroy(ptemp);
    return CPARSER_OK;
}

cparser_result_t cparser_cmd_idcard_no_keyword_all(cparser_context_t *context)
{
    return cmd_no_keyword_all(context, IDCARD_INFORMATION, NO_TYPE);
}

cparser_result_t cparser_cmd_idcard_no_keyword_regular_exp_old_string(cparser_context_t *context,
    char **old_string_ptr)
{
    return cmd_no_keyword_plain_text_keyword(context, IDCARD_INFORMATION, NO_TYPE, old_string_ptr);
}

/* 下面三个接口用来配置文件下载防护的关键字 */
cparser_result_t cparser_cmd_filedown_file_type_plain_text_extension_string(cparser_context_t *context,
    char **extension_string_ptr)
{
    apr_pool_t *ptemp;

    if (context == NULL) {
        return CPARSER_NOT_OK;
    }

    apr_pool_create(&ptemp, psec); 
    apr_pool_tag(ptemp, "ptemp");

    if (context->parser->mode != CPARSER_MODE_CONFIG) {
        keyword_c2p(context, FILE_DOWNLOAD, ptemp);
    } else {
        if (extension_string_ptr == NULL || *extension_string_ptr == NULL) {
            apr_pool_destroy(ptemp);
            return CPARSER_NOT_OK;
        }

        if (is_ascii(*extension_string_ptr) != CONV_OK) {
            cli_printf_info(context, " configure error; file type cann't contains Chinese characters\n");
            apr_pool_destroy(ptemp);
            return CPARSER_NOT_OK;
        }

        keyword_add(context, FILE_DOWNLOAD, NO_TYPE, ptemp, extension_string_ptr, NULL);
    }

    apr_pool_destroy(ptemp);
    return CPARSER_OK;
}

cparser_result_t cparser_cmd_filedown_no_file_type_all(cparser_context_t *context)
{
    return cmd_no_keyword_all(context, FILE_DOWNLOAD, NO_TYPE);
}

cparser_result_t cparser_cmd_filedown_no_file_type_plain_text_extension_string(cparser_context_t *context,
    char **extension_string_ptr)
{
    return cmd_no_keyword_plain_text_keyword(context, FILE_DOWNLOAD, NO_TYPE, extension_string_ptr);
}

/* 下面七个接口用来配置文件上传防护的关键字 */
cparser_result_t cparser_cmd_fileup_file_type_plain_text_extension_string(cparser_context_t *context,
    char **extension_string_ptr)
{
    apr_pool_t *ptemp;

    if (context == NULL) {
        return CPARSER_NOT_OK;
    }

    apr_pool_create(&ptemp, psec); 
    apr_pool_tag(ptemp, "ptemp");

    if (context->parser->mode != CPARSER_MODE_CONFIG) {
        keyword_c2p(context, FILE_UPLOAD, ptemp);
    } else {
        if (is_ascii(*extension_string_ptr) != CONV_OK) {
            cli_printf_info(context, " configure error; file type cann't contains Chinese characters\n");
            apr_pool_destroy(ptemp);
            return CPARSER_NOT_OK;
        }
        
        keyword_add(context, FILE_UPLOAD, FILE_TYPE, ptemp, extension_string_ptr, NULL);
    }

    apr_pool_destroy(ptemp);
    return CPARSER_OK;
}

cparser_result_t cparser_cmd_fileup_no_file_type_all(cparser_context_t *context)
{
    return cmd_no_keyword_all(context, FILE_UPLOAD, FILE_TYPE);
}

cparser_result_t fileup_all_file_size(cparser_context_t *context, uint32_t *number_ptr, int type)
{
    apr_pool_t *ptemp;
    security_policy_t *ring_tmp, *ring_tmp_n;
    keyword_t keyword;
    char **keyword1;
    int rv;
    char buf[COMMAND_LEN_MAX];

    if (context == NULL) {
        return CPARSER_NOT_OK;
    }

    if (context->parser->mode != CPARSER_MODE_CONFIG) {                     
        return CPARSER_OK;
    } else {
        apr_pool_create(&ptemp, psec); 
        apr_pool_tag(ptemp, "ptemp");
        
        keyword.pool = ptemp; 
        keyword.flag = 0;
        strncpy(keyword.sec_policy, (char *)context->cookie[context->parser->root_level], NAME_LEN_MAX);
        keyword.sec_subpolicy = FILE_UPLOAD;
        keyword.type = ALL_FILE_SIZE;

        keyword.keyword = apr_array_make(ptemp, INIT_ARR_LEN, sizeof(char*));  
        keyword1 = (char**)apr_array_push(keyword.keyword);
        
        APR_RING_FOREACH_SAFE(ring_tmp, ring_tmp_n, &sec_policy_ring, security_policy_s, ring) {
            if (strncmp(ring_tmp->name, (char *)context->cookie[context->parser->root_level], NAME_LEN_MAX) == 0) {
                if (number_ptr == NULL) {
                    if (type) {
                        (ring_tmp->fileup_subply).all_file_size = 1;
                        sprintf(buf, "all-file-size");
                    } else {
                        sprintf(buf, "no all-file-size");
                    }
                    
                    *keyword1 = apr_pstrdup(ptemp, apr_ltoa(ptemp, (1 << 20) * 50));  //默认值为50MiB
                } else {
                    if (*number_ptr < 1 || *number_ptr > 100) {
                        cli_printf_info(context, " error, configure file upload all file size range: [1, 100](MiB)\n");
                        return CPARSER_NOT_OK;
                    }
                    
                    (ring_tmp->fileup_subply).all_file_size = 1;
                    *keyword1 = apr_pstrdup(ptemp, apr_ltoa(ptemp, *number_ptr * (1 << 20)));
                    sprintf(buf, "all-file-size %u", *number_ptr);
                }

                break;
            }
        }

        rv = convert_keyword_add(&keyword);
        switch (rv) {
        case CONV_OK:
            admin_log_process(context, buf);
            break;
        case CONV_FAIL:
            cli_printf_info(context, " add keyword failure\n");
            break;
        case CONV_CONFLICT:
            cli_printf_info(context, "add keyword failure, keyword has existed\n");
            break;
        case CONV_EXIST:
            cli_printf_info(context, "add keyword failure, keyword has existed in built-in library\n");
            break;
        default:
            break;
        }
    }

    apr_pool_destroy(ptemp);
    return CPARSER_OK;
}

cparser_result_t fileup_individual_file_size(cparser_context_t *context, uint32_t *number_ptr, int type)
{
    apr_pool_t *ptemp;
    security_policy_t *ring_tmp, *ring_tmp_n;
    keyword_t keyword;
    char **keyword1;
    int rv;
    char buf[COMMAND_LEN_MAX];

    if (context == NULL) {
        return CPARSER_NOT_OK;
    }

    if (context->parser->mode != CPARSER_MODE_CONFIG) {                    
        return CPARSER_OK;
    } else {
        apr_pool_create(&ptemp, psec); 
        apr_pool_tag(ptemp, "ptemp");
        
        keyword.pool = ptemp; 
        keyword.flag = 0;
        strncpy(keyword.sec_policy, (char *)context->cookie[context->parser->root_level], NAME_LEN_MAX);
        keyword.sec_subpolicy = FILE_UPLOAD;
        keyword.type = INDIVIDUAL_FILE_SIZE;

        keyword.keyword = apr_array_make(ptemp, INIT_ARR_LEN, sizeof(char*));  
        keyword1 = (char**)apr_array_push(keyword.keyword);
        
        APR_RING_FOREACH_SAFE(ring_tmp, ring_tmp_n, &sec_policy_ring, security_policy_s, ring) {
            if (strncmp(ring_tmp->name, (char *)context->cookie[context->parser->root_level], NAME_LEN_MAX) == 0) {
                if (number_ptr == NULL) {
                    if (type) {
                        (ring_tmp->fileup_subply).individual_file_size = 1;
                        sprintf(buf, "individual-file-size");
                    } else {
                        sprintf(buf, "no individual-file-size");
                    }

                    *keyword1 = apr_pstrdup(ptemp, apr_ltoa(ptemp, (1 << 20) * 10)); //默认值为10M
                } else {
                    if (*number_ptr < 1 || *number_ptr > 20) {
                        cli_printf_info(context, " error, configure file upload individual file size range: [1, 20](MiB)\n");
                        return CPARSER_NOT_OK;
                    }
                    
                    (ring_tmp->fileup_subply).individual_file_size = 1;
                    *keyword1 = apr_pstrdup(ptemp, apr_ltoa(ptemp, *number_ptr * (1 << 20)));
                    sprintf(buf, "individual-file-size %u", *number_ptr);
                }

                break;
            }
        }

        rv = convert_keyword_add(&keyword);
        switch (rv) {
        case CONV_OK:
            admin_log_process(context, buf);
            break;
        case CONV_FAIL:
            cli_printf_info(context, " add keyword failure\n");
            break;
        case CONV_CONFLICT:
            cli_printf_info(context, "add keyword failure, keyword has existed\n");
            break;
        case CONV_EXIST:
            cli_printf_info(context, "add keyword failure, keyword has existed in built-in library\n");
            break;
        default:
            break;
        }
    }

    apr_pool_destroy(ptemp);
    return CPARSER_OK;
}    

cparser_result_t cparser_cmd_fileup_individual_file_size_number(cparser_context_t *context,
    uint32_t *number_ptr)
{
    return fileup_individual_file_size(context, number_ptr, 1);
}

cparser_result_t cparser_cmd_fileup_all_file_size_number(cparser_context_t *context,
    uint32_t *number_ptr)
{
    return fileup_all_file_size(context, number_ptr, 1);
}

cparser_result_t cparser_cmd_fileup_no_file_type_plain_text_extension_string(cparser_context_t *context,
    char **extension_string_ptr)
{
    return cmd_no_keyword_plain_text_keyword(context, FILE_UPLOAD, FILE_TYPE, extension_string_ptr);
}

cparser_result_t cparser_cmd_fileup_no_individual_file_size(cparser_context_t *context)
{
    return fileup_individual_file_size(context, NULL, 0); 
}

cparser_result_t cparser_cmd_fileup_no_all_file_size(cparser_context_t *context)
{
    return fileup_all_file_size(context, NULL, 0);
}

/* 下面十个接口用来配置cookie防护的关键字 */
cparser_result_t cparser_cmd_cookie_cookie_name_plain_text_extension_string(cparser_context_t *context,
    char **extension_string_ptr)
{
    apr_pool_t *ptemp;

    apr_pool_create(&ptemp, psec); 
    apr_pool_tag(ptemp, "ptemp");

    if (context->parser->mode != CPARSER_MODE_CONFIG) {
        keyword_c2p(context, COOKIE, ptemp);
    } else {
        if (is_ascii(*extension_string_ptr) != CONV_OK) {
            cli_printf_info(context, " configure error; cookie name cann't contains Chinese characters\n");
            apr_pool_destroy(ptemp);
            return CPARSER_NOT_OK;
        }
        
        keyword_add(context, COOKIE, COOKIE_NAME, ptemp, extension_string_ptr, NULL);
    }

    apr_pool_destroy(ptemp);
    return CPARSER_OK;
}

cparser_result_t cparser_cmd_cookie_no_cookie_name_all(cparser_context_t *context)
{
    return cmd_no_keyword_all(context, COOKIE, COOKIE_NAME);
}

cparser_result_t cparser_cmd_cookie_no_cookie_name_plain_text_extension_string(
                    cparser_context_t *context, char **extension_string_ptr)
{
    return cmd_no_keyword_plain_text_keyword(context, COOKIE, COOKIE_NAME, extension_string_ptr);
}

cparser_result_t cparser_cmd_cookie_no_expire_time(cparser_context_t *context)
{
    return cookie_cmd_no_keyword(context, EXPIRE_TIME);
}

cparser_result_t cparser_cmd_cookie_no_verification(cparser_context_t *context)
{
    return cookie_cmd_no_keyword(context, VERIFICATION);
}

cparser_result_t cparser_cmd_cookie_no_attribution(cparser_context_t *context)
{
    return cookie_cmd_no_keyword(context, ATTRIBUTION);
}

cparser_result_t cparser_cmd_cookie_expire_time_minutes(cparser_context_t *context,
    uint32_t *minutes_ptr)
{
    apr_pool_t *ptemp;
    security_policy_t *ring_tmp, *ring_tmp_n;
    keyword_t keyword;
    char **keyword1;
    int rv;
    char buf[COMMAND_LEN_MAX];

    if (context == NULL) {
        return CPARSER_NOT_OK;
    }

    if (context->parser->mode != CPARSER_MODE_CONFIG) {                    
        return CPARSER_OK;
    } else {
        if (minutes_ptr == NULL) {
            return CPARSER_NOT_OK;
        }
        
        if (*minutes_ptr > EXPIRECOOKIE_MAX_TIMEOUT) {
            cli_printf_info(context, "The num is too long,exceed %d minutes.\n", EXPIRECOOKIE_MAX_TIMEOUT);
            return CPARSER_NOT_OK;
        }
        
        apr_pool_create(&ptemp, psec); 
        apr_pool_tag(ptemp, "ptemp");
        
        keyword.pool = ptemp; 
        keyword.flag = 0;
        strncpy(keyword.sec_policy, (char *)context->cookie[context->parser->root_level], NAME_LEN_MAX);
        keyword.sec_subpolicy = COOKIE;
        keyword.type = EXPIRE_TIME;

        keyword.keyword = apr_array_make(ptemp, INIT_ARR_LEN, sizeof(char*));  
        keyword1 = (char**)apr_array_push(keyword.keyword);
        
        APR_RING_FOREACH_SAFE(ring_tmp, ring_tmp_n, &sec_policy_ring, security_policy_s, ring) {
            if (strncmp(ring_tmp->name, (char *)context->cookie[context->parser->root_level], NAME_LEN_MAX) == 0) {
                (ring_tmp->cookie_subply).expire_time = 1;
                *keyword1 = apr_pstrdup(ptemp, apr_itoa(ptemp, *minutes_ptr));
                sprintf(buf, "expire-time %d", *minutes_ptr);
                break;
            }
        }

        rv = convert_keyword_add(&keyword);
        switch (rv) {
        case CONV_OK:
            admin_log_process(context, buf);
            break;
        case CONV_FAIL:
            cli_printf_info(context, " add keyword failure\n");
            break;
        case CONV_CONFLICT:
            cli_printf_info(context, "add keyword failure, keyword has existed\n");
            break;
        case CONV_EXIST:
            cli_printf_info(context, "add keyword failure, keyword has existed in built-in library\n");
            break;
        default:
            break;
        }
    }

    apr_pool_destroy(ptemp);
    return CPARSER_OK;
}

cparser_result_t cparser_cmd_cookie_verification_method_method_content_type(cparser_context_t *context,
    char **method_ptr,
    char **type_ptr)
{
    apr_pool_t *ptemp;
    security_policy_t *ring_tmp, *ring_tmp_n;
    keyword_t keyword;
    char **keyword1, **keyword2;
    int rv;
    char buf[COMMAND_LEN_MAX];

    if (context == NULL) {
        return CPARSER_NOT_OK;
    }

    if (context->parser->mode != CPARSER_MODE_CONFIG) {                    
        return CPARSER_OK;
    } else {
        apr_pool_create(&ptemp, psec); 
        apr_pool_tag(ptemp, "ptemp");
        
        keyword.pool = ptemp; 
        keyword.flag = 0;
        strncpy(keyword.sec_policy, (char *)context->cookie[context->parser->root_level], NAME_LEN_MAX);
        keyword.sec_subpolicy = COOKIE;
        keyword.type =VERIFICATION;

        keyword.keyword = apr_array_make(ptemp, INIT_ARR_LEN, sizeof(char*));  
        keyword1 = (char**)apr_array_push(keyword.keyword);
        keyword2 = (char**)apr_array_push(keyword.keyword);

        APR_RING_FOREACH_SAFE(ring_tmp, ring_tmp_n, &sec_policy_ring, security_policy_s, ring) {
            if (strncmp(ring_tmp->name, (char *)context->cookie[context->parser->root_level], NAME_LEN_MAX) == 0) {
                (ring_tmp->cookie_subply).verification_mothed = 1;

                if (strcmp(*method_ptr, "signature") == 0) {
                    *keyword1 = apr_pstrdup(ptemp, apr_itoa(ptemp, SIGNATURE));
                    sprintf(buf, "verification method signature");
                } else {
                    *keyword1 = apr_pstrdup(ptemp, apr_itoa(ptemp, ENCRYPTION));
                    sprintf(buf, "verification method encryption");
                }

                if (strcmp(*type_ptr, "cookie") == 0) {
                    *keyword2 = apr_pstrdup(ptemp, apr_itoa(ptemp, COOKIE_VERTFICATION));
                    strcat(buf, "content cookie");
                } else {
                    *keyword2 = apr_pstrdup(ptemp, apr_itoa(ptemp, IP_AND_COOKIE));
                    strcat(buf, "content ip-and-cookie");
                } 

                break;
            }
        }

        rv = convert_keyword_add(&keyword);
        switch (rv) {
        case CONV_OK:
            admin_log_process(context, buf);
            break;
        case CONV_FAIL:
            cli_printf_info(context, " add keyword failure\n");
            break;
        case CONV_CONFLICT:
            cli_printf_info(context, "add keyword failure, keyword has existed\n");
            break;
        case CONV_EXIST:
            cli_printf_info(context, "add keyword failure, keyword has existed in built-in library\n");
            break;
        default:
            break;
        }
    }

    apr_pool_destroy(ptemp);
    return CPARSER_OK;
}

/* 为设置cookie属性值提供共同接口 */
cparser_result_t cparser_cmd_cookie_attribution_attr(cparser_context_t *context,
    char **attr_ptr)
{
    apr_pool_t *ptemp;
    security_policy_t *ring_tmp, *ring_tmp_n;
    keyword_t keyword;
    char **keyword1;
    int rv;
    char buf[COMMAND_LEN_MAX];

    if (context == NULL) {
        return CPARSER_NOT_OK;
    }

    if (context->parser->mode != CPARSER_MODE_CONFIG) {                    
        return CPARSER_OK;
    } else {
        apr_pool_create(&ptemp, psec); 
        apr_pool_tag(ptemp, "ptemp");
        
        keyword.pool = ptemp; 
        keyword.flag = 0;
        strncpy(keyword.sec_policy, (char *)context->cookie[context->parser->root_level], NAME_LEN_MAX);
        keyword.sec_subpolicy = COOKIE;
        keyword.type =ATTRIBUTION;

        keyword.keyword = apr_array_make(ptemp, INIT_ARR_LEN, sizeof(char*));  
        keyword1 = (char**)apr_array_push(keyword.keyword);

        APR_RING_FOREACH_SAFE(ring_tmp, ring_tmp_n, &sec_policy_ring, security_policy_s, ring) {
            if (strncmp(ring_tmp->name, (char *)context->cookie[context->parser->root_level], NAME_LEN_MAX) == 0) {
                (ring_tmp->cookie_subply).attribution = 1;

                if (strcmp(*attr_ptr, "secure") == 0) {
                    *keyword1 = apr_pstrdup(ptemp, apr_itoa(ptemp, SECURE));
                    sprintf(buf, "attribution secure");
                } else if (strcmp(*attr_ptr, "httponly") == 0){
                    *keyword1 = apr_pstrdup(ptemp, apr_itoa(ptemp, HTTPDONLY));
                    sprintf(buf, "attribution httponly");
                } else {
                    *keyword1 = apr_pstrdup(ptemp, apr_itoa(ptemp, SECURE_HTTPONLY));
                    sprintf(buf, "attribution secure httponly");
                }

                break;
            }
        }

        rv = convert_keyword_add(&keyword);
        switch (rv) {
        case CONV_OK:
            admin_log_process(context, buf);
            break;
        case CONV_FAIL:
            cli_printf_info(context, " add keyword failure\n");
            break;
        case CONV_CONFLICT:
            cli_printf_info(context, "add keyword failure, keyword has existed\n");
            break;
        case CONV_EXIST:
            cli_printf_info(context, "add keyword failure, keyword has existed in built-in library\n");
            break;
        default:
            break;
        }
    }

    apr_pool_destroy(ptemp);
    return CPARSER_OK;
}

cparser_result_t cparser_cmd_cookie_attribution_httponly(cparser_context_t *context)
{
    apr_pool_t *ptemp;
    char *str;
    int rv;

    apr_pool_create(&ptemp, psec); 
    apr_pool_tag(ptemp, "ptemp");
    
    str = apr_pstrdup(ptemp, "httponly");    
    rv = cparser_cmd_cookie_attribution_attr(context, &str);
    apr_pool_destroy(ptemp);

    return rv;
}

cparser_result_t cparser_cmd_cookie_attribution_secure(cparser_context_t *context)
{
    apr_pool_t *ptemp;
    char *str;
    int rv;

    apr_pool_create(&ptemp, psec); 
    apr_pool_tag(ptemp, "ptemp");
    
    str = apr_pstrdup(ptemp, "secure");    
    rv = cparser_cmd_cookie_attribution_attr(context, &str);
    apr_pool_destroy(ptemp);

    return rv;
}

cparser_result_t cparser_cmd_cookie_attribution_secure_httponly(cparser_context_t *context)
{
    apr_pool_t *ptemp;
    char *str;
    int rv;

    apr_pool_create(&ptemp, psec); 
    apr_pool_tag(ptemp, "ptemp");
    
    str = apr_pstrdup(ptemp, "secure_httponly");    
    rv = cparser_cmd_cookie_attribution_attr(context, &str);
    apr_pool_destroy(ptemp);

    return rv;
}

cparser_result_t protocol_request_header_num(cparser_context_t *context, uint32_t *number_ptr, int type)
{
    apr_pool_t *ptemp;
    security_policy_t *ring_tmp, *ring_tmp_n;
    keyword_t keyword;
    char **keyword1;
    int rv;
    char buf[COMMAND_LEN_MAX];

    if (context == NULL) {
        return CPARSER_NOT_OK;
    }

    apr_pool_create(&ptemp, psec); 
    apr_pool_tag(ptemp, "ptemp");
    
    if (context->parser->mode != CPARSER_MODE_CONFIG) {
        keyword_c2p(context, PROTOCOL_PARAM, ptemp);
        apr_pool_destroy(ptemp);
        return CPARSER_OK;
    } else {       
        keyword.pool = ptemp; 
        keyword.flag = 0;
        strncpy(keyword.sec_policy, (char *)context->cookie[context->parser->root_level], NAME_LEN_MAX);
        keyword.sec_subpolicy = PROTOCOL_PARAM;
        keyword.type = REQUEST_HEADER_NUM;

        keyword.keyword = apr_array_make(ptemp, INIT_ARR_LEN, sizeof(char*));  
        keyword1 = (char**)apr_array_push(keyword.keyword);
        
        APR_RING_FOREACH_SAFE(ring_tmp, ring_tmp_n, &sec_policy_ring, security_policy_s, ring) {
            if (strncmp(ring_tmp->name, (char *)context->cookie[context->parser->root_level], NAME_LEN_MAX) == 0) {
                if (number_ptr == NULL) {
                    if (type) {
                        (ring_tmp->protocol_subply).request_header_num = 1;
                        sprintf(buf, "request-header-num"); 
                    } else {
                        sprintf(buf, "no request-header-num");
                    }

                    *keyword1 = apr_pstrdup(ptemp, apr_itoa(ptemp, 20));
                } else {
                    if (*number_ptr < 1 || *number_ptr > 65535) {
                         cli_printf_info(context, "error, configure request header num range is [1, 65535]\n");
                         return CPARSER_NOT_OK;
                    }
                    
                    (ring_tmp->protocol_subply).request_header_num = 1;
                    *keyword1 = apr_pstrdup(ptemp, apr_itoa(ptemp, *number_ptr));
                    sprintf(buf, "request-header-num %u", *number_ptr);
                }

                break;
            }
        }

        rv = convert_keyword_add(&keyword);
        switch (rv) {
        case CONV_OK:
            admin_log_process(context, buf);
            break;
        case CONV_FAIL:
            cli_printf_info(context, "add keyword failure\n");
            break;
        case CONV_CONFLICT:
            cli_printf_info(context, "add keyword failure, keyword has existed\n");
            break;
        case CONV_EXIST:
            cli_printf_info(context, "add keyword failure, keyword has existed in built-in library\n");
            break;
        default:
            break;
        }
    }

    apr_pool_destroy(ptemp);
    return CPARSER_OK;
}

/* 下面十九个接口用来配置协议参数防护的关键字 */
cparser_result_t cparser_cmd_protocol_request_header_num_number(cparser_context_t *context,
    uint32_t *number_ptr)
{
    return protocol_request_header_num(context, number_ptr, 1);
}

cparser_result_t cparser_cmd_protocol_request_header_num(cparser_context_t *context)
{
    if (context->parser->mode != CPARSER_MODE_CONFIG) {
        return CPARSER_OK;
    }

    return protocol_request_header_num(context, NULL, 1);
}

cparser_result_t protocol_header_size_except_cookie(cparser_context_t *context, uint32_t *number_ptr, 
                    int type)
{
    apr_pool_t *ptemp;
    security_policy_t *ring_tmp, *ring_tmp_n;
    keyword_t keyword;
    char **keyword1;
    int rv;
    char buf[COMMAND_LEN_MAX];

    if (context == NULL) {
        return CPARSER_NOT_OK;
    }
    
    if (context->parser->mode != CPARSER_MODE_CONFIG) {
        return CPARSER_OK;
    } else {
        apr_pool_create(&ptemp, psec); 
        apr_pool_tag(ptemp, "ptemp");
        
        keyword.pool = ptemp; 
        keyword.flag = 0;
        strncpy(keyword.sec_policy, (char *)context->cookie[context->parser->root_level], NAME_LEN_MAX);
        keyword.sec_subpolicy = PROTOCOL_PARAM;
        keyword.type = HEADER_SIZE_EXCEPT_COOKIE;

        keyword.keyword = apr_array_make(ptemp, INIT_ARR_LEN, sizeof(char*));  
        keyword1 = (char**)apr_array_push(keyword.keyword);
        
        APR_RING_FOREACH_SAFE(ring_tmp, ring_tmp_n, &sec_policy_ring, security_policy_s, ring) {
            if (strncmp(ring_tmp->name, (char *)context->cookie[context->parser->root_level], NAME_LEN_MAX) == 0) {
                if (number_ptr == NULL) {
                    if (type) {
                        (ring_tmp->protocol_subply).header_size_except_cookie = 1;
                        sprintf(buf, "header-size-except-cookie");
                    } else {
                        sprintf(buf, "no header-size-except-cookie");
                    }

                    *keyword1 = apr_pstrdup(ptemp, apr_itoa(ptemp, 4096));
                } else {
                    if (*number_ptr < 1 || *number_ptr > 65535) {
                         cli_printf_info(context, "error, configure protocol header size except cookie range is [1, 65535]byte\n");
                         return CPARSER_NOT_OK;
                    }
                    
                    (ring_tmp->protocol_subply).header_size_except_cookie = 1;
                    *keyword1 = apr_pstrdup(ptemp, apr_itoa(ptemp, *number_ptr));
                    sprintf(buf, "header-size-except-cookie %u", *number_ptr);
                }

                break;
            }
        }

        rv = convert_keyword_add(&keyword);
        switch (rv) {
        case CONV_OK:
            admin_log_process(context, buf);
            break;
        case CONV_FAIL:
            cli_printf_info(context, " add keyword failure\n");
            break;
        case CONV_CONFLICT:
            cli_printf_info(context, "add keyword failure, keyword has existed\n");
            break;
        case CONV_EXIST:
            cli_printf_info(context, "add keyword failure, keyword has existed in built-in library\n");
            break;
        default:
            break;
        }
    }

    apr_pool_destroy(ptemp);
    return CPARSER_OK;
}

cparser_result_t cparser_cmd_protocol_header_size_except_cookie_number(cparser_context_t *context,
    uint32_t *number_ptr)
{
    return protocol_header_size_except_cookie(context, number_ptr, 1);
}

cparser_result_t protocol_cookie_size(cparser_context_t *context, uint32_t *number_ptr, int type)
{
    apr_pool_t *ptemp;
    security_policy_t *ring_tmp, *ring_tmp_n;
    keyword_t keyword;
    char **keyword1;
    int rv;
    char buf[COMMAND_LEN_MAX];

    if (context == NULL) {
        return CPARSER_NOT_OK;
    }
    
    if (context->parser->mode != CPARSER_MODE_CONFIG) {
        return CPARSER_OK;
    } else {
        apr_pool_create(&ptemp, psec); 
        apr_pool_tag(ptemp, "ptemp");
        
        keyword.pool = ptemp; 
        keyword.flag = 0;
        strncpy(keyword.sec_policy, (char *)context->cookie[context->parser->root_level], NAME_LEN_MAX);
        keyword.sec_subpolicy = PROTOCOL_PARAM;
        keyword.type = COOKIE_SIZE;

        keyword.keyword = apr_array_make(ptemp, INIT_ARR_LEN, sizeof(char*));  
        keyword1 = (char**)apr_array_push(keyword.keyword);
        
        APR_RING_FOREACH_SAFE(ring_tmp, ring_tmp_n, &sec_policy_ring, security_policy_s, ring) {
            if (strncmp(ring_tmp->name, (char *)context->cookie[context->parser->root_level], NAME_LEN_MAX) == 0) {
                if (number_ptr == NULL) {
                    if (type) {
                        (ring_tmp->protocol_subply).cookie_size = 1;
                        sprintf(buf, "cookie-size");
                    } else {
                        sprintf(buf, "no cookie-size");
                    }

                    *keyword1 = apr_pstrdup(ptemp, apr_itoa(ptemp, 4096));
                } else {
                    if (*number_ptr < 1 || *number_ptr > 65535) {
                         cli_printf_info(context, "error, configure protocol cookie size range is [1, 65535]byte\n");
                         return CPARSER_NOT_OK;
                    }
                    
                    (ring_tmp->protocol_subply).cookie_size = 1;
                    *keyword1 = apr_pstrdup(ptemp, apr_itoa(ptemp, *number_ptr));
                    sprintf(buf, "cookie-size %u", *number_ptr);
                }

                break;
            }
        }

        rv = convert_keyword_add(&keyword);
        switch (rv) {
        case CONV_OK:
            admin_log_process(context, buf);
            break;
        case CONV_FAIL:
            cli_printf_info(context, " add keyword failure\n");
            break;
        case CONV_CONFLICT:
            cli_printf_info(context, "add keyword failure, keyword has existed\n");
            break;
        case CONV_EXIST:
            cli_printf_info(context, "add keyword failure, keyword has existed in built-in library\n");
            break;
        default:
            break;
        }
    }

    apr_pool_destroy(ptemp);
    return CPARSER_OK;
}

cparser_result_t cparser_cmd_protocol_cookie_size_number(cparser_context_t *context,
    uint32_t *number_ptr)
{
    return protocol_cookie_size(context, number_ptr, 1);
}

cparser_result_t protocol_request_url_size(cparser_context_t *context, uint32_t *number_ptr, int type)
{
    apr_pool_t *ptemp;
    security_policy_t *ring_tmp, *ring_tmp_n;
    keyword_t keyword;
    char **keyword1;
    int rv;
    char buf[COMMAND_LEN_MAX];

    if (context == NULL) {
        return CPARSER_NOT_OK;
    }
    
    if (context->parser->mode != CPARSER_MODE_CONFIG) {
        return CPARSER_OK;
    } else {
        apr_pool_create(&ptemp, psec); 
        apr_pool_tag(ptemp, "ptemp");
        
        keyword.pool = ptemp; 
        keyword.flag = 0;
        strncpy(keyword.sec_policy, (char *)context->cookie[context->parser->root_level], NAME_LEN_MAX);
        keyword.sec_subpolicy = PROTOCOL_PARAM;
        keyword.type = REQUEST_URL_SIZE;

        keyword.keyword = apr_array_make(ptemp, INIT_ARR_LEN, sizeof(char*));  
        keyword1 = (char**)apr_array_push(keyword.keyword);
        
        APR_RING_FOREACH_SAFE(ring_tmp, ring_tmp_n, &sec_policy_ring, security_policy_s, ring) {
            if (strncmp(ring_tmp->name, (char *)context->cookie[context->parser->root_level], NAME_LEN_MAX) == 0) {
                if (number_ptr == NULL) {
                    if (type) {
                        (ring_tmp->protocol_subply).request_url_size = 1;
                        sprintf(buf, "request-url-size");
                    } else {
                        sprintf(buf, "no request-url-size");
                    }
                    
                    *keyword1 = apr_pstrdup(ptemp, apr_itoa(ptemp, 5120));
                } else {
                    if (*number_ptr < 1 || *number_ptr > 65535) {
                         cli_printf_info(context, "error, configure protocol request url size range is [1, 65535]byte\n");
                         return CPARSER_NOT_OK;
                    }

                    (ring_tmp->protocol_subply).request_url_size = 1;
                    *keyword1 = apr_pstrdup(ptemp, apr_itoa(ptemp, *number_ptr));
                    sprintf(buf, "request-url-size %u", *number_ptr);
                }

                break;
            }
        }

        rv = convert_keyword_add(&keyword);
        switch (rv) {
        case CONV_OK:
            admin_log_process(context, buf);
            break;
        case CONV_FAIL:
            cli_printf_info(context, " add keyword failure\n");
            break;
        case CONV_CONFLICT:
            cli_printf_info(context, "add keyword failure, keyword has existed\n");
            break;
        case CONV_EXIST:
            cli_printf_info(context, "add keyword failure, keyword has existed in built-in library\n");
            break;
        default:
            break;
        }
    }

    apr_pool_destroy(ptemp);
    return CPARSER_OK;
}

cparser_result_t cparser_cmd_protocol_request_url_size_number(cparser_context_t *context,
    uint32_t *number_ptr)
{
   return protocol_request_url_size(context, number_ptr, 1);
}

cparser_result_t protocol_query_string_size(cparser_context_t *context, uint32_t *number_ptr, int type)
{
    apr_pool_t *ptemp;
    security_policy_t *ring_tmp, *ring_tmp_n;
    keyword_t keyword;
    char **keyword1;
    int rv;
    char buf[COMMAND_LEN_MAX];

    if (context == NULL) {
        return CPARSER_NOT_OK;
    }
    
    if (context->parser->mode != CPARSER_MODE_CONFIG) {
        return CPARSER_OK;
    } else {
        apr_pool_create(&ptemp, psec); 
        apr_pool_tag(ptemp, "ptemp");
        
        keyword.pool = ptemp; 
        keyword.flag = 0;
        strncpy(keyword.sec_policy, (char *)context->cookie[context->parser->root_level], NAME_LEN_MAX);
        keyword.sec_subpolicy = PROTOCOL_PARAM;
        keyword.type = QUERY_STRING_SIZE;

        keyword.keyword = apr_array_make(ptemp, INIT_ARR_LEN, sizeof(char*));  
        keyword1 = (char**)apr_array_push(keyword.keyword);
        
        APR_RING_FOREACH_SAFE(ring_tmp, ring_tmp_n, &sec_policy_ring, security_policy_s, ring) {
            if (strncmp(ring_tmp->name, (char *)context->cookie[context->parser->root_level], NAME_LEN_MAX) == 0) {
                if (number_ptr == NULL) {
                    if (type) {
                        (ring_tmp->protocol_subply).query_string_size = 1;
                        sprintf(buf, "query-string-size");
                    } else {
                        sprintf(buf, "no query-string-size");
                    }
                    
                    *keyword1 = apr_pstrdup(ptemp, apr_itoa(ptemp, 4096));
                } else {
                    if (*number_ptr < 1 || *number_ptr > 65535) {
                         cli_printf_info(context, "error, configure protocol query string size range is [1, 65535]byte\n");
                         return CPARSER_NOT_OK;
                    }
                    
                    (ring_tmp->protocol_subply).query_string_size = 1;
                    *keyword1 = apr_pstrdup(ptemp, apr_itoa(ptemp, *number_ptr));
                    sprintf(buf, "query-string-size %u", *number_ptr);
                }

                break;
            }
        }

        rv = convert_keyword_add(&keyword);
        switch (rv) {
        case CONV_OK:
            admin_log_process(context, buf);
            break;
        case CONV_FAIL:
            cli_printf_info(context, " add keyword failure\n");
            break;
        case CONV_CONFLICT:
            cli_printf_info(context, "add keyword failure, keyword has existed\n");
            break;
        case CONV_EXIST:
            cli_printf_info(context, "add keyword failure, keyword has existed in built-in library\n");
            break;
        default:
            break;
        }
    }

    apr_pool_destroy(ptemp);
    return CPARSER_OK;
}

cparser_result_t cparser_cmd_protocol_query_string_size_number(cparser_context_t *context,
    uint32_t *number_ptr)
{
    return protocol_query_string_size(context, number_ptr, 1);
}

cparser_result_t protocol_request_argument_name_size(cparser_context_t *context, 
                    uint32_t *number_ptr, int type)
{
    apr_pool_t *ptemp;
    security_policy_t *ring_tmp, *ring_tmp_n;
    keyword_t keyword;
    char **keyword1;
    int rv;
    char buf[COMMAND_LEN_MAX];

    if (context == NULL) {
        return CPARSER_NOT_OK;
    }
    
    if (context->parser->mode != CPARSER_MODE_CONFIG) {
        return CPARSER_OK;
    } else {
        apr_pool_create(&ptemp, psec); 
        apr_pool_tag(ptemp, "ptemp");
        
        keyword.pool = ptemp; 
        keyword.flag = 0;
        strncpy(keyword.sec_policy, (char *)context->cookie[context->parser->root_level], NAME_LEN_MAX);
        keyword.sec_subpolicy = PROTOCOL_PARAM;
        keyword.type = ARGUMENT_NAME_SIZE;

        keyword.keyword = apr_array_make(ptemp, INIT_ARR_LEN, sizeof(char*));  
        keyword1 = (char**)apr_array_push(keyword.keyword);
        
        APR_RING_FOREACH_SAFE(ring_tmp, ring_tmp_n, &sec_policy_ring, security_policy_s, ring) {
            if (strncmp(ring_tmp->name, (char *)context->cookie[context->parser->root_level], NAME_LEN_MAX) == 0) {
                if (number_ptr == NULL) {
                    if (type) {
                        (ring_tmp->protocol_subply).request_argument_name_size = 1;
                        sprintf(buf, "request-argument-name-size");  
                    } else {
                        sprintf(buf, "no request-argument-name-size");
                    }
                    
                    *keyword1 = apr_pstrdup(ptemp, apr_itoa(ptemp, 1024));
                } else {
                    if (*number_ptr < 1 || *number_ptr > 65535) {
                         cli_printf_info(context, "error, configure protocol request argument name size range is [1, 65535]byte\n");
                         return CPARSER_NOT_OK;
                    }
                    
                    (ring_tmp->protocol_subply).request_argument_name_size = 1;
                    *keyword1 = apr_pstrdup(ptemp, apr_itoa(ptemp, *number_ptr));
                    sprintf(buf, "request-argument-name-size %u", *number_ptr);
                }

                break;
            }
        }

        rv = convert_keyword_add(&keyword);
        switch (rv) {
        case CONV_OK:
            admin_log_process(context, buf);
            break;
        case CONV_FAIL:
            cli_printf_info(context, " add keyword failure\n");
            break;
        case CONV_CONFLICT:
            cli_printf_info(context, "add keyword failure, keyword has existed\n");
            break;
        case CONV_EXIST:
            cli_printf_info(context, "add keyword failure, keyword has existed in built-in library\n");
            break;
        default:
            break;
        }
    }

    apr_pool_destroy(ptemp);
    return CPARSER_OK;
}

cparser_result_t cparser_cmd_protocol_request_argument_name_size_number(cparser_context_t *context,
    uint32_t *number_ptr)
{
    return protocol_request_argument_name_size(context, number_ptr, 1);
}

cparser_result_t protocol_request_argument_name_value_size(cparser_context_t *context,
    uint32_t *number_ptr, int type)
{
    apr_pool_t *ptemp;
    security_policy_t *ring_tmp, *ring_tmp_n;
    keyword_t keyword;
    char **keyword1;
    int rv;
    char buf[COMMAND_LEN_MAX];

    if (context == NULL) {
        return CPARSER_NOT_OK;
    }
    
    if (context->parser->mode != CPARSER_MODE_CONFIG) {
        return CPARSER_OK;
    } else {
        apr_pool_create(&ptemp, psec); 
        apr_pool_tag(ptemp, "ptemp");
        
        keyword.pool = ptemp; 
        keyword.flag = 0;
        strncpy(keyword.sec_policy, (char *)context->cookie[context->parser->root_level], NAME_LEN_MAX);
        keyword.sec_subpolicy = PROTOCOL_PARAM;
        keyword.type = ARGUMENT_NAME_VALUE_SIZE;

        keyword.keyword = apr_array_make(ptemp, INIT_ARR_LEN, sizeof(char*));  
        keyword1 = (char**)apr_array_push(keyword.keyword);
        
        APR_RING_FOREACH_SAFE(ring_tmp, ring_tmp_n, &sec_policy_ring, security_policy_s, ring) {
            if (strncmp(ring_tmp->name, (char *)context->cookie[context->parser->root_level], NAME_LEN_MAX) == 0) {
                if (number_ptr == NULL) {
                    if (type) {
                        (ring_tmp->protocol_subply).request_argument_name_value_size = 1;
                        sprintf(buf, "request-argument-name-value-size");
                    } else {
                        sprintf(buf, "no request-argument-name-value-size");
                    }
                    
                    *keyword1 = apr_pstrdup(ptemp, apr_itoa(ptemp, 2048));
                } else {
                    if (*number_ptr < 1 || *number_ptr > 65535) {
                         cli_printf_info(context, "error, configure protocol request argument name value size range is [1, 65535]byte\n");
                         return CPARSER_NOT_OK;
                    }
                    
                    (ring_tmp->protocol_subply).request_argument_name_value_size = 1;
                    *keyword1 = apr_pstrdup(ptemp, apr_itoa(ptemp, *number_ptr));
                    sprintf(buf, "request-argument-name-value-size %u", *number_ptr);
                }

                break;
            }
        }

        rv = convert_keyword_add(&keyword);
        switch (rv) {
        case CONV_OK:
            admin_log_process(context, buf);
            break;
        case CONV_FAIL:
            cli_printf_info(context, " add keyword failure\n");
            break;
        case CONV_CONFLICT:
            cli_printf_info(context, "add keyword failure, keyword has existed\n");
            break;
        case CONV_EXIST:
            cli_printf_info(context, "add keyword failure, keyword has existed in built-in library\n");
            break;
        default:
            break;
        }
    }

    apr_pool_destroy(ptemp);
    return CPARSER_OK;
}    

cparser_result_t cparser_cmd_protocol_request_argument_name_value_size_number(cparser_context_t *context,
    uint32_t *number_ptr)
{
    return protocol_request_argument_name_value_size(context, number_ptr, 1);
}

cparser_result_t protocol_request_argument_num(cparser_context_t *context, uint32_t *number_ptr, 
                    int type)
{
    apr_pool_t *ptemp;
    security_policy_t *ring_tmp, *ring_tmp_n;
    keyword_t keyword;
    char **keyword1;
    int rv;
    char buf[COMMAND_LEN_MAX];

    if (context == NULL) {
        return CPARSER_NOT_OK;
    }
    
    if (context->parser->mode != CPARSER_MODE_CONFIG) {
        return CPARSER_OK;
    } else {
        apr_pool_create(&ptemp, psec); 
        apr_pool_tag(ptemp, "ptemp");
        
        keyword.pool = ptemp; 
        keyword.flag = 0;
        strncpy(keyword.sec_policy, (char *)context->cookie[context->parser->root_level], NAME_LEN_MAX);
        keyword.sec_subpolicy = PROTOCOL_PARAM;
        keyword.type = ARGUMENT_NUM;

        keyword.keyword = apr_array_make(ptemp, INIT_ARR_LEN, sizeof(char*));  
        keyword1 = (char**)apr_array_push(keyword.keyword);
        
        APR_RING_FOREACH_SAFE(ring_tmp, ring_tmp_n, &sec_policy_ring, security_policy_s, ring) {
            if (strncmp(ring_tmp->name, (char *)context->cookie[context->parser->root_level], NAME_LEN_MAX) == 0) {
                if (number_ptr == NULL) {
                    if (type) {
                        (ring_tmp->protocol_subply).request_argument_num = 1;
                        sprintf(buf, "request-argument-num");
                    } else {
                        sprintf(buf, "no request-argument-num");
                    }
                    
                    *keyword1 = apr_pstrdup(ptemp, apr_itoa(ptemp, 1024));
                } else {
                    if (*number_ptr < 1 || *number_ptr > 65535) {
                         cli_printf_info(context, "error, configure protocol request argument num range is [1, 65535]\n");
                         return CPARSER_NOT_OK;
                    }
                    
                    (ring_tmp->protocol_subply).request_argument_num = 1;
                    *keyword1 = apr_pstrdup(ptemp, apr_itoa(ptemp, *number_ptr));
                    sprintf(buf, "request-argument-num %u", *number_ptr);
                }

                break;
            }
        }

        rv = convert_keyword_add(&keyword);
        switch (rv) {
        case CONV_OK:
            admin_log_process(context, buf);
            break;
        case CONV_FAIL:
            cli_printf_info(context, " add keyword failure\n");
            break;
        case CONV_CONFLICT:
            cli_printf_info(context, "add keyword failure, keyword has existed\n");
            break;
        case CONV_EXIST:
            cli_printf_info(context, "add keyword failure, keyword has existed in built-in library\n");
            break;
        default:
            break;
        }
    }

    apr_pool_destroy(ptemp);
    return CPARSER_OK;
}

cparser_result_t cparser_cmd_protocol_request_argument_num_number(cparser_context_t *context,
    uint32_t *number_ptr)
{
    return protocol_request_argument_num(context, number_ptr, 1);
}

cparser_result_t protocol_request_body_size(cparser_context_t *context, uint32_t *number_ptr, 
                    int type)
{
    apr_pool_t *ptemp;
    security_policy_t *ring_tmp, *ring_tmp_n;
    keyword_t keyword;
    char **keyword1;
    int rv;
    char buf[COMMAND_LEN_MAX];

    if (context == NULL) {
        return CPARSER_NOT_OK;
    }
    
    if (context->parser->mode != CPARSER_MODE_CONFIG) {
        return CPARSER_OK;
    } else {
        apr_pool_create(&ptemp, psec); 
        apr_pool_tag(ptemp, "ptemp");
        
        keyword.pool = ptemp; 
        keyword.flag = 0;
        strncpy(keyword.sec_policy, (char *)context->cookie[context->parser->root_level], NAME_LEN_MAX);
        keyword.sec_subpolicy = PROTOCOL_PARAM;
        keyword.type = BODY_SIZE;

        keyword.keyword = apr_array_make(ptemp, INIT_ARR_LEN, sizeof(char*));  
        keyword1 = (char**)apr_array_push(keyword.keyword);
        
        APR_RING_FOREACH_SAFE(ring_tmp, ring_tmp_n, &sec_policy_ring, security_policy_s, ring) {
            if (strncmp(ring_tmp->name, (char *)context->cookie[context->parser->root_level], NAME_LEN_MAX) == 0) {
                if (number_ptr == NULL) {
                    if (type) {
                        (ring_tmp->protocol_subply).request_body_size = 1;
                        sprintf(buf, "request-body-size");
                    } else {
                        sprintf(buf, "no request-body-size");
                    }
                    *keyword1 = apr_pstrdup(ptemp, apr_ltoa(ptemp, 50 * (1 << 20)));
                } else {
                    if (*number_ptr < 1 || *number_ptr > 2000) {
                         cli_printf_info(context, "error, configure protocol request body size range is [1, 2000]MiB\n");
                         return CPARSER_NOT_OK;
                    }
                    
                    (ring_tmp->protocol_subply).request_body_size = 1;
                    *keyword1 = apr_pstrdup(ptemp, apr_ltoa(ptemp, ((unsigned long)(*number_ptr) * (1 << 20))));
                    sprintf(buf, "request-body-size %u", *number_ptr);
                }

                break;
            }
        }

        rv = convert_keyword_add(&keyword);
        switch (rv) {
        case CONV_OK:
            admin_log_process(context, buf);
            break;
        case CONV_FAIL:
            cli_printf_info(context, " add keyword failure\n");
            break;
        case CONV_CONFLICT:
            cli_printf_info(context, "add keyword failure, keyword has existed\n");
            break;
        case CONV_EXIST:
            cli_printf_info(context, "add keyword failure, keyword has existed in built-in library\n");
            break;
        default:
            break;
        }
    }

    apr_pool_destroy(ptemp);
    return CPARSER_OK;
}

cparser_result_t cparser_cmd_protocol_request_body_size_number(cparser_context_t *context,
    uint32_t *number_ptr)
{
    return protocol_request_body_size(context, number_ptr, 1);
}

cparser_result_t cparser_cmd_protocol_no_request_header_num(cparser_context_t *context)
{
    if (context->parser->mode != CPARSER_MODE_CONFIG) {
        return CPARSER_OK;
    } else {
        return protocol_request_header_num(context, NULL, 0);
    }
}

cparser_result_t cparser_cmd_protocol_no_header_size_except_cookie(cparser_context_t *context)
{
    return protocol_header_size_except_cookie(context, NULL, 0);
}

cparser_result_t cparser_cmd_protocol_no_cookie_size(cparser_context_t *context)
{
    return protocol_cookie_size(context, NULL, 0);
}

cparser_result_t cparser_cmd_protocol_no_request_url_size(cparser_context_t *context)
{
    return protocol_request_url_size(context, NULL, 0);
}

cparser_result_t cparser_cmd_protocol_no_query_string_size(cparser_context_t *context)
{
   return protocol_query_string_size(context, NULL, 0);
}

cparser_result_t cparser_cmd_protocol_no_request_argument_name_size(cparser_context_t *context)
{
    return protocol_request_argument_name_size(context, NULL, 0);
}

cparser_result_t cparser_cmd_protocol_no_request_argument_name_value_size(cparser_context_t *context)
{
    return protocol_request_argument_name_value_size(context, NULL, 0);
}

cparser_result_t cparser_cmd_protocol_no_request_argument_num(cparser_context_t *context)
{
    return protocol_request_argument_num(context, NULL, 0);
}

cparser_result_t cparser_cmd_protocol_no_request_body_size(cparser_context_t *context)
{
    return protocol_request_body_size(context, NULL, 0);
}

/* 下面三个接口用来配置协议参数防护的关键字 */
cparser_result_t cparser_cmd_method_method_plain_text_method(cparser_context_t *context,
    char **method_ptr)
{
    apr_pool_t *ptemp;

    if (context == NULL) {
        return CPARSER_NOT_OK;
    }

    apr_pool_create(&ptemp, psec); 
    apr_pool_tag(ptemp, "ptemp");

    if (context->parser->mode != CPARSER_MODE_CONFIG) {
        keyword_c2p(context, REQUEST_METHOD, ptemp);
    } else {
        if (method_ptr == NULL || *method_ptr == NULL) {
            apr_pool_destroy(ptemp);
            return CPARSER_NOT_OK;
        }   

        if (is_ascii(*method_ptr) != CONV_OK) {
            cli_printf_info(context, " configure error; request method cann't contains Chinese characters\n");
            apr_pool_destroy(ptemp);
            return CPARSER_NOT_OK;
        }
        
        keyword_add(context, REQUEST_METHOD, NO_TYPE, ptemp, method_ptr, NULL);
    }

    apr_pool_destroy(ptemp);
    return CPARSER_OK;
}

cparser_result_t cparser_cmd_method_no_method_all(cparser_context_t *context)
{
    return cmd_no_keyword_all(context, REQUEST_METHOD, NO_TYPE);
}

cparser_result_t cparser_cmd_method_no_method_plain_text_method(cparser_context_t *context,
    char **method_ptr)
{
    return cmd_no_keyword_plain_text_keyword(context, REQUEST_METHOD, NO_TYPE, method_ptr);
}

/* 下面三个接口用来配置关键字过滤的关键字 */
cparser_result_t cparser_cmd_keyword_filter_keyword_plain_text_keyword(cparser_context_t *context,
    char **keyword_ptr)
{
    apr_pool_t *ptemp;

    if (context == NULL) {
        return CPARSER_NOT_OK;
    }

    apr_pool_create(&ptemp, psec); 
    apr_pool_tag(ptemp, "ptemp");

    if (context->parser->mode != CPARSER_MODE_CONFIG) {
        keyword_c2p(context, KEYWORD_FILTER, ptemp);
        apr_pool_destroy(ptemp);                     
        return CPARSER_OK;
    } else {
        if (keyword_ptr == NULL || *keyword_ptr == NULL) {
            apr_pool_destroy(ptemp);
            return CPARSER_NOT_OK;
        }   

        keyword_add(context, KEYWORD_FILTER, NO_TYPE, ptemp, keyword_ptr, NULL);
    }

    apr_pool_destroy(ptemp);
    return CPARSER_OK;
}

cparser_result_t cparser_cmd_keyword_filter_no_keyword_all(cparser_context_t *context)
{
   return cmd_no_keyword_all(context, KEYWORD_FILTER, NO_TYPE);
}

cparser_result_t cparser_cmd_keyword_filter_no_keyword_plain_text_keyword(cparser_context_t *context,
    char **keyword_ptr)
{
    return cmd_no_keyword_plain_text_keyword(context, KEYWORD_FILTER, NO_TYPE, keyword_ptr);
}

/* 下面十一个接口用来配置cc防护的关键字 */
cparser_result_t cparser_cmd_cc_no_source_ip_access_rate(cparser_context_t *context)
{
    if (context->parser->mode != CPARSER_MODE_CONFIG) {
        return CPARSER_OK;
    }
    
    return cc_cmd_set_source_ip_keyword(context, NULL, NULL ,0);
}

cparser_result_t cparser_cmd_cc_no_source_ip_status_408_rate(cparser_context_t *context)
{
    if (context->parser->mode != CPARSER_MODE_CONFIG) {
        return CPARSER_OK;
    }
    
    return cc_cmd_set_status_408_rate_keyword(context, NULL, NULL ,0);
}

cparser_result_t cparser_cmd_cc_no_referrer_url_access_rate(cparser_context_t *context)
{
    if (context->parser->mode != CPARSER_MODE_CONFIG) {
        return CPARSER_OK;
    }
    
    return cc_cmd_set_referrer_url_keyword(context, NULL, NULL ,0);
}

cparser_result_t cparser_cmd_cc_source_ip_access_rate_statistic_cycle_seconds_request_times_times(cparser_context_t *context,
    uint32_t *seconds_ptr,
    uint32_t *times_ptr)
{
    apr_pool_t *ptemp;
    char sec_policy_name[NAME_LEN_MAX];
    int type;
    apr_array_header_t *k, *result;
    keyword_t **kw, *kw_sub;
    int i;

    apr_pool_create(&ptemp, psec); 
    apr_pool_tag(ptemp, "ptemp");
    
    if (context->parser->mode != CPARSER_MODE_CONFIG) {
        strncpy(sec_policy_name, (char *)context->cookie[context->parser->root_level], NAME_LEN_MAX);
        result = apr_array_make(ptemp, 10, sizeof(keyword_t*));
        convert_sec_policy_list(sec_policy_name, CC_PROTECT, &result);
        kw = (keyword_t**)result->elts;

        for (i = 0; i < result->nelts; i++) {
            kw_sub = kw[i];
            k = kw_sub->keyword;
            type = kw_sub->type;
            if (kw_sub->flag == OUTER_KEYWORD) {
                cc_by_type(type, k, context);
            }
        }

        apr_pool_destroy(ptemp);                     
        return CPARSER_OK;
    } else {
        if (*seconds_ptr < 1 ) {
            cli_printf_info(context, "error, configure cycle seconds range is [1, (1 << 32) - 1]\n");
            return CPARSER_NOT_OK;
        }

        if (*times_ptr < 1) {
            cli_printf_info(context, "error, configure request times range is [1, (1 << 32) - 1]\n");
            return CPARSER_NOT_OK;
        }
        
        return cc_cmd_set_source_ip_keyword(context, seconds_ptr, times_ptr, 1);
    }
}

cparser_result_t cparser_cmd_cc_source_ip_status_408_rate_statistic_cycle_seconds_response_times_times(cparser_context_t *context,
    uint32_t *seconds_ptr,
    uint32_t *times_ptr)
{
    if (context->parser->mode != CPARSER_MODE_CONFIG) {
        return CPARSER_OK;
    } else {
        if (*seconds_ptr < 1) {
                cli_printf_info(context, "error, configure cycle seconds range is [1, (1 << 32) - 1]\n");
                return CPARSER_NOT_OK;
        }

        if (*times_ptr < 1) {
            cli_printf_info(context, "error, configure request times range is [1, (1 << 32) - 1]\n");
            return CPARSER_NOT_OK;
        }

        return cc_cmd_set_status_408_rate_keyword(context, seconds_ptr, times_ptr, 1);
    }
}

cparser_result_t cparser_cmd_cc_referrer_url_access_rate_statistic_cycle_seconds_request_times_times(cparser_context_t *context,
    uint32_t *seconds_ptr,
    uint32_t *times_ptr)
{
    if (context->parser->mode != CPARSER_MODE_CONFIG) {
        return CPARSER_OK;
    } else {
        if (*seconds_ptr < 1) {
                cli_printf_info(context, "error, configure cycle seconds range is [1, (1 << 32) - 1]\n");
                return CPARSER_NOT_OK;
        }

        if (*times_ptr < 1) {
            cli_printf_info(context, "error, configure request times range is [1, (1 << 32) - 1]\n");
            return CPARSER_NOT_OK;
        }
        
        return cc_cmd_set_referrer_url_keyword(context, seconds_ptr, times_ptr, 1);
    }
}

cparser_result_t cparser_cmd_cc_url_access_rate_statistic_cycle_seconds_request_times_times(cparser_context_t *context,
    uint32_t *seconds_ptr,
    uint32_t *times_ptr)
{
    apr_pool_t *ptemp;
    char sec_policy_name[NAME_LEN_MAX];
    int type;
    apr_array_header_t *k, *result;
    keyword_t **kw, *kw_sub;
    int i;

    apr_pool_create(&ptemp, psec); 
    apr_pool_tag(ptemp, "ptemp");
    
    if (context->parser->mode != CPARSER_MODE_CONFIG) {
        strncpy(sec_policy_name, (char *)context->cookie[context->parser->root_level], NAME_LEN_MAX);
        result = apr_array_make(ptemp, 10, sizeof(keyword_t*));
        convert_sec_policy_list(sec_policy_name, CC_PROTECT, &result);
        kw = (keyword_t**)result->elts;
        for (i = 0; i < result->nelts; i++) {
            kw_sub = kw[i];
            k = kw_sub->keyword;
            type = kw_sub->type;
            if (kw_sub->flag == OUTER_KEYWORD) {
                cc_url_by_type(type, k, context);
            }
        }

        return CPARSER_OK;
    } else {
        if (*seconds_ptr < 1) {
            cli_printf_info(context, "error, configure cycle seconds range is [1, (1 << 32) - 1]\n");
            return CPARSER_NOT_OK;
        }

        if (*times_ptr < 1) {
            cli_printf_info(context, "error, configure request times range is [1, (1 << 32) - 1]\n");
            return CPARSER_NOT_OK;
        }
        
        return cc_cmd_set_url_access_rate_keyword(context, seconds_ptr, times_ptr, 1);
    }
}

cparser_result_t cparser_cmd_cc_url_no_access_rate_statistic_cycle(cparser_context_t *context)
{
    if (context->parser->mode != CPARSER_MODE_CONFIG) {
        return CPARSER_OK;
    }
    
    return cc_cmd_set_url_access_rate_keyword(context, NULL, NULL, 0);
}

cparser_result_t cparser_cmd_cc_url_no_url_all(cparser_context_t *context)
{
    return cmd_no_keyword_all(context, CC_PROTECT, CC_KEYWORD_ALL);
}

cparser_result_t cparser_cmd_cc_url_no_url_type_url_string(cparser_context_t *context,
                    char **type_ptr, char **url_string_ptr)
{
    apr_pool_t *ptemp;
    char sec_policy_name[NAME_LEN_MAX];
    keyword_t keyword;
    char **keyword1;
    int rv;
    char buf[COMMAND_LEN_MAX];

    if (context->parser->mode != CPARSER_MODE_CONFIG) {
        return CPARSER_OK;
    } else {
        apr_pool_create(&ptemp, psec); 
        apr_pool_tag(ptemp, "ptemp");
        
        strncpy(sec_policy_name, (char *)context->cookie[context->parser->root_level], NAME_LEN_MAX);
    
        keyword.pool = ptemp; 
        strncpy(keyword.sec_policy, sec_policy_name, NAME_LEN_MAX);
        keyword.sec_subpolicy = CC_PROTECT;
        keyword.flag = 0;

        if (strcmp(*type_ptr, "plain-text") == 0) {
            keyword.type = CC_PLAIN_URL;
        } else {
            keyword.type = CC_REGEX_URL;
        }

        keyword.keyword = apr_array_make(ptemp, INIT_ARR_LEN, sizeof(char*));
        keyword1 = (char**)apr_array_push(keyword.keyword);
        *keyword1 = apr_pstrdup(ptemp, *url_string_ptr);

        sprintf(buf, "no url %s %s", *type_ptr, *url_string_ptr);

        rv = convert_keyword_del(&keyword);
        switch (rv) {
        case CONV_OK:
            admin_log_process(context, buf);
            break;
        case CONV_FAIL:
            cli_printf_info(context, "del keyword failure\n");
            break;
        case CONV_NOTEXIST:
            cli_printf_info(context, "del keyword failure, keyword hasn't existed\n");
            break;
        default:
            break;
        }
    }

    apr_pool_destroy(ptemp);
    return CPARSER_OK;
}

cparser_result_t cparser_cmd_cc_url_url_type_url_string(cparser_context_t *context,
    char **type_ptr,
    char **url_string_ptr)
{
    apr_pool_t *ptemp;
    char sec_policy_name[NAME_LEN_MAX];
    keyword_t keyword;
    char **keyword1;
    int rv;
    char buf[COMMAND_LEN_MAX];

    if (context->parser->mode != CPARSER_MODE_CONFIG) {
        return CPARSER_OK;
    } else {
        if (is_ascii(*url_string_ptr) != CONV_OK) {
            cli_printf_info(context, " configure error; url page keyword cann't contains Chinese characters\n");
            return CPARSER_NOT_OK;
        }
        
        apr_pool_create(&ptemp, psec); 
        apr_pool_tag(ptemp, "ptemp");
        
        strncpy(sec_policy_name, (char *)context->cookie[context->parser->root_level], NAME_LEN_MAX);
    
        keyword.pool = ptemp; 
        strncpy(keyword.sec_policy, sec_policy_name, NAME_LEN_MAX);
        keyword.sec_subpolicy = CC_PROTECT;
        keyword.flag = 0;

        if (strcmp(*type_ptr, "plain-text") == 0) {
            keyword.type = CC_PLAIN_URL;
        } else {
            keyword.type = CC_REGEX_URL;
        }

        keyword.keyword = apr_array_make(ptemp, INIT_ARR_LEN, sizeof(char*));
        keyword1 = (char**)apr_array_push(keyword.keyword);
        *keyword1 = apr_pstrdup(ptemp, *url_string_ptr);

        sprintf(buf, "url %s %s", *type_ptr, *url_string_ptr);

        rv = convert_keyword_add(&keyword);
        switch (rv) {
        case CONV_OK:
            admin_log_process(context, buf);
            break;
        case CONV_FAIL:
            cli_printf_info(context, "add keyword failure\n");
            break;
        case CONV_CONFLICT:
            cli_printf_info(context, "add keyword failure, keyword has existed\n");
            break;
        default:
            break;
        }
    }

    apr_pool_destroy(ptemp);
    return CPARSER_OK;
}

/* 用来show 安全策略 */
cparser_result_t cparser_cmd_show_protect_engine_security_policy(cparser_context_t *context)
{
    security_policy_t *ring_tmp, *ring_tmp_n;
    int sec_policy_num, sub_policy_num, enable_num, disable_num;
    char buf[COMMAND_LEN_MAX];
    
    if (context->parser->mode != CPARSER_MODE_CONFIG) {
        return CPARSER_OK;
    } else {
        cli_printf_info(context, "------------------------------------------------------------------------\n");
        cli_printf_info(context, "No.    Policy-Name                        Subpolicy    Enable    Disable    Commit-Status\n");
        sec_policy_num = 0;
        APR_RING_FOREACH_SAFE(ring_tmp, ring_tmp_n, &sec_policy_ring, security_policy_s, ring) {
            sub_policy_num = 0;
            enable_num = 0;
            disable_num = 0;            
            securitypolicy_sum(ring_tmp, &sub_policy_num, &enable_num, &disable_num);
            cli_printf_info(context, "%-3d    %-31s    %-9d    %-6d    %-7d    %s\n",
                 ++sec_policy_num, ring_tmp->name, sub_policy_num, enable_num, disable_num,
                 ring_tmp->commit_status ? "Succ" : "Fail");
        }

        snprintf(buf, COMMAND_LEN_MAX, "show protect-engine security-policy");
        admin_log_process(context, buf);
    }

    return CPARSER_OK;
}

cparser_result_t cparser_cmd_show_protect_engine_security_policy_detail(cparser_context_t *context)
{
    security_policy_t *ring_tmp, *ring_tmp_n;
    int sub_policy_num, enable_num, disable_num;
    char buf[COMMAND_LEN_MAX];

    if (context->parser->mode != CPARSER_MODE_CONFIG) {
        return CPARSER_OK;
    } else {
        APR_RING_FOREACH_SAFE(ring_tmp, ring_tmp_n, &sec_policy_ring, security_policy_s, ring) {
            sub_policy_num = 0;
            enable_num = 0;
            disable_num = 0;
            
            cli_printf_info(context, "-------------------------------------------------------------------------\n");
            cli_printf_info(context, "Security policy name: %s\n", ring_tmp->name);
            cli_printf_info(context, " Subpolicy statistic as follows:\n");
            securitypolicy_sum(ring_tmp, &sub_policy_num, &enable_num, &disable_num);
            
            cli_printf_info(context, "  Total:   %d\n", sub_policy_num);
            cli_printf_info(context, "  Enable:  %d\n", enable_num);
            cli_printf_info(context, "  Disable: %d\n", disable_num);
            cli_printf_info(context, " Subpolicy configuration as follows:\n");
            cli_printf_info(context, "  No. Sub-policyName                     Action  Log  Status\n");

            securitypolicy_show(context, ring_tmp);
            cli_printf_info(context, " Commit status: %s\n", ring_tmp->commit_status ? "Succ" : "Fail");
        }

        snprintf(buf, COMMAND_LEN_MAX, "show protect-engine security-policy detail");
        admin_log_process(context, buf);
    }

    return CPARSER_OK;
}

cparser_result_t cparser_cmd_show_protect_engine_security_policy_sp_name_detail(cparser_context_t *context,
    char **sp_name_ptr)
{
    security_policy_t *ring_tmp, *ring_tmp_n;
    int sub_policy_num, enable_num, disable_num;
    char sp_name[STR_LEN_MAX], buf[COMMAND_LEN_MAX];
    
    if (context->parser->mode != CPARSER_MODE_CONFIG) {
        return CPARSER_OK;
    } else {
        strncpy(sp_name, *sp_name_ptr, STR_LEN_MAX);

        APR_RING_FOREACH_SAFE(ring_tmp, ring_tmp_n, &sec_policy_ring, security_policy_s, ring) {
            if (!strncmp(ring_tmp->name, sp_name, NAME_LEN_MAX)) {
                sub_policy_num = 0;
                enable_num = 0;
                disable_num = 0;
        
                cli_printf_info(context, "--------------------------------------------------------------\n");
                cli_printf_info(context, "Security policy name: %s\n", ring_tmp->name);
                cli_printf_info(context, " Subpolicy statistic as follows:\n");
                securitypolicy_sum(ring_tmp, &sub_policy_num, &enable_num, &disable_num);
                
                cli_printf_info(context, "  Total:   %d\n", sub_policy_num);
                cli_printf_info(context, "  Enable:  %d\n", enable_num);
                cli_printf_info(context, "  Disable: %d\n", disable_num);
                cli_printf_info(context, " Subpolicy configuration as follows:\n");
                cli_printf_info(context, "  No. Sub-policyName                     Action  Log  Status\n");
                securitypolicy_show(context, ring_tmp);
                break;
            }
        }
        
        if (ring_tmp != APR_RING_SENTINEL(&sec_policy_ring, security_policy_s, ring)) {
            snprintf(buf, COMMAND_LEN_MAX, "show protect-engine security-policy %s detail", *sp_name_ptr);
            admin_log_process(context, buf);
        } 
        
        /* 不存在的时候什么都不显示 */
        return CPARSER_OK;
    }
}

cparser_result_t show_protect_engine_security_policy_sp_name(cparser_context_t *context, 
                    char **sp_name_ptr, char **type_ptr, int detail)
{
    security_policy_t *ring_tmp, *ring_tmp_n;
    int sub_policy_num, enable_num, disable_num;
    char sp_name[STR_LEN_MAX], buf[COMMAND_LEN_MAX];
    apr_pool_t *ptemp;
    char temp_str[STR_LEN_MAX];
    int i;

    if (context->parser->mode != CPARSER_MODE_CONFIG) {
        return CPARSER_OK;
    } else {
        apr_pool_create(&ptemp, psec); 
        apr_pool_tag(ptemp, "ptemp");  
        strncpy(sp_name, *sp_name_ptr, STR_LEN_MAX);
        strncpy(temp_str, scpname, STR_LEN_MAX);
        strncpy(scpname, sp_name, STR_LEN_MAX);  

        if (type_ptr == NULL) {
            APR_RING_FOREACH_SAFE(ring_tmp, ring_tmp_n, &sec_policy_ring, security_policy_s, ring) {              
                if (!strncmp(ring_tmp->name, sp_name, NAME_LEN_MAX)) {
                    sub_policy_num = 0;
                    enable_num = 0;
                    disable_num = 0;

                    cli_printf_info(context, 
                        "------------------------------------------------------------------------\n");
                    cli_printf_info(context, 
                        "No.    Policy-Name                        Subpolicy    Enable    Disable\n");         

                    securitypolicy_sum(ring_tmp, &sub_policy_num, &enable_num, &disable_num);
                    cli_printf_info(context, "%-3d    %-31s    %-9d    %-6d    %-7d\n",
                         1, ring_tmp->name, sub_policy_num, enable_num, disable_num);
                    break;
                }
            }

            if (detail) {
                snprintf(buf, COMMAND_LEN_MAX, "show protect-engine security-policy %s detail", 
                    *sp_name_ptr);        
            } else {
                snprintf(buf, COMMAND_LEN_MAX, "show protect-engine security-policy %s", 
                    *sp_name_ptr);
            }
        } else {
            for (i =0; i < 31; i++) {
                if (strcmp(*type_ptr, subpolicy_type[i]) == 0) {
                    break;
                }
            }
            
            if (i < 31) {                     
                 APR_RING_FOREACH_SAFE(ring_tmp, ring_tmp_n, &sec_policy_ring, security_policy_s, ring) {
                     if (!strncmp(ring_tmp->name, sp_name, NAME_LEN_MAX)) {
                         cli_printf_info(context, 
                             "--------------------------------------------------------------\n");
                         scp_show_viatype(context, ring_tmp, i);
                         keyword_show(i, ptemp, context);
                         break;
                     }
                 }
            }
            
            if (detail) {
                snprintf(buf, COMMAND_LEN_MAX, "show protect-engine security-policy %s %s detail", 
                    *sp_name_ptr, *type_ptr);        
            } else {
                snprintf(buf, COMMAND_LEN_MAX, "show protect-engine security-policy %s %s", 
                    *sp_name_ptr, *type_ptr);
            }
        }

        /* 不存在的时候什么都不显示 */
        if (ring_tmp == APR_RING_SENTINEL(&sec_policy_ring, security_policy_s, ring)) {
            apr_pool_destroy(ptemp);
            return CPARSER_OK;
        }

        admin_log_process(context, buf);
        strncpy(scpname, temp_str, STR_LEN_MAX);
        apr_pool_destroy(ptemp);
    }
    
    return CPARSER_OK;
}

cparser_result_t cparser_cmd_show_protect_engine_security_policy_sp_name_type(cparser_context_t *context,
    char **sp_name_ptr, char **type_ptr)
{
    return show_protect_engine_security_policy_sp_name(context, sp_name_ptr, type_ptr, 0);
}

cparser_result_t cparser_cmd_show_protect_engine_security_policy_sp_name_type_detail(cparser_context_t *context,
    char **sp_name_ptr, char **type_ptr)
{
    return show_protect_engine_security_policy_sp_name(context, sp_name_ptr, type_ptr, 1);
}

