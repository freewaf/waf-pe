/*
 * $Id: cli_security_policy_interface.c 2786 2013-07-09 16:42:55 FreeWAF Development Team $
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

#include <ctype.h>
#include <string.h>
#include "cli_security_policy.h"
#include "pe_cli.h"
 
/* 安全子策略命令中存在action log status */
void set_default_sub_secpolicy_typefirst(generate_subpolicy_t *subpolicy, int type, 
    security_policy_t *ring_tmp)
{
    subpolicy->pool = ring_tmp->pool;
    subpolicy->sec_subpolicy = type;
    strncpy(subpolicy->sec_policy, ring_tmp->name, NAME_LEN_MAX);
    subpolicy->action = ACTION_PASS;
    subpolicy->log = 1;
    subpolicy->status = ENABLE;
}

void set_default_sub_secpolicy_typethird(generate_subpolicy_t *subpolicy, int type, 
    security_policy_t *ring_tmp)
{
    subpolicy->pool = ring_tmp->pool;
    subpolicy->sec_subpolicy = type;
    strncpy(subpolicy->sec_policy, ring_tmp->name, NAME_LEN_MAX);
    subpolicy->action = ACTION_PASS;
    subpolicy->log = 1;
    subpolicy->status = DISABLE;
}

/* 安全子策略命令中不存在action */
void set_default_sub_secpolicy_typesecond(generate_subpolicy_t *subpolicy, int type, 
    security_policy_t *ring_tmp)
{
    subpolicy->pool = ring_tmp->pool;
    subpolicy->sec_subpolicy = type;
    strncpy(subpolicy->sec_policy, ring_tmp->name, NAME_LEN_MAX);
    subpolicy->action = -1;                /* 安全子策略命令不存在action动作，用-1来进行表示 */
    subpolicy->log = 1;
    subpolicy->status = ENABLE;
}

/* 安全子策略命令中不存在action */
void set_default_sub_secpolicy_typefourth(generate_subpolicy_t *subpolicy, int type, 
    security_policy_t *ring_tmp)
{
    subpolicy->pool = ring_tmp->pool;
    subpolicy->sec_subpolicy = type;
    strncpy(subpolicy->sec_policy, ring_tmp->name, NAME_LEN_MAX);
    subpolicy->action = -1;                /* 安全子策略命令不存在action动作，用-1来进行表示 */
    subpolicy->log = 1;
    subpolicy->status = DISABLE;
}

/* 设置安全策略默认包含子策略 */
void set_default_security_policy(security_policy_t *ring_tmp)
{
    set_default_sub_secpolicy_typefirst(&(ring_tmp->sql_subply), SQL_INJECTION, ring_tmp);
    set_default_sub_secpolicy_typefirst(&(ring_tmp->ldap_subply), LDAP_INJECTION, ring_tmp);
    set_default_sub_secpolicy_typefirst(&(ring_tmp->email_subply), EMAIL_INJECTION, ring_tmp);
    set_default_sub_secpolicy_typefirst(&(ring_tmp->cmd_subply), COMMAND_INJECTION, ring_tmp);
    set_default_sub_secpolicy_typefirst(&(ring_tmp->code_subply), CODE_INJECTION, ring_tmp);
    set_default_sub_secpolicy_typethird(&(ring_tmp->null_subply), NULL_BYTE_INJECTION, ring_tmp);
    set_default_sub_secpolicy_typefirst(&(ring_tmp->xss_subply), XSS, ring_tmp);
    set_default_sub_secpolicy_typefirst(&(ring_tmp->csrf_subply), CSRF, ring_tmp);
    set_default_sub_secpolicy_typefirst(&(ring_tmp->overflow_subply), OVERFLOW, ring_tmp);
    set_default_sub_secpolicy_typethird(&(ring_tmp->file_subply), FILE_INCLUDE, ring_tmp);
    set_default_sub_secpolicy_typefirst(&(ring_tmp->base_subply), BASE_ATTACK, ring_tmp);
    set_default_sub_secpolicy_typefirst(&(ring_tmp->path_subply), PATH_TRAVERSAL, ring_tmp);
    set_default_sub_secpolicy_typefirst(&(ring_tmp->dir_subply), DIRECTORY_INDEX, ring_tmp);
    set_default_sub_secpolicy_typefirst(&(ring_tmp->spider_subply), SPIDER_SCANNER, ring_tmp);
    set_default_sub_secpolicy_typefirst(&(ring_tmp->trojan_subply), TROJAN, ring_tmp);
    set_default_sub_secpolicy_typefirst(&(ring_tmp->xml_subply), XML_ATTACK, ring_tmp);
    set_default_sub_secpolicy_typefirst(&(ring_tmp->weakpwd_subply), WEAK_PASSWORD, ring_tmp);
    set_default_sub_secpolicy_typesecond(&(ring_tmp->version_subply), SERVER_VERSION, ring_tmp);
    set_default_sub_secpolicy_typefirst(&(ring_tmp->http_subply), HTTP_STATUS_CODE, ring_tmp);
    set_default_sub_secpolicy_typefourth(&(ring_tmp->iccard_subply), ICCARD_INFORMATION, ring_tmp);
    set_default_sub_secpolicy_typefirst(&(ring_tmp->server_subply), SERVER_ERROR_INFO, ring_tmp);
    set_default_sub_secpolicy_typefirst(&(ring_tmp->program_subply), PROGRAM_CODE, ring_tmp);
    set_default_sub_secpolicy_typethird(&(ring_tmp->magcard_subply), MAGCARD_INFORMATION, ring_tmp);
    set_default_sub_secpolicy_typefourth(&(ring_tmp->idcard_subply), IDCARD_INFORMATION, ring_tmp);
    set_default_sub_secpolicy_typefirst(&(ring_tmp->filedown_subply), FILE_DOWNLOAD, ring_tmp);
    set_default_sub_secpolicy_typefirst((generate_subpolicy_t *)(&(ring_tmp->fileup_subply)), 
        FILE_UPLOAD, ring_tmp);
    set_default_sub_secpolicy_typefirst((generate_subpolicy_t *)(&(ring_tmp->cookie_subply)), 
        COOKIE, ring_tmp);
    set_default_sub_secpolicy_typefirst((generate_subpolicy_t *)(&(ring_tmp->protocol_subply)), 
        PROTOCOL_PARAM, ring_tmp);
    set_default_sub_secpolicy_typefirst(&(ring_tmp->request_subply), REQUEST_METHOD, ring_tmp);
    set_default_sub_secpolicy_typefirst(&(ring_tmp->keyword_subply), KEYWORD_FILTER, ring_tmp);
    set_default_sub_secpolicy_typefirst((generate_subpolicy_t *)(&(ring_tmp->ccprotect_subply)), 
        CC_PROTECT, ring_tmp);
}

 void add_security_policy(cparser_context_t *context, char *sec_policy_name)
 {
    apr_pool_t *psecpolicy;
    int rv;
    security_policy_t *ring_tmp;
    
    /* 为每个安全策略创建一个子池 */
    apr_pool_create(&psecpolicy, psec); 
    apr_pool_tag(psecpolicy, "psecpolicy");
    
    ring_tmp = (security_policy_t*)apr_pcalloc(psecpolicy, sizeof(security_policy_t));
    if (!ring_tmp) {
        cli_printf_info(context, "not enough memmory\n");      
        return;
    }

    ring_tmp->pool = psecpolicy;
    strncpy(ring_tmp->name, sec_policy_name, NAME_LEN_MAX -  1);
    ring_tmp->name[NAME_LEN_MAX -  1] = '\0';
    set_default_security_policy(ring_tmp);
    ring_tmp->commit_status = 0;

    rv = ap_secpolicy_list_add(sec_policy_name);
    if (rv != OK) {
        apr_pool_destroy(psecpolicy);
        cli_printf_info(context, "add security policy failure in security-policy list\n");           
        return;
    }

    APR_RING_ELEM_INIT(ring_tmp, ring);
    
    /* 将默认安全策略插到链表首部 */
    if (!strncmp(ring_tmp->name, DEFAULT_POLICY, NAME_LEN_MAX)) {
        APR_RING_INSERT_HEAD(&sec_policy_ring, ring_tmp, security_policy_s, ring); 
    } else {  
        APR_RING_INSERT_TAIL(&sec_policy_ring, ring_tmp, security_policy_s, ring); 
    }  
 }

void sec_policy_get_option(generate_subpolicy_t *subpolicy, char **option_ptr, char *buf)
{ 
    if (strcmp(*option_ptr, "enable") == 0) {
        subpolicy->status = ENABLE;
        sprintf(buf, "%s enable", subpolicy_type[subpolicy->sec_subpolicy]);

    } else {
        subpolicy->status = DISABLE;
        sprintf(buf, "%s disable", subpolicy_type[subpolicy->sec_subpolicy]);
    }
}

void sec_policy_get_action(generate_subpolicy_t *subpolicy, char **action_ptr, char *buf)
{
    if (strcmp(*action_ptr, "drop") == 0) {
       subpolicy->action = ACTION_DROP;
       sprintf(buf, "%s action drop", subpolicy_type[subpolicy->sec_subpolicy]);
    } else if (strcmp(*action_ptr, "deny") == 0) {
       subpolicy->action = ACTION_DENY; 
       sprintf(buf, "%s action deny", subpolicy_type[subpolicy->sec_subpolicy]);
    } else {
        subpolicy->action = ACTION_PASS;
        sprintf(buf, "%s action pass", subpolicy_type[subpolicy->sec_subpolicy]);
    }    
}

void sec_policy_get_action_option(generate_subpolicy_t *subpolicy, char **action_ptr, 
        char **option_ptr, char *buf)
{
    if (strcmp(*action_ptr, "drop") == 0) {
       subpolicy->action = ACTION_DROP;
       sprintf(buf, "%s action drop", subpolicy_type[subpolicy->sec_subpolicy]);
    } else if (strcmp(*action_ptr, "deny") == 0) {
       subpolicy->action = ACTION_DENY; 
       sprintf(buf, "%s action deny", subpolicy_type[subpolicy->sec_subpolicy]);
    } else {
        subpolicy->action = ACTION_PASS;
        sprintf(buf, "%s action pass", subpolicy_type[subpolicy->sec_subpolicy]);
    }
    
    if (strcmp(*option_ptr, "enable") == 0) {
        subpolicy->status = ENABLE;
        strcat(buf, " enable");
    } else {
        subpolicy->status = DISABLE;
        strcat(buf, " disable");
    }
}

void sec_policy_get_log_option(generate_subpolicy_t *subpolicy, char **option_ptr, char *buf)
{    
    if (strcmp(*option_ptr, "enable") == 0) {
        subpolicy->status = ENABLE;
        sprintf(buf, "%s log enable", subpolicy_type[subpolicy->sec_subpolicy]);
    } else {
        subpolicy->status = DISABLE;
        sprintf(buf, "%s log disable", subpolicy_type[subpolicy->sec_subpolicy]);
    }

    subpolicy->log = 1;
}

void sec_policy_get_action_log(generate_subpolicy_t *subpolicy, char **action_ptr, char *buf)
{
    if (strcmp(*action_ptr, "drop") == 0) {
       subpolicy->action = ACTION_DROP;
       sprintf(buf, "%s action drop log", subpolicy_type[subpolicy->sec_subpolicy]);
    } else if (strcmp(*action_ptr, "deny") == 0) {
       subpolicy->action = ACTION_DENY;
       sprintf(buf, "%s action deny log", subpolicy_type[subpolicy->sec_subpolicy]);
    } else {
        subpolicy->action = ACTION_PASS;
        sprintf(buf, "%s action pass log", subpolicy_type[subpolicy->sec_subpolicy]);
    }

    subpolicy->log = 1;
}

void sec_policy_get_action_log_option(generate_subpolicy_t *subpolicy, char **action_ptr, 
        char **option_ptr, char *buf)
{
    if (strcmp(*action_ptr, "drop") == 0) {
       subpolicy->action = ACTION_DROP;
       sprintf(buf, "%s action drop", subpolicy_type[subpolicy->sec_subpolicy]);
    } else if (strcmp(*action_ptr, "deny") == 0) {
       subpolicy->action = ACTION_DENY;
       sprintf(buf, "%s action deny", subpolicy_type[subpolicy->sec_subpolicy]);
    } else {
        subpolicy->action = ACTION_PASS;
        sprintf(buf, "%s action pass", subpolicy_type[subpolicy->sec_subpolicy]);
    }
    
    subpolicy->log = 1;
    if (strcmp(*option_ptr, "enable") == 0) {
        subpolicy->status = ENABLE;
        strcat(buf, " log enable");
    } else {
        subpolicy->status = DISABLE;
        strcat(buf, " log disable");
    }
}

void transfer_security_policy_name(cparser_context_t *context)
{
    const char *temp_str;
    apr_pool_t *ptemp;

    apr_pool_create(&ptemp, psec); 
    apr_pool_tag(ptemp, "ptemp");
    
    temp_str = apr_pstrdup(ptemp, (const char *)context->cookie[context->parser->root_level]);
    strcpy(context->cookie[context->parser->root_level], ap_getword_conf(ptemp, &temp_str));

    apr_pool_destroy(ptemp);
}

/* 删除所有关键字写管理日志 */
static void admin_log_no_keyword_all(cparser_context_t *context, int sec_subpolicy, int type)
{
    char buf[COMMAND_LEN_MAX];

    switch(sec_subpolicy) {
    case FILE_DOWNLOAD:
        sprintf(buf, "no file-type all");
        break;
    case FILE_UPLOAD:
        if (type == FILE_TYPE) {
            sprintf(buf, "no file-type all");
        }
        
        break;
    case COOKIE:
        if (type == COOKIE_NAME) {
            sprintf(buf, "no cookie-name all");
        }
        
        break;
    case REQUEST_METHOD:
        sprintf(buf, "no method all");
        break;
    case CC_PROTECT:
        if (type == CC_KEYWORD_ALL) {
            sprintf(buf, "no url all");
        }
        
        break;
    case CSRF:
        if (type == CSRF_COOKIE_NAME) {
            sprintf(buf, "no cookie-name all");
        } if (type == CSRF_URL_ALL) {
            sprintf(buf, "no url all");
        }

        break;
    default:
        sprintf(buf, "no keyword all");
        break;    
    }

    admin_log_process(context, buf);
}
/* 为子安全策略no keyword all提供公用的接口 */
cparser_result_t cmd_no_keyword_all(cparser_context_t *context, int sec_subpolicy, int type)
{
    apr_pool_t *ptemp;
    keyword_t keyword;
    char **keyword1;
    int rv;

    if (context->parser->mode != CPARSER_MODE_CONFIG) {
        return CPARSER_OK;
    } else {
        apr_pool_create(&ptemp, psec); 
        apr_pool_tag(ptemp, "ptemp");
        
        keyword.type = type;
        keyword.pool = ptemp;
        strncpy(keyword.sec_policy, (char *)context->cookie[context->parser->root_level], NAME_LEN_MAX);
        keyword.sec_subpolicy = sec_subpolicy;
        keyword.flag = 1;
        
        keyword.keyword = apr_array_make(ptemp, INIT_ARR_LEN, sizeof(char*));
        keyword1 = (char**)apr_array_push(keyword.keyword); 
        *keyword1 = apr_pstrdup(ptemp, "all");
        
        rv = convert_keyword_del(&keyword);
        switch (rv) {
        case CONV_OK:
            admin_log_no_keyword_all(context, sec_subpolicy, type);
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

    }

    apr_pool_destroy(ptemp);
    return CPARSER_OK;
}

/* 对删除单个关键字的命令记录到管理日志中 */
static void admin_log_no_keyword_single(cparser_context_t *context, int sec_subpolicy, int type, char **keyword_ptr)
{
    char buf[COMMAND_LEN_MAX];

    switch (sec_subpolicy) {
    case FILE_DOWNLOAD:
        sprintf(buf, "no file-type plain-text %s", *keyword_ptr);
        break;
    case FILE_UPLOAD:
        if (type == FILE_TYPE) {
            sprintf(buf, "no file-type plain-text %s", *keyword_ptr);
        }
        
        break;
    case COOKIE:
        if (type == COOKIE_NAME) {
            sprintf(buf, "no cookie-name plain-text %s", *keyword_ptr);
        }
        
        break;
    case CSRF:
        if (type == CSRF_COOKIE_NAME) {
           sprintf(buf, "no cookie-name plain-text %s", *keyword_ptr); 
        }

        break;
    case REQUEST_METHOD:
        sprintf(buf, "no method plain-text %s", *keyword_ptr);
        break;
    default:
        sprintf(buf, "no keyword plain-text %s", *keyword_ptr);
        break;
    }

    admin_log_process(context, buf);
}

/* 为子安全策略 no keyword plain-text string 提供共用接口*/
cparser_result_t cmd_no_keyword_plain_text_keyword(cparser_context_t *context, int sec_subpolicy,
                    int type, char **keyword_ptr)
{
    apr_pool_t *ptemp;
    keyword_t keyword;
    char **keyword1;
    int rv;

    if (keyword_ptr == NULL || *keyword_ptr == NULL) {
        return CPARSER_NOT_OK;
    }

    if (context->parser->mode != CPARSER_MODE_CONFIG) {
        return CPARSER_OK;
    } else {
        apr_pool_create(&ptemp, psec); 
        apr_pool_tag(ptemp, "ptemp");
        
        keyword.type = type;
        keyword.pool = ptemp;
        strncpy(keyword.sec_policy, (char *)context->cookie[context->parser->root_level], NAME_LEN_MAX);
        keyword.sec_subpolicy = sec_subpolicy;
        keyword.flag = 0;
        
        keyword.keyword = apr_array_make(ptemp, INIT_ARR_LEN, sizeof(char*));
        keyword1 = (char**)apr_array_push(keyword.keyword); 
        *keyword1 = apr_pstrdup(ptemp, *keyword_ptr);

        rv = convert_keyword_del(&keyword);
        switch (rv) {
        case CONV_OK:
            admin_log_no_keyword_single(context, sec_subpolicy, type, keyword_ptr);
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

/* 为cookie删除关键字提供共同的接口 */
cparser_result_t cookie_cmd_no_keyword(cparser_context_t *context, int type)
{
    apr_pool_t *ptemp;
    keyword_t keyword;
    int rv;
    char buf[COMMAND_LEN_MAX];
    char **keyword1;

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
        keyword.type = type;

        keyword.keyword = apr_array_make(ptemp, INIT_ARR_LEN, sizeof(char*));  
        keyword1 = (char**)apr_array_push(keyword.keyword);
        switch(type) {
        case EXPIRE_TIME:
            *keyword1 = apr_pstrdup(ptemp, apr_itoa(ptemp, 1440));
            sprintf(buf, "no expire-time");
            break;
        case VERIFICATION:
            sprintf(buf, "no verification");
            break;
        case ATTRIBUTION:
            sprintf(buf, "no attribution");
            break;
        default:
            break;
        }

        if (type == EXPIRE_TIME) {
            rv = convert_keyword_add(&keyword);
        } else {
            rv = convert_keyword_del(&keyword);
        }

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

/* 根据子安全策略的值来进行c2p保存 */
void sec_policy_showcmd(generate_subpolicy_t *subpolicy, char *str) 
{
    if (subpolicy) {
        switch(subpolicy->action) {
        case ACTION_DROP:
            strcat(str, "action drop ");
            break;
        case ACTION_DENY:
            strcat(str, "action deny ");
            break;
        case ACTION_PASS:
            strcat(str, "action pass ");
            break;
        default:
            break;
        }
        
       if(subpolicy->log) {
            strcat(str, "log ");
       }

        switch(subpolicy->status) {
        case DISABLE:
            strcat(str, "disable");
            break;
        case ENABLE:
            strcat(str, "enable");
            break;
        default:
            break;
        }  
    } 
}

/* sql-injection c2p */
void cmd_c2p_sql(cparser_context_t *context, generate_subpolicy_t *sec_subpolicy)
{
    char str[STR_LEN_MAX] = "";
    char *temp_str;

    temp_str = (char *)context->cookie[context->parser->root_level];
    if (!sec_subpolicy) {
        return;
    }

    if (sec_subpolicy->flag != 1) {
        return;
    }
    
    sec_policy_showcmd(sec_subpolicy, str);
    if (context->parser->mode == CPARSER_MODE_WRITE) {
        if (context->parser->fp == NULL) {
            return;
        } else {
            cli_fprintf(context, "sql-injection-protect %s\n", str);
        }
    } else {
        cli_printf(context, "sql-injection-protect %s\n", str);       
    }   

    context->parser->root_level++;
    context->parser->root[context->parser->root_level] = context->parser->cur_node->children;
    cparser_walk(context->parser, cparser_running_conf_walker, NULL, temp_str);
    context->parser->root_level--;
}

/* ldap-injection c2p */
void cmd_c2p_ldap(cparser_context_t *context, generate_subpolicy_t *sec_subpolicy)
{
    char str[STR_LEN_MAX] = "";
    
    if (!sec_subpolicy) {
        return;
    }

    if (sec_subpolicy->flag != 1) {
        return;
    }

    sec_policy_showcmd(sec_subpolicy, str);
    if (context->parser->mode == CPARSER_MODE_WRITE) {
        if (context->parser->fp == NULL) {
            return;
        } else {
            cli_fprintf(context, "ldap-injection-protect %s\n", str);
        }
    } else {
        cli_printf(context, "ldap-injection-protect %s\n", str);
    }
}

/* email-injection c2p */
void cmd_c2p_email(cparser_context_t *context, generate_subpolicy_t *sec_subpolicy)
{
    char str[STR_LEN_MAX] = "";

    if (!sec_subpolicy) {
        return;
    }

    if (sec_subpolicy->flag != 1) {
        return;
    }
    
    sec_policy_showcmd(sec_subpolicy, str);
    if (context->parser->mode == CPARSER_MODE_WRITE) {
        if (context->parser->fp == NULL) {
            return;
        } else {
            cli_fprintf(context, "email-injection-protect %s\n", str);
        }
    } else {
        cli_printf(context, "email-injection-protect %s\n", str);
    }
}

/* command-injection c2p */
void cmd_c2p_command(cparser_context_t *context, generate_subpolicy_t *sec_subpolicy)
{
    char str[STR_LEN_MAX] = "";
    char *temp_str;

    temp_str = (char *)context->cookie[context->parser->root_level];
    if (!sec_subpolicy) {
        return;
    }

    if (sec_subpolicy->flag != 1) {
        return;
    }
    
    sec_policy_showcmd(sec_subpolicy, str);
    if (context->parser->mode == CPARSER_MODE_WRITE) {
        if (context->parser->fp == NULL) {
            return;
        } else {
            cli_fprintf(context, "command-injection-protect %s\n", str);
        }
    } else {
        cli_printf(context, "command-injection-protect %s\n", str);
    }
    
    context->parser->root_level++;
    context->parser->root[context->parser->root_level] = context->parser->cur_node->children;
    cparser_walk(context->parser, cparser_running_conf_walker, NULL, temp_str);
    context->parser->root_level--;
}

/* code-injection c2p */
void cmd_c2p_code(cparser_context_t *context, generate_subpolicy_t *sec_subpolicy)
{
    char str[STR_LEN_MAX] = "";
    char *temp_str;

    temp_str = (char *)context->cookie[context->parser->root_level];

    if (!sec_subpolicy) {
        return;
    }

    if (sec_subpolicy->flag != 1) {
        return;
    }
    
    sec_policy_showcmd(sec_subpolicy, str);
    if (context->parser->mode == CPARSER_MODE_WRITE) {
        if (context->parser->fp == NULL) {
            return;
        } else {
            cli_fprintf(context, "code-injection-protect %s\n", str);
        }
    } else {
        cli_printf(context, "code-injection-protect %s\n", str);
    }

    context->parser->root_level++;
    context->parser->root[context->parser->root_level] = context->parser->cur_node->children;
    cparser_walk(context->parser, cparser_running_conf_walker, NULL, temp_str);
    context->parser->root_level--;
}

/* null-byte-injection c2p*/
void cmd_c2p_null(cparser_context_t *context, generate_subpolicy_t *sec_subpolicy)
{
    char str[STR_LEN_MAX] = "";

    if (!sec_subpolicy) {
        return;
    }

    if (sec_subpolicy->flag != 1) {
        return;
    }
    
    sec_policy_showcmd(sec_subpolicy, str);
    if (context->parser->mode == CPARSER_MODE_WRITE) {
        if (context->parser->fp == NULL) {
            return;
        } else {
            cli_fprintf(context, "null-byte-injection-protect %s\n", str);
        }
    } else {
        cli_printf(context, "null-byte-injection-protect %s\n", str);
    }  
}

/* xss c2p */
void cmd_c2p_xss(cparser_context_t *context, generate_subpolicy_t *sec_subpolicy)
{
    char str[STR_LEN_MAX] = "";
    char *temp_str;

    temp_str = (char *)context->cookie[context->parser->root_level];
    if (!sec_subpolicy) {
        return;
    }

    if (sec_subpolicy->flag != 1) {
        return;
    }
    
    sec_policy_showcmd(sec_subpolicy, str);
    if (context->parser->mode == CPARSER_MODE_WRITE) {
        if (context->parser->fp == NULL) {
            return;
        } else {
            cli_fprintf(context, "xss-attack-protect %s\n", str);
        }
    } else {
        cli_printf(context, "xss-attack-protect %s\n", str);
    }

    context->parser->root_level++;
    context->parser->root[context->parser->root_level] = context->parser->cur_node->children;
    cparser_walk(context->parser, cparser_running_conf_walker, NULL, temp_str);
    context->parser->root_level--;
}

/* csrf c2p*/
void cmd_c2p_csrf(cparser_context_t *context, generate_subpolicy_t *sec_subpolicy)
{
    char *temp_str;
    char str[STR_LEN_MAX] = "";

    temp_str = (char *)context->cookie[context->parser->root_level];

    if (!sec_subpolicy) {
        return;
    }

    if (sec_subpolicy->flag != 1) {
        return;
    }
    
    sec_policy_showcmd(sec_subpolicy, str);
    if (context->parser->mode == CPARSER_MODE_WRITE) {
        if (context->parser->fp == NULL) {
            return;
        } else {
            cli_fprintf(context, "csrf-attack-protect %s\n", str);
        }
    } else {
        cli_printf(context, "csrf-attack-protect %s\n", str);
    }

    context->parser->root_level++;
    context->parser->root[context->parser->root_level] = context->parser->cur_node->children;
    cparser_walk(context->parser, cparser_running_conf_walker, NULL, temp_str);
    context->parser->root_level--;
}

/* overflow c2p*/
void cmd_c2p_overflow(cparser_context_t *context, generate_subpolicy_t *sec_subpolicy)
{
    char str[STR_LEN_MAX] = "";
 
    if (!sec_subpolicy) {
        return;
    }

    if (sec_subpolicy->flag != 1) {
        return;
    }
    
    sec_policy_showcmd(sec_subpolicy, str);
    if (context->parser->mode == CPARSER_MODE_WRITE) {
        if (context->parser->fp == NULL) {
            return;
        } else {
            cli_fprintf(context, "overflow-attack-protect %s\n", str);
        }
    } else {
        cli_printf(context, "overflow-attack-protect %s\n", str);
    }             
}

/* file-include c2p*/
void cmd_c2p_file(cparser_context_t *context, generate_subpolicy_t *sec_subpolicy)
{
    char str[STR_LEN_MAX] = "";

    if (!sec_subpolicy) {
        return;
    }

    if (sec_subpolicy->flag != 1) {
        return;
    }
    
    sec_policy_showcmd(sec_subpolicy, str);
    if (context->parser->mode == CPARSER_MODE_WRITE) {
        if (context->parser->fp == NULL) {
            return;
        } else {
            cli_fprintf(context, "file-include-attack-protect %s\n", str);
        }
    } else {
        cli_printf(context, "file-include-attack-protect %s\n", str);
    }                       
}

/* base c2p */
void cmd_c2p_base(cparser_context_t *context, generate_subpolicy_t *sec_subpolicy)
{
    char str[STR_LEN_MAX] = "";

    if (!sec_subpolicy) {
        return;
    }

    if (sec_subpolicy->flag != 1) {
        return;
    }
    
    sec_policy_showcmd(sec_subpolicy, str);
    if (context->parser->mode == CPARSER_MODE_WRITE) {
        if (context->parser->fp == NULL) {
            return;
        } else {
            cli_fprintf(context, "misc-attack-protect %s\n", str);
        }
    } else {
        cli_printf(context, "misc-attack-protect %s\n", str);
    }                       
}

/* path-traversal c2p */
void cmd_c2p_path(cparser_context_t *context, generate_subpolicy_t *sec_subpolicy)
{
    char str[STR_LEN_MAX] = "";

    if (!sec_subpolicy) {
        return;
    }

    if (sec_subpolicy->flag != 1) {
        return;
    }
    
    sec_policy_showcmd(sec_subpolicy, str);
    if (context->parser->mode == CPARSER_MODE_WRITE) {
        if (context->parser->fp == NULL) {
            return;
        } else {
            cli_fprintf(context, "path-traversal-attack-protect %s\n", str);
        }
    } else {
        cli_printf(context, "path-traversal-attack-protect %s\n", str);
    }                      
}

/* directory-index c2p */
void cmd_c2p_directory(cparser_context_t *context, generate_subpolicy_t *sec_subpolicy)
{
    char str[STR_LEN_MAX] = "";

    if (!sec_subpolicy) {
        return;
    }

    if (sec_subpolicy->flag != 1) {
        return;
    }
    
    sec_policy_showcmd(sec_subpolicy, str);
    if (context->parser->mode == CPARSER_MODE_WRITE) {
        if (context->parser->fp == NULL) {
            return;
        } else {
            cli_fprintf(context, "directory-index-protect %s\n", str);
        }
    } else {
        cli_printf(context, "directory-index-protect %s\n", str);
    }                     
}

/* spider c2p */
void cmd_c2p_spider(cparser_context_t *context, generate_subpolicy_t *sec_subpolicy)
{
    char str[STR_LEN_MAX] = "";
    char *temp_str;

    temp_str = (char *)context->cookie[context->parser->root_level];
    if (!sec_subpolicy) {
        return;
    }

    if (sec_subpolicy->flag != 1) {
        return;
    }

    sec_policy_showcmd(sec_subpolicy, str);
    if (context->parser->mode == CPARSER_MODE_WRITE) {
        if (context->parser->fp == NULL) {
            return;
        } else {
            cli_fprintf(context, "spider-scanner-attack-protect %s\n", str);
        }
    } else {
        cli_printf(context, "spider-scanner-attack-protect %s\n", str);
    }

    context->parser->root_level++;
    context->parser->root[context->parser->root_level] = context->parser->cur_node->children;
    cparser_walk(context->parser, cparser_running_conf_walker, NULL, temp_str);
    context->parser->root_level--;
}

/* trojan c2p */
void cmd_c2p_trojan(cparser_context_t *context, generate_subpolicy_t *sec_subpolicy)
{
    char str[STR_LEN_MAX] = "";
    char *temp_str;

    temp_str = (char *)context->cookie[context->parser->root_level];
    if (!sec_subpolicy) {
        return;
    }

    if (sec_subpolicy->flag != 1) {
        return;
    }
    
    sec_policy_showcmd(sec_subpolicy, str);
    if (context->parser->mode == CPARSER_MODE_WRITE) {
        if (context->parser->fp == NULL) {
            return;
        } else {
            cli_fprintf(context, "trojan-protect %s\n", str);
        }
    } else {
        cli_printf(context, "trojan-protect %s\n", str);
    }

    context->parser->root_level++;
    context->parser->root[context->parser->root_level] = context->parser->cur_node->children;
    cparser_walk(context->parser, cparser_running_conf_walker, NULL, temp_str);
    context->parser->root_level--;
}

/* xml c2p */
void cmd_c2p_xml(cparser_context_t *context, generate_subpolicy_t *sec_subpolicy)
{
    char str[STR_LEN_MAX] = "";
    
    if (!sec_subpolicy) {
        return;
    }

    if (sec_subpolicy->flag != 1) {
        return;
    }
    
    sec_policy_showcmd(sec_subpolicy, str);
    if (context->parser->mode == CPARSER_MODE_WRITE) {
        if (context->parser->fp == NULL) {
            return;
        } else {
            cli_fprintf(context, "xml-attack-protect %s\n", str);
        }
    } else {
        cli_printf(context, "xml-attack-protect %s\n", str);
    }
}

/* weak-password c2p */
void cmd_c2p_weak_password(cparser_context_t *context, generate_subpolicy_t *sec_subpolicy)
{
    char str[STR_LEN_MAX] = "";
    char *temp_str;

    if (sec_subpolicy->flag != 1) {
        return;
    }

    temp_str = (char *)context->cookie[context->parser->root_level];   
    sec_policy_showcmd(sec_subpolicy, str);
    if (context->parser->mode == CPARSER_MODE_WRITE) {
        if (context->parser->fp == NULL) {
            return;        
        } else {
            cli_fprintf(context, "weak-password-protect %s\n", str);
        }
    } else {
        cli_printf(context, "weak-password-protect %s\n", str);
    }

    context->parser->root_level++;
    context->parser->root[context->parser->root_level] = context->parser->cur_node->children;
    cparser_walk(context->parser, cparser_running_conf_walker, NULL, temp_str);
    context->parser->root_level--;
}

/* server-version c2p */
void cmd_c2p_server_version(cparser_context_t *context, generate_subpolicy_t *sec_subpolicy)
{
    char str[STR_LEN_MAX] = "";
    char *temp_str;
    
    temp_str = (char *)context->cookie[context->parser->root_level];
    if (!sec_subpolicy) {
        return;
    }

    if (sec_subpolicy->flag != 1) {
        return;
    }
    
    sec_policy_showcmd(sec_subpolicy, str);
    if (context->parser->mode == CPARSER_MODE_WRITE) {
        if (context->parser->fp == NULL) {
            return;
        } else {
            cli_fprintf(context, "server-version-protect %s\n", str);
        }
    } else {
        cli_printf(context, "server-version-protect %s\n", str);
    }

    context->parser->root_level++;
    context->parser->root[context->parser->root_level] = context->parser->cur_node->children;
    cparser_walk(context->parser, cparser_running_conf_walker, NULL, temp_str);
    context->parser->root_level--;
}

/* http-code-status c2p */
void cmd_c2p_http(cparser_context_t *context, generate_subpolicy_t *sec_subpolicy)
{
    char str[STR_LEN_MAX] = "";
    
    if (!sec_subpolicy) {
        return;
    }

    if (sec_subpolicy->flag != 1) {
        return;
    }
    
    sec_policy_showcmd(sec_subpolicy, str);
    if (context->parser->mode == CPARSER_MODE_WRITE) {
        if (context->parser->fp == NULL) {
            return;
        } else {
            cli_fprintf(context, "http-status-code-protect %s\n", str);
        }
    } else {
        cli_printf(context, "http-status-code-protect %s\n", str);
    }
}

/* iccard-information c2p */
void cmd_c2p_iccard(cparser_context_t *context, generate_subpolicy_t *sec_subpolicy)
{
    char str[STR_LEN_MAX] = "";
    char *temp_str;

    temp_str = (char *)context->cookie[context->parser->root_level];
    if (!sec_subpolicy) {
        return;
    }

    if (sec_subpolicy->flag != 1) {
        return;
    }
    
    sec_policy_showcmd(sec_subpolicy, str);
    if (context->parser->mode == CPARSER_MODE_WRITE) {
        if (context->parser->fp == NULL) {
            return;
        } else {
            cli_fprintf(context, "creditcard-information-protect %s\n", str);
        }
    } else {
        cli_printf(context, "creditcard-information-protect %s\n", str);
    }

    context->parser->root_level++;
    context->parser->root[context->parser->root_level] = context->parser->cur_node->children;
    cparser_walk(context->parser, cparser_running_conf_walker, NULL, temp_str);
    context->parser->root_level--;
}

/* server-error-info c2p */
void cmd_c2p_server_error(cparser_context_t *context, generate_subpolicy_t *sec_subpolicy)
{
    char str[STR_LEN_MAX] = "";
    
    if (!sec_subpolicy) {
        return;
    }

    if (sec_subpolicy->flag != 1) {
        return;
    }
    
    sec_policy_showcmd(sec_subpolicy, str);
    if (context->parser->mode == CPARSER_MODE_WRITE) {
        if (context->parser->fp == NULL) {
            return;
        } else {
            cli_fprintf(context, "server-error-information-protect %s\n", str);
        }
    } else {
        cli_printf(context, "server-error-information-protect %s\n", str);
    }
}

/* progarm_code c2p */
void cmd_c2p_program(cparser_context_t *context, generate_subpolicy_t *sec_subpolicy)
{
    char str[STR_LEN_MAX] = "";
    
    if (!sec_subpolicy) {
        return;
    }

    if (sec_subpolicy->flag != 1) {
        return;
    }
    
    sec_policy_showcmd(sec_subpolicy, str);
    if (context->parser->mode == CPARSER_MODE_WRITE) {
        if (context->parser->fp == NULL) {
            return;
        } else {
            cli_fprintf(context, "program-code-protect %s\n", str);
        }
    } else {
        cli_printf(context, "program-code-protect %s\n", str);
    }           
}

/* magcard-information c2p */
void cmd_c2p_magcard(cparser_context_t *context, generate_subpolicy_t *sec_subpolicy)
{
    char str[STR_LEN_MAX] = "";
    
    if (!sec_subpolicy) {
        return;
    }

    if (sec_subpolicy->flag != 1) {
        return;
    }
    
    sec_policy_showcmd(sec_subpolicy, str);
    if (context->parser->mode == CPARSER_MODE_WRITE) {
        if (context->parser->fp == NULL) {
            return;
        } else {
            cli_fprintf(context, "magcard-information-protect %s\n", str);
        }
    } else {
        cli_printf(context, "magcard-information-protect %s\n", str);
    }
}

/* idcard-information c2p */
void cmd_c2p_idcard(cparser_context_t *context, generate_subpolicy_t *sec_subpolicy)
{
    char str[STR_LEN_MAX] = "";
    char *temp_str;

    temp_str = (char *)context->cookie[context->parser->root_level];
    if (!sec_subpolicy) {
        return;
    }

    if (sec_subpolicy->flag != 1) {
        return;
    }
    
    sec_policy_showcmd(sec_subpolicy, str);
    if (context->parser->mode == CPARSER_MODE_WRITE) {
        if (context->parser->fp == NULL) {
            return;
        } else {
            cli_fprintf(context, "idcard-information-protect %s\n", str);
        }
    } else {
        cli_printf(context, "idcard-information-protect %s\n", str);
    }

    context->parser->root_level++;
    context->parser->root[context->parser->root_level] = context->parser->cur_node->children;
    cparser_walk(context->parser, cparser_running_conf_walker, NULL, temp_str);
    context->parser->root_level--;
}

/* file-download c2p */
void cmd_c2p_file_download(cparser_context_t *context, generate_subpolicy_t *sec_subpolicy)
{
    char str[STR_LEN_MAX] = "";
    char *temp_str;

    temp_str = (char *)context->cookie[context->parser->root_level];
    if (!sec_subpolicy) {
        return;
    }

    if (sec_subpolicy->flag != 1) {
        return;
    }
    
    sec_policy_showcmd(sec_subpolicy, str);
    if (context->parser->mode == CPARSER_MODE_WRITE) {
        if (context->parser->fp == NULL) {
            return;
        } else {
            cli_fprintf(context, "file-download-protect %s\n", str);
        }
    } else {
        cli_printf(context, "file-download-protect %s\n", str);
    }

    context->parser->root_level++;
    context->parser->root[context->parser->root_level] = context->parser->cur_node->children;
    cparser_walk(context->parser, cparser_running_conf_walker, NULL, temp_str);
    context->parser->root_level--;
}

/* file-upload c2p */
void cmd_c2p_file_upload(cparser_context_t *context, generate_subpolicy_t *sec_subpolicy)
{
    char str[STR_LEN_MAX] = "";
    char *temp_str;

    temp_str = (char *)context->cookie[context->parser->root_level];
    if (!sec_subpolicy) {
        return;
    }

    if (sec_subpolicy->flag != 1) {
        return;
    }
    
    sec_policy_showcmd(sec_subpolicy, str);
    if (context->parser->mode == CPARSER_MODE_WRITE) {
        if (context->parser->fp == NULL) {
            return;
        } else {
            cli_fprintf(context, "file-upload-protect %s\n", str);
        }
    } else {
        cli_printf(context, "file-upload-protect %s\n", str);
    }

    context->parser->root_level++;
    context->parser->root[context->parser->root_level] = context->parser->cur_node->children;
    cparser_walk(context->parser, cparser_running_conf_walker, NULL, temp_str);
    context->parser->root_level--;
}

/* cookie c2p */
void cmd_c2p_cookie(cparser_context_t *context, generate_subpolicy_t *sec_subpolicy)
{
    char str[STR_LEN_MAX] = "";
    char *temp_str;

    temp_str = (char *)context->cookie[context->parser->root_level];
    if (!sec_subpolicy) {
        return;
    }

    if (sec_subpolicy->flag != 1) {
        return;
    }
    
    sec_policy_showcmd(sec_subpolicy, str);
    if (context->parser->mode == CPARSER_MODE_WRITE) {
        if (context->parser->fp == NULL) {
            return;
        } else {
            cli_fprintf(context, "cookie-protect %s\n", str);
        }
    } else {
        cli_printf(context, "cookie-protect %s\n", str);
    }

    context->parser->root_level++;
    context->parser->root[context->parser->root_level] = context->parser->cur_node->children;
    cparser_walk(context->parser, cparser_running_conf_walker, NULL, temp_str);
    context->parser->root_level--;
}

/* protocol c2p */
void cmd_c2p_protocol(cparser_context_t *context, generate_subpolicy_t *sec_subpolicy)
{
    char str[STR_LEN_MAX] = "";
    char *temp_str;

    temp_str = (char *)context->cookie[context->parser->root_level];
    if (!sec_subpolicy) {
        return;
    }

    if (sec_subpolicy->flag != 1) {
        return;
    }
    
    sec_policy_showcmd(sec_subpolicy, str);
    if (context->parser->mode == CPARSER_MODE_WRITE) {
        if (context->parser->fp == NULL) {
            return;
        } else {
            cli_fprintf(context, "protocol-param-protect %s\n", str);
        }
    } else {
        cli_printf(context, "protocol-param-protect %s\n", str);
    }

    context->parser->root_level++;
    context->parser->root[context->parser->root_level] = context->parser->cur_node->children;
    cparser_walk(context->parser, cparser_running_conf_walker, NULL, temp_str);
    context->parser->root_level--;
}

/* request-method c2p */
void cmd_c2p_request_method(cparser_context_t *context, generate_subpolicy_t *sec_subpolicy)
{
    char str[STR_LEN_MAX] = "";
    char *temp_str;

    temp_str = (char *)context->cookie[context->parser->root_level];
    if (!sec_subpolicy) {
        return;
    }
    
    if (sec_subpolicy->flag != 1) {
        return;
    }
    
    sec_policy_showcmd(sec_subpolicy, str);
    if (context->parser->mode == CPARSER_MODE_WRITE) {
        if (context->parser->fp == NULL) {
            return;
        } else {
            cli_fprintf(context, "request-method-protect %s\n", str);
        }
    } else {
        cli_printf(context, "request-method-protect %s\n", str);
    }

    context->parser->root_level++;
    context->parser->root[context->parser->root_level] = context->parser->cur_node->children;
    cparser_walk(context->parser, cparser_running_conf_walker, NULL, temp_str);
    context->parser->root_level--;
}

/* keyword-filter c2p */
void cmd_c2p_keyword_filter(cparser_context_t *context, generate_subpolicy_t *sec_subpolicy)
{
    char str[STR_LEN_MAX] = "";
    char *temp_str;

    temp_str = (char *)context->cookie[context->parser->root_level];
    if (!sec_subpolicy) {
        return;
    }

    if (sec_subpolicy->flag != 1) {
        return;
    }
    
    sec_policy_showcmd(sec_subpolicy, str);
    if (context->parser->mode == CPARSER_MODE_WRITE) {
        if (context->parser->fp == NULL) {
            return;
        } else {
            cli_fprintf(context, "keyword-filter %s\n", str);
        }
    } else {
        cli_printf(context, "keyword-filter %s\n", str);
    }

    context->parser->root_level++;
    context->parser->root[context->parser->root_level] = context->parser->cur_node->children;
    cparser_walk(context->parser, cparser_running_conf_walker, NULL, temp_str);
    context->parser->root_level--;
}

/* cc-protect c2p */
void cmd_c2p_cc(cparser_context_t *context, generate_subpolicy_t *sec_subpolicy)
{
    char str[STR_LEN_MAX] = "";
    char *temp_str;

    temp_str = (char *)context->cookie[context->parser->root_level];
    if (!sec_subpolicy) {
        return;
    }

    if (sec_subpolicy->flag != 1) {
        return;
    }
    
    sec_policy_showcmd(sec_subpolicy, str);
    if (context->parser->mode == CPARSER_MODE_WRITE) {
        if (context->parser->fp == NULL) {
            return;
        } else {
            cli_fprintf(context, "cc-protect %s\n", str);
        }
    } else {
        cli_printf(context, "cc-protect %s\n", str);
    }

    context->parser->root_level++;
    context->parser->root[context->parser->root_level] = context->parser->cur_node->children;
    cparser_walk(context->parser, cparser_running_conf_walker, NULL, temp_str);
    context->parser->root_level--;
}

void cmd_c2p_url_page(cparser_context_t *context, security_policy_t *ring_tmp)
{
    if (ring_tmp->url_page_flag) {      
      if (context->parser->mode == CPARSER_MODE_WRITE) {
            if (context->parser->fp == NULL) {
                return;
            } else {
                cli_fprintf(context, "url-page\n");
            }
        } else {
            cli_printf(context, "url-page\n");
        }

        context->parser->root_level++;
        context->parser->root[context->parser->root_level] = context->parser->cur_node->children;
        cparser_walk(context->parser, cparser_running_conf_walker, NULL, ring_tmp->name);
        context->parser->root_level--;
    }
}

void cookie_name_c2p(cparser_context_t *context, char *str_sub1)
{
    if (context->parser->mode == CPARSER_MODE_WRITE) {
        if (context->parser->fp == NULL) {
            return;
        } else {
            cli_fprintf(context, "cookie-name plain-text %s\n", str_sub1);
        } 
    }  else {
        cli_printf(context, "cookie-name plain-text %s\n", str_sub1);
    }
}

void expire_time_c2p(cparser_context_t *context, char *str_sub1, security_policy_t *ring_tmp)
{
    if ((ring_tmp->cookie_subply).expire_time) {
        if (context->parser->mode == CPARSER_MODE_WRITE) {
            if (context->parser->fp == NULL) {
                return;
            } else {
                cli_fprintf(context, "expire-time %s\n", str_sub1);
            }
        } else {
            cli_printf(context, "expire-time %s\n", str_sub1);
        }
    }
}

void verification_method_signature_c2p(cparser_context_t *context, char *str_sub2)
{
    if (apr_atoi64(str_sub2) == COOKIE_VERTFICATION) {
        if (context->parser->mode == CPARSER_MODE_WRITE) {
            if (context->parser->fp == NULL) {
                return;
            } else {
                cli_fprintf(context, "verification method signature content cookie\n");
            } 
        }  else {
            cli_printf(context, "verification method signature content cookie\n");
        }
    } else {
        if (context->parser->mode == CPARSER_MODE_WRITE) {
            if (context->parser->fp == NULL) {
                return;
            } else {
                cli_fprintf(context, "verification method signature content ip-and-cookie\n");
            } 
        }  else {
            cli_printf(context, "verification method signature content ip-and-cookie\n");
        }
    }
}

void verification_method_encryption_c2p(cparser_context_t *context, char *str_sub2)
{
    if (apr_atoi64(str_sub2) == COOKIE_VERTFICATION) {
        if (context->parser->mode == CPARSER_MODE_WRITE) {
            if (context->parser->fp == NULL) {
                return;
            } else {
                cli_fprintf(context, "verification method encryption content cookie\n");
            } 
        }  else {
            cli_printf(context, "verification method encryption content cookie\n");
        }
    } else {
        if (context->parser->mode == CPARSER_MODE_WRITE) {
            if (context->parser->fp == NULL) {
                return;
            } else {
                cli_fprintf(context, "verification method encryption content ip-and-cookie\n");
            } 
        }  else {
            cli_printf(context, "verification method encryption content ip-and-cookie\n");
        }
    }
}

void attribution_c2p(cparser_context_t *context, char *str_sub1, security_policy_t *ring_tmp)
{
    if ((ring_tmp->cookie_subply).attribution) {
        switch(apr_atoi64(str_sub1)) {
        case SECURE:
            if (context->parser->mode == CPARSER_MODE_WRITE) {
                if (context->parser->fp == NULL) {
                    return;
                } else {
                    cli_fprintf(context, "attribution secure\n");
                } 
            } else {
                cli_printf(context, "attribution secure\n");
            }
                
            break;
        case HTTPDONLY:
            if (context->parser->mode == CPARSER_MODE_WRITE) {
                if (context->parser->fp == NULL) {
                    return;
                } else {
                    cli_fprintf(context, "attribution httponly\n");
                } 
            } else {
                cli_printf(context, "attribution httponly\n");
            }

            break;
        case SECURE_HTTPONLY:
            if (context->parser->mode == CPARSER_MODE_WRITE) {
                if (context->parser->fp == NULL) {
                    return;
                } else {
                    cli_fprintf(context, "attribution secure httponly\n");
                } 
            } else {
                cli_printf(context, "attribution secure httponly\n");
            }

            break;
        default:
            break;
        }
    }
}

/* 由于cookie_c2p函数内嵌层次太多，需要进行修改，减少内嵌层次， 故创建这个函数，供cookie_c2p函数调用 */
void cookie_middle_c2p(cparser_context_t *context, int type, apr_array_header_t *k,  security_policy_t *ring_tmp)
{
    int j;
    char **str;
    char *str_sub1, *str_sub2;
    
    str = (char**)k->elts;
    for (j = 0; j < k->nelts; j++) {
        str_sub1 = str[j];
        switch(type) {
        case COOKIE_NAME:
            cookie_name_c2p(context, str_sub1);        
            break;
        case EXPIRE_TIME:
            expire_time_c2p(context, str_sub1, ring_tmp);            
            break;
        case VERIFICATION:
            if ((ring_tmp->cookie_subply).verification_mothed) {
                switch(apr_atoi64(str_sub1)) {
                case SIGNATURE:
                    j = j + 1;
                    str_sub2 = str[j];
                    verification_method_signature_c2p(context, str_sub2);            
                    break;
                case ENCRYPTION:
                    j = j + 1;
                    str_sub2 = str[j];
                    verification_method_encryption_c2p(context, str_sub2);
                    break;                       
                default:
                    break;
                }
            }

            break;
        case ATTRIBUTION:
            attribution_c2p(context, str_sub1, ring_tmp);
            break;
        default:
            break;
        }     
    }
}

void cookie_c2p(cparser_context_t *context, const apr_array_header_t *result,  security_policy_t *ring_tmp) 
{
    int i;
    int type;
    apr_array_header_t *k;
    keyword_t **kw, *kw_sub;

    kw = (keyword_t**)result->elts;
    for (i = 0; i < result->nelts; i++) {
        kw_sub = kw[i];
        k = kw_sub->keyword;
        type = kw_sub->type;     
        cookie_middle_c2p(context, type, k, ring_tmp);
    }

    return;
}

/* 由于protocol_c2p嵌套层次太多， 故创建这个函数来减少protocol_c2p嵌套层次 */
void protocol_middle_c2p(cparser_context_t *context, char *str_sub, int type, security_policy_t *ring_tmp)
{
    switch(type) {
    case REQUEST_HEADER_NUM:
        if ((ring_tmp->protocol_subply).request_header_num) {
            if (context->parser->mode == CPARSER_MODE_WRITE) {
                if (context->parser->fp == NULL) {
                    return;
                } else {
                    cli_fprintf(context, "request-header-num %s\n", str_sub);
                } 
            } else {
                cli_printf(context, "request-header-num %s\n", str_sub);
            }
        }
        
        break;
    case HEADER_SIZE_EXCEPT_COOKIE:
        if ((ring_tmp->protocol_subply).header_size_except_cookie) {
            if (context->parser->mode == CPARSER_MODE_WRITE) {
                if (context->parser->fp == NULL) {
                    return;
                } else {
                    cli_fprintf(context, "header-size-except-cookie %s\n", str_sub);
                } 
            } else {
                cli_printf(context, "header-size-except-cookie %s\n", str_sub);
            }
        }
        
        break;
    case COOKIE_SIZE:
        if ((ring_tmp->protocol_subply).cookie_size) {
            if (context->parser->mode == CPARSER_MODE_WRITE) {
                if (context->parser->fp == NULL) {
                    return;
                } else {
                    cli_fprintf(context, "cookie-size %s\n", str_sub);
                } 
            } else {
                cli_printf(context, "cookie-size %s\n", str_sub);
            }
        }
        
        break;
    case REQUEST_URL_SIZE:
        if ((ring_tmp->protocol_subply).request_url_size) {
            if (context->parser->mode == CPARSER_MODE_WRITE) {
                if (context->parser->fp == NULL) {
                    return;
                } else {
                    cli_fprintf(context, "request-url-size %s\n", str_sub);
                } 
            } else {
                cli_printf(context, "request-url-size %s\n", str_sub);
            }
        }
        
        break;
    case QUERY_STRING_SIZE:
        if ((ring_tmp->protocol_subply).query_string_size) {
            if (context->parser->mode == CPARSER_MODE_WRITE) {
                if (context->parser->fp == NULL) {
                    return;
                } else {
                    cli_fprintf(context, "query-string-size %s\n", str_sub);
                } 
            } else {
                cli_printf(context, "query-string-size %s\n", str_sub);
            }
        }
        
        break;
    case ARGUMENT_NUM:
        if ((ring_tmp->protocol_subply).request_argument_num) {
            if (context->parser->mode == CPARSER_MODE_WRITE) {
                if (context->parser->fp == NULL) {
                    return;
                } else {
                    cli_fprintf(context, "request-argument-num %s\n", str_sub);
                } 
            } else {
                cli_printf(context, "request-argument-num %s\n", str_sub);
            }
        }
        
        break;
    case ARGUMENT_SIZE:
        if ((ring_tmp->protocol_subply).request_argument_size) {
            if (context->parser->mode == CPARSER_MODE_WRITE) {
                if (context->parser->fp == NULL) {
                    return;
                } else {
                    cli_fprintf(context, "request-argument-size %s\n", str_sub);
                } 
            } else {
                cli_printf(context, "request-argument-size %s\n", str_sub);
            }
        }
        
        break;
    case BODY_SIZE:
        if ((ring_tmp->protocol_subply).request_body_size) {
            if (context->parser->mode == CPARSER_MODE_WRITE) {
                if (context->parser->fp == NULL) {
                    return;
                } else {
                    cli_fprintf(context, "request-body-size %u\n", apr_atoi64(str_sub) / (1 << 20));
                } 
            } else {
                cli_printf(context, "request-body-size %u\n", apr_atoi64(str_sub) / (1 << 20));
            }
        }
        
        break;
    case ARGUMENT_NAME_SIZE:
        if ((ring_tmp->protocol_subply).request_argument_name_size) {
            if (context->parser->mode == CPARSER_MODE_WRITE) {
                if (context->parser->fp == NULL) {
                    return;
                } else {
                    cli_fprintf(context, "request-argument-name-size %s\n", str_sub);
                } 
            } else {
                cli_printf(context, "request-argument-name-size %s\n", str_sub);
            }
        }
        
        break;
    case ARGUMENT_NAME_VALUE_SIZE:
        if ((ring_tmp->protocol_subply).request_argument_name_value_size) {
            if (context->parser->mode == CPARSER_MODE_WRITE) {
                if (context->parser->fp == NULL) {
                    return;
                } else {
                    cli_fprintf(context, "request-argument-name-value-size %s\n", str_sub);
                } 
            } else {
                cli_printf(context, "request-argument-name-value-size %s\n", str_sub);
            }
        }
        
        break;
    default:
        break;
    }
}

void protocol_c2p(cparser_context_t *context, const apr_array_header_t *result, security_policy_t *ring_tmp)
{
    int i, j;
    char **str, *str_sub;;
    apr_array_header_t *k;
    keyword_t **kw, *kw_sub;
    int type;

    kw = (keyword_t**)result->elts;
    for (i = 0; i < result->nelts; i++) {
        kw_sub = kw[i];
        k = kw_sub->keyword;
        type = kw_sub->type;
        str = (char**)k->elts;
        for (j = 0; j < k->nelts; j++) {
            str_sub = str[j];
            protocol_middle_c2p(context, str_sub, type, ring_tmp);
        }
    }
    
    return;
}

/* 由于file_upload_c2p嵌套层次太多， 故创建这个函数来减少file_upload_c2p嵌套层次 */
void file_upload_middle_c2p(cparser_context_t *context, int type, keyword_t *kw_sub, char *str_sub, security_policy_t *ring_tmp)
{
    switch(type) {
    case FILE_TYPE:
        if (kw_sub->flag == OUTER_KEYWORD) {
            if (context->parser->mode == CPARSER_MODE_WRITE) {
                if (context->parser->fp == NULL) {
                    return;
                } else {
                    cli_fprintf(context, "file-type plain-text %s\n", str_sub);
                } 
            } else {
                cli_printf(context, "file-type plain-text %s\n", str_sub);
            }
        }
        
        break;
    case INDIVIDUAL_FILE_SIZE:
        if ((ring_tmp->fileup_subply).individual_file_size) {
            if (context->parser->mode == CPARSER_MODE_WRITE) {
                if (context->parser->fp == NULL) {
                    return;
                } else {
                    cli_fprintf(context, "individual-file-size %u\n", apr_atoi64(str_sub)/(1 << 20));
                } 
            } else {
                cli_printf(context, "individual-file-size %u\n", apr_atoi64(str_sub)/(1 << 20));
            }
        }
        
        break;
    case ALL_FILE_SIZE:
        if ((ring_tmp->fileup_subply).all_file_size) {
            if (context->parser->mode == CPARSER_MODE_WRITE) {
                if (context->parser->fp == NULL) {
                    return;
                } else {
                    cli_fprintf(context, "all-file-size %u\n", apr_atoi64(str_sub)/(1 << 20));
                } 
            } else {
                cli_printf(context, "all-file-size %u\n", apr_atoi64(str_sub)/(1 << 20));
            }
        }
        
        break;
    default:
        break;
    }
}

void file_upload_c2p(cparser_context_t *context, const apr_array_header_t *result, security_policy_t *ring_tmp)
{
    int i, j;
    char **str, *str_sub;
    apr_array_header_t *k;
    keyword_t **kw, *kw_sub;
    int type;

    kw = (keyword_t**)result->elts;
    for (i = 0; i < result->nelts; i++) {
        kw_sub = kw[i];
        k = kw_sub->keyword;
        type = kw_sub->type;
        str = (char**)k->elts;
        if (kw_sub->flag == OUTER_KEYWORD) {
            for (j = 0; j < k->nelts; j++) {
                str_sub = str[j]; 
                file_upload_middle_c2p(context, type, kw_sub, str_sub, ring_tmp);
            }
        }
    }

    return;
}

void csrf_keyword_c2p(cparser_context_t *context, int type, apr_array_header_t *k)
{
    char **str;

    str = (char**)k->elts;
    if (context->parser->mode == CPARSER_MODE_WRITE) {
        if (context->parser->fp == NULL) {
            return;
        } else {
            switch(type) {
            case CSRF_COOKIE_NAME:
                cli_fprintf(context, "cookie-name plain-text %s\n", *str);
                break;
            case CSRF_URL_PLAIN:
                cli_fprintf(context, "url plain-text %s\n", *str);
                break;
            case CSRF_URL_REGEX:
                cli_fprintf(context, "url regular-exp %s\n", *str);
                break;
            default:
                break;
            }
        }
    } else {
        switch(type) {
        case CSRF_COOKIE_NAME:
            cli_printf(context, "cookie-name plain-text %s\n", *str);
            break;
        case CSRF_URL_PLAIN:
            cli_printf(context, "url plain-text %s\n", *str);
            break;
        case CSRF_URL_REGEX:
            cli_printf(context, "url regular-exp %s\n", *str);
            break;
        default:
            break;
        }
    }
}

/* 由于请求方法c2p嵌套层次太多， 故创建这个函数来减少嵌套 */
void request_method_middle_c2p(cparser_context_t *context, int type, apr_array_header_t *k)
{
    int j;
    char **str;
    
    str = (char**)k->elts;
    for (j = 0; j < k->nelts; j++) {
        /* list接口返回包含内置库中的方法，show running不需要显示内置库中的方法 */
        if (strcmp(str[j], "GET") && strcmp(str[j], "POST") && strcmp(str[j], "OPTIONS")) {
            if (context->parser->mode == CPARSER_MODE_WRITE) {
                if (context->parser->fp == NULL) {
                    return;
                } else {
                    cli_fprintf(context, "method plain-text %s\n", str[j]);
                } 
            } else {
                cli_printf(context, "method plain-text %s\n", str[j]);
            }
        }
    }
}

/* 由于keyword_c2p函数内嵌层次太多，需要进行修改，减少内嵌层次， 故创建这个函数，供keyword_c2p函数调用 */
void keyword_middle_c2p(cparser_context_t *context, int type, apr_array_header_t *k) 
{
    int j;
    char **str;
    
    str = (char**)k->elts;
    switch(type) {
    case SQL_INJECTION:
    case KEYWORD_FILTER:
    case COMMAND_INJECTION:
    case XSS:
    case SPIDER_SCANNER:
    case TROJAN: 
    case CODE_INJECTION:
        if (context->parser->mode == CPARSER_MODE_WRITE) {
            for (j = 0; j < k->nelts; j++) {          
                if (context->parser->fp == NULL) {
                    return;
                } else {
                    cli_fprintf(context, "keyword plain-text %s\n", str[j]);
                }
            }
        } else {
            for (j = 0; j < k->nelts; j++) {
                cli_printf(context, "keyword plain-text %s\n", str[j]);
            }
        }

        break;
    case FILE_DOWNLOAD:
        if (context->parser->mode == CPARSER_MODE_WRITE) {
            for (j = 0; j < k->nelts; j++) {
                if (context->parser->fp == NULL) {
                    return;
                } else {
                    cli_fprintf(context, "file-type plain-text %s\n", str[j]);
                }
            }
        } else {
            for (j = 0; j < k->nelts; j++) {
                cli_printf(context, "file-type plain-text %s\n", str[j]);
            }
        }

        break;
    default:
        break;
    }
}

void information_leakage_keyword_c2p(cparser_context_t *context, int type, apr_array_header_t *k)
{
    int j;
    char **str;
    
    str = (char**)k->elts;
    if (context->parser->mode == CPARSER_MODE_WRITE) {
        for (j = 0; j < k->nelts; j = j + 2) {
            if (context->parser->fp == NULL) {
                return;
            } else {
                cli_fprintf(context, "keyword substitute plain-text %s for regular-exp %s\n", str[j], str[j+1]);
                break;               
            }
        } 
    } else {
        for (j = 0; j < k->nelts; j = j + 2) {
            cli_printf(context, "keyword substitute plain-text %s for regular-exp %s\n", str[j], str[j+1]);
            break;
        }
    }
}

void keyword_c2p(cparser_context_t *context, int type, apr_pool_t *ptemp)
{
    int i;
    char sec_policy_name[NAME_LEN_MAX];
    security_policy_t *ring_tmp, *ring_tmp_n;
    apr_array_header_t *result, *k;
    keyword_t **kw, *kw_sub;
    int keyword_type;

    strncpy(sec_policy_name, (char *)context->cookie[context->parser->root_level], NAME_LEN_MAX);
    result = apr_array_make(ptemp, 10, sizeof(keyword_t*));
    convert_sec_policy_list(sec_policy_name, type, &result);
    kw = (keyword_t**)result->elts;

    switch(type) {
    /* 下面几种模式进行关键字c2p使用同一过程, 进行复用，下面情况相同 */
    case SQL_INJECTION:
    case KEYWORD_FILTER:
    case COMMAND_INJECTION:
    case XSS:
    case SPIDER_SCANNER:
    case TROJAN:
    case CODE_INJECTION:
        for (i = 0; i < result->nelts; i++) {
            kw_sub = kw[i];
            if (kw_sub->flag == OUTER_KEYWORD) {
                k = kw_sub->keyword;
                keyword_middle_c2p(context, type, k);
            }
        }

        break;
    case SERVER_VERSION:
    case ICCARD_INFORMATION:
    case IDCARD_INFORMATION:
        for (i = 0; i < result->nelts; i++) {
            kw_sub = kw[i];
            if (kw_sub->flag == OUTER_KEYWORD) {
                k = kw_sub->keyword;
                information_leakage_keyword_c2p(context, type, k);
            }
        }

        break;
    case CSRF:
        for (i = 0; i < result->nelts; i++) {
            kw_sub = kw[i];
            keyword_type = kw_sub->type;
            k = kw_sub->keyword;
            csrf_keyword_c2p(context, keyword_type, k);
        }
        
        break;
    case FILE_DOWNLOAD:
        for (i = 0; i < result->nelts; i++) {
            kw_sub = kw[i];
            if (kw_sub->flag == OUTER_KEYWORD) {
                k = kw_sub->keyword;
                keyword_middle_c2p(context, type, k);
            }
        }

        break;
    case FILE_UPLOAD:
        APR_RING_FOREACH_SAFE(ring_tmp, ring_tmp_n, &sec_policy_ring, security_policy_s, ring) {
            if (strncmp(ring_tmp->name, sec_policy_name, NAME_LEN_MAX) == 0) {
                file_upload_c2p(context, result, ring_tmp);
                break;
            }
        }
        
        break;
    case COOKIE:
        APR_RING_FOREACH_SAFE(ring_tmp, ring_tmp_n, &sec_policy_ring, security_policy_s, ring) {
            if (strncmp(ring_tmp->name, sec_policy_name, NAME_LEN_MAX) == 0) {
                cookie_c2p(context, result, ring_tmp);
                break;
            }
        }
        
        break;
     
    case PROTOCOL_PARAM:
        APR_RING_FOREACH_SAFE(ring_tmp, ring_tmp_n, &sec_policy_ring, security_policy_s, ring) {
            if (strncmp(ring_tmp->name, sec_policy_name, NAME_LEN_MAX) == 0) {
                protocol_c2p(context, result, ring_tmp);
                break;
            }
        }
        
        break;

    case REQUEST_METHOD:
        for (i = 0; i < result->nelts; i++) {
            kw_sub = kw[i];
            k = kw_sub->keyword;
            request_method_middle_c2p(context, type, k);
        }

        break;
    default:
        break;
    }   
    
    return;
}

/* 将增加关键字的命令记录到管理日志中 */
static void admin_log_keyword_add(cparser_context_t *context, int sec_subpolicy, int type, char **key_str1, char **key_str2)
{
    char buf[COMMAND_LEN_MAX];
    
    switch(sec_subpolicy) {
    case SERVER_VERSION:
    case ICCARD_INFORMATION:
    case IDCARD_INFORMATION:
        sprintf(buf, "keyword substitute plain-text %s  for regular-exp %s", *key_str1, *key_str2);
        break;
    case FILE_DOWNLOAD:
        sprintf(buf, "file-type plain-text %s", *key_str1);
        break;
    case FILE_UPLOAD:
        if (type == FILE_TYPE) {
            sprintf(buf, "file-type plain-text %s", *key_str1);
        }
        
        break;
    case REQUEST_METHOD:
        sprintf(buf, "method plain-text %s", *key_str1);
        break;
    case COOKIE:
        if (type == COOKIE_NAME) {
            sprintf(buf, "cookie-name plain-text %s", *key_str1);
        }
        
        break;
    case CSRF:
        if (type == CSRF_COOKIE_NAME) {
            sprintf(buf, "cookie-name plain-text %s", *key_str1);
        } else if (type == CSRF_URL_PLAIN) {
            sprintf(buf, "url plain-text %s", *key_str1);
        } else if (type == CSRF_URL_REGEX) {
            sprintf(buf, "url regular-exp %s", *key_str1);
        }

        break;
    default:
        sprintf(buf, "keyword plain-text %s", *key_str1);
        break;
    }

    admin_log_process(context, buf);
}

/* 为增加关键字提供统一接口 */
void keyword_add(cparser_context_t *context, int sec_subpolicy, int type, apr_pool_t *ptemp, char **key_str1, char **key_str2) 
{
    char sec_policy_name[NAME_LEN_MAX];
    keyword_t keyword;
    char **keyword1, **keyword2;
    int rv;
    
    strncpy(sec_policy_name, (char *)context->cookie[context->parser->root_level], NAME_LEN_MAX);

    keyword.pool = ptemp;
    keyword.type = type;
    keyword.flag = 0;
    strncpy(keyword.sec_policy, sec_policy_name, NAME_LEN_MAX);
    keyword.sec_subpolicy = sec_subpolicy;
    
    keyword.keyword = apr_array_make(ptemp, INIT_ARR_LEN, sizeof(char*));
    if (key_str1 != NULL) {
        keyword1 = (char**)apr_array_push(keyword.keyword);
        *keyword1 = apr_pstrdup(ptemp, *key_str1);
    }

    if (key_str2 != NULL) {
        keyword2 = (char**)apr_array_push(keyword.keyword);
        *keyword2 = apr_pstrdup(ptemp, *key_str2);
    }

    rv = convert_keyword_add(&keyword);
    switch (rv) {
    case CONV_OK:
        admin_log_keyword_add(context, sec_subpolicy, type, key_str1, key_str2);
        break;
    case CONV_FAIL:
        cli_printf_info(context, "add keyword failure\n");
        break;
    case CONV_CONFLICT:
        cli_printf_info(context, "add keyword failure, keyword has existed\n");
        break;
    case CONV_EXIST:
        cli_printf_info(context, "add keyword failure, keyword has existed built-in library\n");
        break;
    default:
        break;
    } 
}

int type_compare(int bef_type, int type)
{
    if (bef_type == type) {
        return 1;
    } else if (bef_type == PLAIN_PLAIN && type == PLAIN_REGEX) {
        return 1;
    } else if (bef_type == REGEX_PLAIN && type == REGEX_REGEX) {
        return 1;
    } else if (bef_type == PLAIN_REGEX && type == PLAIN_PLAIN) {
        return 1;
    } else if (bef_type == REGEX_REGEX && type == REGEX_PLAIN) {
        return 1;
    }

    return 0;
}

void wp_url_printf(cparser_context_t *context, int type, char **str)
{
    if (type == PLAIN_PLAIN || type == PLAIN_REGEX) {
        if (context->parser->mode == CPARSER_MODE_WRITE) {
            if (context->parser->fp == NULL) {
                return;
            } else {
                fprintf(context->parser->fp, "  url plain-text %s password-name %s\n", str[0], str[1]);
            } 
        } else {
            cli_printf_info(context, "  url plain-text %s password-name %s\n", str[0], str[1]);
        }
    } else if (type == REGEX_PLAIN || type == REGEX_REGEX) {
        if (context->parser->mode == CPARSER_MODE_WRITE) {
            if (context->parser->fp == NULL) {
                    return;
            } else {
                    fprintf(context->parser->fp, "  url regular-exp %s password-name %s\n", str[0], str[1]);
            } 
        } else {
            cli_printf_info(context, "  url regular-exp %s password-name %s\n", str[0], str[1]);
        }
    }
}

void wp_url_keyword_printf(cparser_context_t *context, int type, char **str)
{
    if (type == PLAIN_PLAIN || type == REGEX_PLAIN) {
        if (context->parser->mode == CPARSER_MODE_WRITE) {
            if (context->parser->fp == NULL) {
                return;
            } else {
                fprintf(context->parser->fp, "   weak_password plain-text %s\n", str[2]);
            } 
        } else {
            cli_printf_info(context, "   weak_password plain-text %s\n", str[2]);
        }
    } else if (type == PLAIN_REGEX || type == REGEX_REGEX) {
        if (context->parser->mode == CPARSER_MODE_WRITE) {
            if (context->parser->fp == NULL) {
                return;
            } else {
                fprintf(context->parser->fp, "   weak_password regular-exp %s\n", str[2]);
            } 
        } else {
            cli_printf_info(context, "   weak_password regular-exp %s\n", str[2]);
        }
    }
}

void wp_url_by_keyword(keyword_t *kw_sub, char *url_string, cparser_context_t *context, int type)
{
    apr_array_header_t *k;
    char **string;

    k = kw_sub->keyword;
    string = (char**)k->elts;

    if (kw_sub->flag == OUTER_KEYWORD) {
        if ((type == kw_sub->type) && (!strcmp(string[0], url_string))) {
            wp_url_keyword_printf(context, kw_sub->type, string);
        }
    }
}

void commit_c2p(cparser_context_t *context)
{
    if (context->parser->mode == CPARSER_MODE_WRITE) {
        if (context->parser->fp == NULL) {
            return;
        } else {
            cli_fprintf(context, "commit\n");
        }
    } else {
        cli_printf(context, "commit\n");
    }
}

/* 为cc设置删除关键字提供共同接口 */
cparser_result_t cc_cmd_set_source_ip_keyword(cparser_context_t *context, uint32_t *seconds_ptr,
                    uint32_t *times_ptr, int type)
{
    apr_pool_t *ptemp;
    char sec_policy_name[NAME_LEN_MAX];
    keyword_t keyword;
    char **keyword1, **keyword2;
    int rv;
    char buf[COMMAND_LEN_MAX];
  
    apr_pool_create(&ptemp, psec); 
    apr_pool_tag(ptemp, "ptemp");

    strncpy(sec_policy_name, (char *)context->cookie[context->parser->root_level], NAME_LEN_MAX);

    keyword.pool = ptemp; 
    keyword.flag = 0;
    strncpy(keyword.sec_policy, sec_policy_name, NAME_LEN_MAX);
    keyword.sec_subpolicy = CC_PROTECT;
    keyword.type = SOURCE_IP;

    keyword.keyword = apr_array_make(ptemp, INIT_ARR_LEN, sizeof(char*));
    keyword1 = (char**)apr_array_push(keyword.keyword);
    keyword2 = (char**)apr_array_push(keyword.keyword);
    
    if (type) {
        sprintf(buf, "source-ip access-rate statistic-cycle %u request-times %u", *seconds_ptr, *times_ptr);
        *keyword1 = apr_pstrdup(ptemp, apr_ltoa(ptemp, *seconds_ptr));
        *keyword2 = apr_pstrdup(ptemp, apr_ltoa(ptemp, *times_ptr));    
    } else {
         *keyword1 = apr_pstrdup(ptemp, apr_itoa(ptemp, 60));
         *keyword2 = apr_pstrdup(ptemp, apr_itoa(ptemp, 1000));
         sprintf(buf, "no source-ip access-rate");
         
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
    default:
        break;
    }

    apr_pool_destroy(ptemp);
    return CPARSER_OK;
}

cparser_result_t cc_cmd_set_status_408_rate_keyword(cparser_context_t *context, uint32_t *seconds_ptr,
                    uint32_t *times_ptr, int type)
{
    apr_pool_t *ptemp;
    char sec_policy_name[NAME_LEN_MAX];
    keyword_t keyword;
    char **keyword1, **keyword2;
    int rv;
    char buf[COMMAND_LEN_MAX];
  
    apr_pool_create(&ptemp, psec); 
    apr_pool_tag(ptemp, "ptemp");

    strncpy(sec_policy_name, (char *)context->cookie[context->parser->root_level], NAME_LEN_MAX);

    keyword.pool = ptemp; 
    keyword.flag = 0;
    strncpy(keyword.sec_policy, sec_policy_name, NAME_LEN_MAX);
    keyword.sec_subpolicy = CC_PROTECT;
    keyword.type = STATUS_408_RATE;

    keyword.keyword = apr_array_make(ptemp, INIT_ARR_LEN, sizeof(char*));
    keyword1 = (char**)apr_array_push(keyword.keyword);
    keyword2 = (char**)apr_array_push(keyword.keyword);
    
    if (type) {
        sprintf(buf, "source-ip status-408-rate statistic-cycle %u response-times %u", *seconds_ptr, *times_ptr);
        *keyword1 = apr_pstrdup(ptemp, apr_ltoa(ptemp, *seconds_ptr));
        *keyword2 = apr_pstrdup(ptemp, apr_ltoa(ptemp, *times_ptr));    
    } else {
         *keyword1 = apr_pstrdup(ptemp, apr_itoa(ptemp, 60));
         *keyword2 = apr_pstrdup(ptemp, apr_itoa(ptemp, 10));
         sprintf(buf, "no source-ip status-408-rate");
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
    default:
        break;
    }

    apr_pool_destroy(ptemp);
    return CPARSER_OK;
}

cparser_result_t cc_cmd_set_referrer_url_keyword(cparser_context_t *context, uint32_t *seconds_ptr,
                    uint32_t *times_ptr, int type)
{
    apr_pool_t *ptemp;
    char sec_policy_name[NAME_LEN_MAX];
    keyword_t keyword;
    char **keyword1, **keyword2;
    int rv;
    char buf[COMMAND_LEN_MAX];
  
    apr_pool_create(&ptemp, psec); 
    apr_pool_tag(ptemp, "ptemp");

    strncpy(sec_policy_name, (char *)context->cookie[context->parser->root_level], NAME_LEN_MAX);

    keyword.pool = ptemp; 
    keyword.flag = 0;
    strncpy(keyword.sec_policy, sec_policy_name, NAME_LEN_MAX);
    keyword.sec_subpolicy = CC_PROTECT;
    keyword.type = REFERRER_URL;

    keyword.keyword = apr_array_make(ptemp, INIT_ARR_LEN, sizeof(char*));
    keyword1 = (char**)apr_array_push(keyword.keyword);
    keyword2 = (char**)apr_array_push(keyword.keyword);
    
    if (type) {
        sprintf(buf, "referrer-url access-rate statistic-cycle %u request-times %u", *seconds_ptr, *times_ptr);
        *keyword1 = apr_pstrdup(ptemp, apr_ltoa(ptemp, *seconds_ptr));
        *keyword2 = apr_pstrdup(ptemp, apr_ltoa(ptemp, *times_ptr));    
    } else {
         *keyword1 = apr_pstrdup(ptemp, apr_itoa(ptemp, 60));
         *keyword2 = apr_pstrdup(ptemp, apr_itoa(ptemp, 500));
         sprintf(buf, "no referrer-url access-rate");
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
    default:
        break;
    }

    apr_pool_destroy(ptemp);
    return CPARSER_OK;
}

cparser_result_t cc_cmd_set_url_access_rate_keyword(cparser_context_t *context, uint32_t *seconds_ptr,
                    uint32_t *times_ptr, int type)
{
    apr_pool_t *ptemp;
    char sec_policy_name[NAME_LEN_MAX];
    keyword_t keyword;
    char **keyword1, **keyword2;
    int rv;
    char buf[COMMAND_LEN_MAX];
  
    apr_pool_create(&ptemp, psec); 
    apr_pool_tag(ptemp, "ptemp");

    strncpy(sec_policy_name, (char *)context->cookie[context->parser->root_level], NAME_LEN_MAX);

    keyword.pool = ptemp; 
    keyword.flag = 0;
    strncpy(keyword.sec_policy, sec_policy_name, NAME_LEN_MAX);
    keyword.sec_subpolicy = CC_PROTECT;
    keyword.type = URL_ACCESS_RATE;

    keyword.keyword = apr_array_make(ptemp, INIT_ARR_LEN, sizeof(char*));
    keyword1 = (char**)apr_array_push(keyword.keyword);
    keyword2 = (char**)apr_array_push(keyword.keyword);
    
    if (type) {
        sprintf(buf, "access-rate statistic-cycle %u request-times %u", *seconds_ptr, *times_ptr);
        *keyword1 = apr_pstrdup(ptemp, apr_ltoa(ptemp, *seconds_ptr));
        *keyword2 = apr_pstrdup(ptemp, apr_ltoa(ptemp, *times_ptr));    
    } else {
         *keyword1 = apr_pstrdup(ptemp, apr_itoa(ptemp, 60));
         *keyword2 = apr_pstrdup(ptemp, apr_itoa(ptemp, 1000));
         sprintf(buf, "no access-rate");
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
    default:
        break;
    }

    apr_pool_destroy(ptemp);
    return CPARSER_OK;
}

void cc_by_type(int type, apr_array_header_t *k, cparser_context_t *context)
{
    int j;
    char **str;
    
    str = (char**)k->elts; 

     if (type == SOURCE_IP) {
        for (j = 0; j < k->nelts; j = j + 2) {
            if (context->parser->mode == CPARSER_MODE_WRITE) {
                if (context->parser->fp == NULL) {
                    return;
                } else {
                    cli_fprintf(context, "source-ip access-rate statistic-cycle %s request-times %s\n",
                        str[j], str[j+1]);
                }
            } else {
                cli_printf(context, "source-ip access-rate statistic-cycle %s request-times %s\n",
                        str[j], str[j+1]);
            }
        }
    } else if (type == REFERRER_URL) {
        for (j = 0; j < k->nelts; j = j + 2) {
            if (context->parser->mode == CPARSER_MODE_WRITE) {
                if (context->parser->fp == NULL) {
                    return;
                } else {
                    cli_fprintf(context, "referrer-url access-rate statistic-cycle %s request-times %s\n",
                        str[j], str[j+1]);
                }
            } else {
                cli_printf(context, "referrer-url access-rate statistic-cycle %s request-times %s\n",
                        str[j], str[j+1]);
            }
        }
    } else if (type == STATUS_408_RATE) {
        for (j = 0; j < k->nelts; j = j + 2) {
            if (context->parser->mode == CPARSER_MODE_WRITE) {
                if (context->parser->fp == NULL) {
                    return;
                } else {
                    cli_fprintf(context, "source-ip status-408-rate statistic-cycle %s response-times %s\n",
                        str[j], str[j+1]);
                }
            } else {
                cli_printf(context, "source-ip status-408-rate statistic-cycle %s response-times %s\n",
                    str[j], str[j+1]);
            }
        }
    }
}

void cc_url_by_type(int type, apr_array_header_t *k, cparser_context_t *context)
{
    int j;
    char **str;
    
    str = (char**)k->elts; 
    if (type == CC_PLAIN_URL) {
        for (j = 0; j < k->nelts; j = j + 1) {
            if (context->parser->mode == CPARSER_MODE_WRITE) {
                if (context->parser->fp == NULL) {
                    return;
                } else {
                    cli_fprintf(context, "url plain-text %s\n", str[j]);
                }
            } else {
                cli_printf(context, "url plain-text %s\n", str[j]);
            }
        }
    } else if (type == CC_REGEX_URL) {
        for (j = 0; j < k->nelts; j = j + 1) {
            if (context->parser->mode == CPARSER_MODE_WRITE) {
                if (context->parser->fp == NULL) {
                    return;
                } else {
                    cli_fprintf(context, "url regular-exp %s\n", str[j]);
                }
            } else {
                cli_printf(context, "url regular-exp %s\n", str[j]);
            }
        }
    } else if (type == URL_ACCESS_RATE) {
        for (j = 0; j < k->nelts; j = j + 2) {
            if (context->parser->mode == CPARSER_MODE_WRITE) {
                if (context->parser->fp == NULL) {
                    return;
                } else {
                    cli_fprintf(context, "access-rate statistic-cycle %s request-times %s\n",
                        str[j], str[j+1]);
                }
            } else {
                cli_printf(context, "access-rate statistic-cycle %s request-times %s\n",
                        str[j], str[j+1]);    
            }
        }
    }
}

void weakpwd_url_c2p_process(apr_pool_t *ptemp, cparser_context_t *context, int type, char **url, char *str)
{
    char *c2p_str, *temp_str;

    if (strcmp(url[0], str)) {        
        c2p_str = apr_pstrdup(ptemp, (char *)context->cookie[context->parser->root_level]);
        c2p_str = apr_pstrcat(ptemp, c2p_str, " ", NULL);
        c2p_str = apr_pstrcat(ptemp, c2p_str, url[0], NULL);
        c2p_str = apr_pstrcat(ptemp, c2p_str, " ", NULL);
        c2p_str = apr_pstrcat(ptemp, c2p_str, apr_itoa(ptemp, type), NULL);

        strncpy((char *)context->cookie[context->parser->root_level], c2p_str, MAX_SCPNAME_LEN);
        temp_str = (char *)context->cookie[context->parser->root_level];

        str = apr_pstrdup(ptemp, url[0]);
        context->parser->cur_node = &cparser_node_scp_weak_password_protect_option_root_url_type_url_string_password_name_passwordname_eol;
        context->parser->root_level++;       
        context->parser->root[context->parser->root_level] = context->parser->cur_node->children; 
        cparser_walk(context->parser, cparser_running_conf_walker, NULL, temp_str);
        context->parser->root_level--;
    }
}

void subpolicy_sum(generate_subpolicy_t *subpolicy, int *sub_policy_num, int *enable_num, 
    int *disable_num)
{
    (*sub_policy_num)++;
    
    if (subpolicy) {
        if (subpolicy->status == 1) {
            (*enable_num)++;
        } else {
            (*disable_num)++;
        }
    } 

    return;
}

void securitypolicy_sum(security_policy_t *ring_tmp, int *sub_policy_num, int *enable_num, 
    int *disable_num)
{
    subpolicy_sum(&(ring_tmp->sql_subply), sub_policy_num, enable_num, disable_num);
    subpolicy_sum(&(ring_tmp->xss_subply), sub_policy_num, enable_num, disable_num);
    subpolicy_sum(&(ring_tmp->ldap_subply), sub_policy_num, enable_num, disable_num);
    subpolicy_sum(&(ring_tmp->email_subply), sub_policy_num, enable_num, disable_num);
    subpolicy_sum(&(ring_tmp->code_subply), sub_policy_num, enable_num, disable_num);
    subpolicy_sum(&(ring_tmp->null_subply), sub_policy_num, enable_num, disable_num);
    subpolicy_sum(&(ring_tmp->csrf_subply), sub_policy_num, enable_num, disable_num);
    subpolicy_sum(&(ring_tmp->overflow_subply), sub_policy_num, enable_num, disable_num);
    subpolicy_sum(&(ring_tmp->base_subply), sub_policy_num, enable_num, disable_num);
    subpolicy_sum(&(ring_tmp->file_subply), sub_policy_num, enable_num, disable_num);
    subpolicy_sum(&(ring_tmp->path_subply), sub_policy_num, enable_num, disable_num);
    subpolicy_sum(&(ring_tmp->dir_subply), sub_policy_num, enable_num, disable_num);
    subpolicy_sum(&(ring_tmp->xml_subply), sub_policy_num, enable_num, disable_num);
    subpolicy_sum(&(ring_tmp->spider_subply), sub_policy_num, enable_num, disable_num);
    subpolicy_sum(&(ring_tmp->weakpwd_subply), sub_policy_num, enable_num, disable_num);
    subpolicy_sum((generate_subpolicy_t*)(&(ring_tmp->protocol_subply)), sub_policy_num, 
        enable_num, disable_num);
    subpolicy_sum(&(ring_tmp->cmd_subply), sub_policy_num, enable_num, disable_num);
    subpolicy_sum((generate_subpolicy_t*)(&(ring_tmp->cookie_subply)), sub_policy_num, 
        enable_num, disable_num);
    subpolicy_sum((generate_subpolicy_t*)(&(ring_tmp->fileup_subply)), sub_policy_num, 
        enable_num, disable_num);
    subpolicy_sum(&(ring_tmp->filedown_subply), sub_policy_num, enable_num, disable_num);
    subpolicy_sum(&(ring_tmp->trojan_subply), sub_policy_num, enable_num, disable_num);
    subpolicy_sum(&(ring_tmp->server_subply), sub_policy_num, enable_num, disable_num);
    subpolicy_sum(&(ring_tmp->version_subply), sub_policy_num, enable_num, disable_num);
    subpolicy_sum(&(ring_tmp->iccard_subply), sub_policy_num, enable_num, disable_num);
    subpolicy_sum(&(ring_tmp->http_subply), sub_policy_num, enable_num, disable_num);
    subpolicy_sum(&(ring_tmp->program_subply), sub_policy_num, enable_num, disable_num);
    subpolicy_sum(&(ring_tmp->magcard_subply), sub_policy_num, enable_num, disable_num);
    subpolicy_sum(&(ring_tmp->idcard_subply), sub_policy_num, enable_num, disable_num);
    subpolicy_sum(&(ring_tmp->request_subply), sub_policy_num, enable_num, disable_num);
    subpolicy_sum(&(ring_tmp->keyword_subply), sub_policy_num, enable_num, disable_num);
    subpolicy_sum((generate_subpolicy_t*)(&(ring_tmp->ccprotect_subply)), sub_policy_num, 
        enable_num, disable_num);
}

void subpolicy_show(cparser_context_t *context, generate_subpolicy_t *p)
{
    cli_printf_info(context, "  %-4d", (p->sec_subpolicy + 1));
    cli_printf_info(context, "%-35s", subpolicy_type[p->sec_subpolicy]);

    if (p->action == 1) {
        cli_printf_info(context, "drop    ");
    } else if (p->action == 2) {
        cli_printf_info(context, "deny    ");
    } else if (p->action == -1){
        cli_printf_info(context, "--      ");
    } else {
        cli_printf_info(context, "pass    ");
    }

    if (p->log == 0) {
        cli_printf_info(context, "N    ");
    } else {
        cli_printf_info(context, "Y    ");
    }

    if (p->status == 0) {
        cli_printf_info(context, "disable\n");
    } else if (p->status == -1){
        cli_printf_info(context, "--\n");
    } else {
        cli_printf_info(context, "enable\n");
    } 

    return;
}

static void subpolicy_show_viatype(cparser_context_t *context, generate_subpolicy_t *p)
{
    cli_printf_info(context, "%s configuration as follows:\n", subpolicy_type[p->sec_subpolicy]);
    cli_printf_info(context, " Action:");
    if (p->action == 1) {
        cli_printf_info(context, "  drop\n");
    } else if (p->action == 2) {
        cli_printf_info(context, "  deny\n");
    } else if (p->action == -1){
        cli_printf_info(context, "  --\n");
    } else {
        cli_printf_info(context, "  pass\n");
    }

    cli_printf_info(context, " Log:");
    if (p->log == 0) {
        cli_printf_info(context, "     N\n");
    } else {
        cli_printf_info(context, "     Y\n");
    }

    cli_printf_info(context, " Status:");
    if (p->status == 0) {
        cli_printf_info(context, "  disable\n");
    } else if (p->status == -1){
        cli_printf_info(context, "  --\n");
    } else {
        cli_printf_info(context, "  enable\n");
    }     
}

void scp_show_viatype(cparser_context_t *context,security_policy_t *ring_tmp, int type) 
{
    switch (type) {
    case SQL_INJECTION:
        subpolicy_show_viatype(context, &(ring_tmp->sql_subply));
        break;
    case LDAP_INJECTION:
         subpolicy_show_viatype(context, &(ring_tmp->ldap_subply));
        break;
    case EMAIL_INJECTION:
        subpolicy_show_viatype(context, &(ring_tmp->email_subply));
        break;
    case COMMAND_INJECTION:
        subpolicy_show_viatype(context, &(ring_tmp->cmd_subply));
        break;
    case CODE_INJECTION:
        subpolicy_show_viatype(context, &(ring_tmp->code_subply));
        break;
    case NULL_BYTE_INJECTION:
        subpolicy_show_viatype(context, &(ring_tmp->null_subply));
        break;
    case XSS:
        subpolicy_show_viatype(context, &(ring_tmp->xss_subply));
        break;
    case CSRF:
        subpolicy_show_viatype(context, &(ring_tmp->csrf_subply));
        break;
    case OVERFLOW:
        subpolicy_show_viatype(context, &(ring_tmp->overflow_subply));
        break;
    case FILE_INCLUDE:
        subpolicy_show_viatype(context, &(ring_tmp->file_subply));
        break;
    case BASE_ATTACK:
        subpolicy_show_viatype(context, &(ring_tmp->base_subply));
        break;
    case PATH_TRAVERSAL:
        subpolicy_show_viatype(context, &(ring_tmp->path_subply));
        break;
    case DIRECTORY_INDEX:
        subpolicy_show_viatype(context, &(ring_tmp->dir_subply));
        break;
    case SPIDER_SCANNER:
        subpolicy_show_viatype(context, &(ring_tmp->spider_subply));
        break;
    case TROJAN:
        subpolicy_show_viatype(context, &(ring_tmp->trojan_subply));
        break;
    case XML_ATTACK:
        subpolicy_show_viatype(context, &(ring_tmp->xml_subply));
        break;
    case WEAK_PASSWORD:
        subpolicy_show_viatype(context, &(ring_tmp->weakpwd_subply));
        break;
    case SERVER_VERSION:
        subpolicy_show_viatype(context, &(ring_tmp->version_subply));
        break;
    case HTTP_STATUS_CODE:
        subpolicy_show_viatype(context, &(ring_tmp->http_subply));
        break;
    case ICCARD_INFORMATION:
        subpolicy_show_viatype(context, &(ring_tmp->iccard_subply));
        break;
    case SERVER_ERROR_INFO:
        subpolicy_show_viatype(context, &(ring_tmp->server_subply));
        break;
    case PROGRAM_CODE:
        subpolicy_show_viatype(context, &(ring_tmp->program_subply));
        break;
    case MAGCARD_INFORMATION:
        subpolicy_show_viatype(context, &(ring_tmp->magcard_subply));
        break;
    case IDCARD_INFORMATION:
        subpolicy_show_viatype(context, &(ring_tmp->idcard_subply));
        break;
    case FILE_DOWNLOAD:
        subpolicy_show_viatype(context, &(ring_tmp->filedown_subply));
        break;
    case FILE_UPLOAD:
        subpolicy_show_viatype(context, (generate_subpolicy_t*)(&(ring_tmp->fileup_subply)));
        break;
    case COOKIE:
        subpolicy_show_viatype(context, (generate_subpolicy_t*)(&(ring_tmp->cookie_subply)));
        break;
    case PROTOCOL_PARAM:
        subpolicy_show_viatype(context, (generate_subpolicy_t*)(&(ring_tmp->protocol_subply)));
        break;
    case REQUEST_METHOD:
        subpolicy_show_viatype(context, &(ring_tmp->request_subply));
        break;
    case KEYWORD_FILTER:
        subpolicy_show_viatype(context, &(ring_tmp->keyword_subply));
        break;
    case CC_PROTECT:
        subpolicy_show_viatype(context, (generate_subpolicy_t*)(&(ring_tmp->ccprotect_subply)));
        break;
    default:
        break;
    }

    return;
}

void securitypolicy_show(cparser_context_t *context, security_policy_t *ring_tmp) 
{
    subpolicy_show(context, &(ring_tmp->sql_subply));
    subpolicy_show(context, &(ring_tmp->ldap_subply));
    subpolicy_show(context, &(ring_tmp->email_subply));
    subpolicy_show(context, &(ring_tmp->cmd_subply));
    subpolicy_show(context, &(ring_tmp->code_subply));
    subpolicy_show(context, &(ring_tmp->null_subply));
    subpolicy_show(context, &(ring_tmp->xss_subply));
    subpolicy_show(context, &(ring_tmp->csrf_subply));
    subpolicy_show(context, &(ring_tmp->overflow_subply));
    subpolicy_show(context, &(ring_tmp->file_subply));
    subpolicy_show(context, &(ring_tmp->base_subply));
    subpolicy_show(context, &(ring_tmp->path_subply));
    subpolicy_show(context, &(ring_tmp->dir_subply));
    subpolicy_show(context, &(ring_tmp->spider_subply));
    subpolicy_show(context, &(ring_tmp->trojan_subply));
    subpolicy_show(context, &(ring_tmp->xml_subply));
    subpolicy_show(context, &(ring_tmp->weakpwd_subply));
    subpolicy_show(context, &(ring_tmp->version_subply));
    subpolicy_show(context, &(ring_tmp->http_subply));
    subpolicy_show(context, &(ring_tmp->iccard_subply));
    subpolicy_show(context, &(ring_tmp->server_subply));
    subpolicy_show(context, &(ring_tmp->program_subply));
    subpolicy_show(context, &(ring_tmp->magcard_subply));
    subpolicy_show(context, &(ring_tmp->idcard_subply));
    subpolicy_show(context, &(ring_tmp->filedown_subply));
    subpolicy_show(context, (generate_subpolicy_t*)(&(ring_tmp->fileup_subply)));
    subpolicy_show(context, (generate_subpolicy_t*)(&(ring_tmp->cookie_subply)));
    subpolicy_show(context, (generate_subpolicy_t*)(&(ring_tmp->protocol_subply)));
    subpolicy_show(context, &(ring_tmp->request_subply));
    subpolicy_show(context, &(ring_tmp->keyword_subply));
    subpolicy_show(context, (generate_subpolicy_t*)(&(ring_tmp->ccprotect_subply)));

    return;
}

void cookie_verification_method_printf(cparser_context_t *context, int type, int flag)
{
    cli_printf_info(context, "   Method:");
    if (flag == SIGNATURE) {
        cli_printf_info(context, "        signature\n");
    } else {
        cli_printf_info(context, "        encryption\n");
    }
    cli_printf_info(context, "   Content:");
    if (type == COOKIE_VERTFICATION) {
        cli_printf_info(context, "       cookie\n");
    } else {
        cli_printf_info(context, "       ip-and-cookie\n");
    }
}

static void cookie_show(cparser_context_t *context, const apr_array_header_t *result)
{
    int i, j;
    apr_array_header_t *k;
    keyword_t **kw, *kw_sub;
    int cookie_name_num;
    int value_printed;
    char **str;

    kw = (keyword_t**)result->elts;

    cli_printf_info(context, " Expire-Time:    ");
    value_printed = 0;
    for (i = 0; i < result->nelts; i++) {
        kw_sub = kw[i];  
        if (kw_sub->type == EXPIRE_TIME) {
            k = kw_sub->keyword;
            str = (char**)k->elts; 
            for (j = 0; j < k->nelts; j++) {
                cli_printf_info(context, " %s (Min)\n", str[j]);
                value_printed = 1;
                break;
            }  
            break;
        }
    }
    if (!value_printed) {
        cli_printf_info(context, " --\n");
    }

    cli_printf_info(context, " Verification:\n");
    value_printed = 0;
    for (i = 0; i < result->nelts; i++) {
        kw_sub = kw[i];
        if (kw_sub->type == VERIFICATION) {
            k = kw_sub->keyword;
            str = (char**)k->elts; 
            for (j = 0; j < k->nelts; j = j + 2) {
                cookie_verification_method_printf(context, 
                    apr_atoi64(str[j + 1]), apr_atoi64(str[j]));          
                break;
            }
            value_printed = 1;
            break;
        }
    }
    if (!value_printed) {
        cli_printf_info(context, "   Method:        --\n");
        cli_printf_info(context, "   Content:       --\n");
    }

    cli_printf_info(context, " Attribution:    ");
    value_printed = 0;
    for (i = 0; i < result->nelts; i++) {
        kw_sub = kw[i];
        if (kw_sub->type == ATTRIBUTION) {
            k = kw_sub->keyword;
            str = (char**)k->elts;              
            for (j = 0; j < k->nelts; j++) {
                switch(apr_atoi64(str[j])) {
                case SECURE:
                    cli_printf_info(context, " secure\n");
                    break;
                case HTTPDONLY:
                    cli_printf_info(context, " httponly\n");
                    break;
                case SECURE_HTTPONLY:
                    cli_printf_info(context, " secure httponly\n");
                    break;
                default:
                    cli_printf_info(context, " --\n");
                    break;
                }
                value_printed = 1;
                break;
            }
            break;
        }
    }
    if (!value_printed) {
        cli_printf_info(context, " --\n");
    }
    
    cli_printf_info(context, " Cookie-Name configuration as follows:\n");
    cli_printf_info(context, "  No.    Cookie-Name\n");
    cookie_name_num = 0;
    for (i = 0; i < result->nelts; i++) {
        kw_sub = kw[i]; 
        if (kw_sub->type == COOKIE_NAME) {
            k = kw_sub->keyword;
            str = (char**)k->elts; 
            for (j = 0; j < k->nelts; j++) {
                cli_printf_info(context, "  %-3d    %s\n", ++cookie_name_num, str[j]); 
            }
        }
    }
}

void protocol_show(cparser_context_t *context, const apr_array_header_t *result)
{
    int i, j;
    char **str, *str_sub;
    apr_array_header_t *k;
    keyword_t **kw, *kw_sub;
    int type;

    kw = (keyword_t**)result->elts;
    for (i = 0; i < result->nelts; i++) {
        kw_sub = kw[i];
        k = kw_sub->keyword;
        type = kw_sub->type;
        str = (char**)k->elts;     
        for (j = 0; j < k->nelts; j++) {
            str_sub = str[j];
            switch(type) {
            case REQUEST_HEADER_NUM:
                cli_printf_info(context, " Request_Header_Num:               %s\n", str_sub);
                break;
            case HEADER_SIZE_EXCEPT_COOKIE:
                cli_printf_info(context, " Header_Size_Except_Cookie:        %s (B)\n", str_sub);
                break;
            case COOKIE_SIZE:
                cli_printf_info(context, " Cookie_Size:                      %s (B)\n", str_sub);
                break;
            case REQUEST_URL_SIZE:
                cli_printf_info(context, " Request_URL_Size:                 %s (B)\n", str_sub);
                break;
            case QUERY_STRING_SIZE:
                cli_printf_info(context, " Query_String_Size:                %s (B)\n", str_sub);
                break;
            case ARGUMENT_NUM:
                cli_printf_info(context, " Request_Argument_Num:             %s\n", str_sub);
                break;
            case ARGUMENT_NAME_SIZE:
                cli_printf_info(context, " Request_Argument_Name_Size:       %s (B)\n", str_sub);
                break;
            case ARGUMENT_NAME_VALUE_SIZE:
                cli_printf_info(context, " Request_Argument_Name_Value_Size: %s (B)\n", str_sub);
                break;
            case BODY_SIZE:
                cli_printf_info(context, " Request_Body_Size:                %d (MiB)\n", apr_atoi64(str_sub) / (1 << 20));
                break;
            default:
                break;
            }
        }
    }
}

void file_upload_show(cparser_context_t *context, const apr_array_header_t *result)
{
    int i, j;
    char **str;
    apr_array_header_t *k;
    keyword_t **kw, *kw_sub;
    int key_num;

    kw = (keyword_t**)result->elts;

    cli_printf_info(context, " Individual-File-Size: ");
    for (i = 0; i < result->nelts; i++) {
        kw_sub = kw[i];
        if (kw_sub->type == INDIVIDUAL_FILE_SIZE) {
            k = kw_sub->keyword;
            str = (char**)k->elts; 
            for (j = 0; j < k->nelts; j++) {
                cli_printf_info(context, " %d (MiB)\n", apr_atoi64(str[j])/(1 << 20));
                break;
            }            
        }
    }

    cli_printf_info(context, " All-File-Size:        ");
    for (i = 0; i < result->nelts; i++) {
        kw_sub = kw[i];
        if (kw_sub->type == ALL_FILE_SIZE) {
            k = kw_sub->keyword;
            str = (char**)k->elts; 
            for (j = 0; j < k->nelts; j++) {
                cli_printf_info(context, " %d (MiB)\n", apr_atoi64(str[j])/(1 << 20));
                break;
            }            
        }
    }

    cli_printf_info(context, " Keyword configuration as follows:\n");
    cli_printf_info(context, "  No.    Filename-Extension\n");
    key_num = 0;
    for (i = 0; i < result->nelts; i++) {
        kw_sub = kw[i]; 
        if (kw_sub->type == FILE_TYPE && kw_sub->flag == OUTER_KEYWORD) {  
            k = kw_sub->keyword;
            str = (char**)k->elts;               
            for (j = 0; j < k->nelts; j++) {
                cli_printf_info(context, "  %-3d    %s\n", ++key_num, str[j]);       
            }
        }
    }
}

void keyword_filter_show(cparser_context_t *context, const apr_array_header_t *result)
{
    int i, j;
    char **str;
    apr_array_header_t *k;
    keyword_t **kw, *kw_sub;

    kw = (keyword_t**)result->elts;
    for (i = 0; i < result->nelts; i++) {
        kw_sub = kw[i];
        k = kw_sub->keyword;
        str = (char**)k->elts;  
        for (j = 0; j < k->nelts; j = j + 2) {
            switch(apr_atoi64(str[j+1])) {
            case URL:
                cli_printf_info(context, "  keyword %s url\n",  str[j]);
                break;
            case KEY_COOKIE:
                cli_printf_info(context, "  keyword %s cookie\n",  str[j]);
                 break;
            case POST:
                cli_printf_info(context, "  keyword %s post\n",  str[j]);
                break;
            case REQUEST_BODY:
                cli_printf_info(context, "  keyword %s request-body\n",  str[j]);
                break;
            case RESPONSE_BODY:
                cli_printf_info(context, "  keyword %s response-body\n",  str[j]);
                break;
            default:
                break;
            }
        }
    }  
}

void cc_protect_show(cparser_context_t *context, const apr_array_header_t *result) 
{
    int i, j;
    char **str;
    apr_array_header_t *k;
    keyword_t **kw, *kw_sub;
    int type;
    int num;

    kw = (keyword_t**)result->elts;

    cli_printf_info(context, " Statistic cycle configuration as follows:\n");
    cli_printf_info(context, "  No.    Type            Statistic-Sycle(Sec)    Request-Times\n");
    num = 0;
    for (i = 0; i < result->nelts; i++) {
        kw_sub = kw[i];
        k = kw_sub->keyword;
        type = kw_sub->type;
        str = (char**)k->elts; 
        if (type == URL_ACCESS_RATE) {
            for (j = 0; j < k->nelts; j = j + 2) {
                cli_printf_info(context, "  %-3d    %-12s    %-20s    %-13s\n",
                    ++num, "url", str[j], str[j + 1]);
            }
        } else if (type == SOURCE_IP) {
            for (j = 0; j < k->nelts; j = j + 2) {
                cli_printf_info(context, "  %-3d    %-12s    %-20s    %-13s\n",
                    ++num, "source-ip", str[j], str[j + 1]);
            }
        } else if (type == REFERRER_URL) {
            for (j = 0; j < k->nelts; j = j + 2) {
                cli_printf_info(context, "  %-3d    %-12s    %-20s    %-13s\n",
                    ++num, "referrer-url", str[j], str[j + 1]);
            }
        } else if (type == STATUS_408_RATE) {
            for (j = 0; j < k->nelts; j = j + 2) {
                cli_printf_info(context, "  %-3d    %-12s    %-20s    %-13s\n",
                    ++num, "status-408", str[j], str[j + 1]);
            }
        }
    }

    cli_printf_info(context, " URL configuration as follows:\n");
    cli_printf_info(context, "  No.    Type           URL\n");
    num  = 0;
    for (i = 0; i < result->nelts; i++) {
        kw_sub = kw[i];
        k = kw_sub->keyword;
        type = kw_sub->type;
        str = (char**)k->elts;          
        for (j = 0; j < k->nelts; j = j + 1) {
            if (type == CC_PLAIN_URL) {
                cli_printf_info(context, "  %-3d    Plain-Text     %s\n", ++num, str[j]);
            } else if(type == CC_REGEX_URL) {
                cli_printf_info(context, "  %-3d    Regular-Exp    %s\n", ++num, str[j]);
            }
        }
    }
}

void keyword_show(int type, apr_pool_t *ptemp, cparser_context_t *context) 
{
    int i, j;
    char **str;
    char sec_policy_name[NAME_LEN_MAX];
    apr_array_header_t *result, *k;
    keyword_t **kw, *kw_sub;
    int key_num;
    char *last_url;
    int keyword_type;
    int last_type, cur_type; 
    int flag;

    strncpy(sec_policy_name, scpname, NAME_LEN_MAX);
    result = apr_array_make(ptemp, 10, sizeof(keyword_t*));
    convert_sec_policy_list(sec_policy_name, type, &result);
    kw = (keyword_t**)result->elts; 

    switch(type) {
    /* 下面几种模式进行关键字c2p使用同一过程, 进行复用，下面情况雷同 */
    case SQL_INJECTION:
    case COMMAND_INJECTION:
    case XSS:
    case SPIDER_SCANNER:
    case TROJAN:
    case KEYWORD_FILTER:
    case CODE_INJECTION:
        cli_printf_info(context, " Keyword configuration as follows: \n");
        cli_printf_info(context, "  No.    Keyword\n");
        key_num = 0;
        for (i = 0; i < result->nelts; i++) {
            kw_sub = kw[i];
            if (kw_sub->flag == OUTER_KEYWORD) {
                k = kw_sub->keyword;
                str = (char**)k->elts;             
                for (j = 0; j < k->nelts; j++) {
                    cli_printf_info(context, "  %-3d    %s\n", ++key_num, str[j]);
                }
            }
        }

        break;      
    case WEAK_PASSWORD:        
        last_url = NULL;
        last_type = 0;
        cur_type = 0;
        key_num = 0;
        cli_printf_info(context, " URL configuration as follows: \n");
        flag  = 0;
        for (i = 0; i < result->nelts; i++) {
            kw_sub = kw[i];
            if (kw_sub->type == PLAIN_PLAIN || kw_sub->type == PLAIN_REGEX 
                        || kw_sub->type == PLAIN_URL) {
                cur_type = PLAIN;
            } else {
                cur_type = REGEX;
            }
            k = kw_sub->keyword;
            str = (char**)k->elts;
            if (last_url == NULL || strcmp(last_url, str[0]) != 0 || last_type != cur_type) {
                if (last_url != NULL) {
                    if (flag == 0) {
                        cli_printf_info(context, "    %-3d    Regular-Exp    %s\n", ++key_num, "default");
                    }
                }
                
                flag = 0;
                last_url = apr_pstrdup(ptemp, str[0]);
                last_type = cur_type;
                key_num = 0;
                cli_printf_info(context, "  URL: "); 
                cli_printf_info(context, "%s\n", str[0]);
                cli_printf_info(context, "   Type:          "); 
                if (cur_type == PLAIN) {
                    cli_printf_info(context, "Plain-Text\n");
                } else {
                    cli_printf_info(context, "Regular-Exp\n");
                }
                cli_printf_info(context, "   Password-Name:"); 
                cli_printf_info(context, " %s\n", str[1]);
    
                cli_printf_info(context, "   Keyword configuration as follows:\n");
                cli_printf_info(context, "    No.    Type           Keyword\n");
            }

            if (k->nelts >= 3) {
                if (kw_sub->type == PLAIN_PLAIN || kw_sub->type == REGEX_PLAIN) {
                    cli_printf_info(context, "    %-3d    Plain-Text     %s\n", ++key_num, str[2]);
                } else {
                    cli_printf_info(context, "    %-3d    Regular-Exp    %s\n", ++key_num, str[2]);
                    flag = 1;
                }
            }

            if (i == result->nelts -1) {
                if (flag == 0) {
                    cli_printf_info(context, "    %-3d    Regular-Exp    %s\n", ++key_num, "default");    
                }
            }
        }
        
        break;
    case SERVER_VERSION:
    case ICCARD_INFORMATION:
    case IDCARD_INFORMATION:
        cli_printf_info(context, " Keyword configuration as follows:\n");
        cli_printf_info(context, "  No.    Old-Keyword             New-Keyword\n");
        key_num = 0;
        for (i = 0; i < result->nelts; i++) {
            kw_sub = kw[i];
            k = kw_sub->keyword;
            str = (char**)k->elts;              
            for (j = 0; j < k->nelts; j = j + 2) {
                cli_printf_info(context, "  %-3d    %-20s    %s\n",
                    ++key_num, str[j + 1], str[j]);
            }
        }

        break;
    case CSRF:
        cli_printf_info(context, " Cookie-Name configuration as follows:\n");
        cli_printf_info(context, "  No.    Cookie-Name\n");
        key_num = 0;
        for (i = 0; i < result->nelts; i++) {
            kw_sub = kw[i];
            k = kw_sub->keyword;
            keyword_type = kw_sub->type;
            str = (char**)k->elts;

            if (keyword_type == CSRF_COOKIE_NAME) {
                cli_printf_info(context, "  %-3d    %s\n", ++key_num, *str);
            }
        }

        cli_printf_info(context, " Url configuration as follows:\n");
        cli_printf_info(context, "  No.    Type              URL\n");
        key_num = 0;
        for (i = 0; i < result->nelts; i++) {
            kw_sub = kw[i];
            k = kw_sub->keyword;
            keyword_type = kw_sub->type;
            str = (char**)k->elts;

            if (keyword_type == CSRF_URL_PLAIN) {
                cli_printf_info(context, "  %-3d    Plain-Text        %s\n", ++key_num, *str);
            } else if (keyword_type == CSRF_URL_REGEX) {
                cli_printf_info(context, "  %-3d    Regular-Exp       %s\n", ++key_num, *str);
            }
        }
        
        break;
    case FILE_DOWNLOAD:
        cli_printf_info(context, " Keyword configuration as follows:\n");
        cli_printf_info(context, "  No.    Filename-Extension\n");
        key_num = 0;
        for (i = 0; i < result->nelts; i++) {
            kw_sub = kw[i];
            k = kw_sub->keyword;
            if (kw_sub->flag == OUTER_KEYWORD) {
                str = (char**)k->elts;
                for (j = 0; j < k->nelts; j++) {
                    cli_printf_info(context, "  %-3d    %s\n", ++key_num, str[j]);
                }
            }
        }

        break;
    case FILE_UPLOAD:
        file_upload_show(context, result);
        
        break;
    case COOKIE:  
        cookie_show(context, result);
        
        break;
    case PROTOCOL_PARAM:
        protocol_show(context, result);
        
        break;
    case REQUEST_METHOD:
        cli_printf_info(context, " Method configuration as follows:\n");
        cli_printf_info(context, "  No.    Method\n");
        key_num = 0;
        for (i = 0; i < result->nelts; i++) {
            kw_sub = kw[i];
            k = kw_sub->keyword;
            str = (char**)k->elts;
            for (j = 0; j < k->nelts; j++) {
                cli_printf_info(context, "  %-3d    %s\n", ++key_num, str[j]);
            }
        }

        break;
    case CC_PROTECT:
        cc_protect_show(context, result);

        break;
    default:
        break;
    }   

    return;
}

