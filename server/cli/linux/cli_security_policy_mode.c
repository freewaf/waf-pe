/*
 * $Id: cli_security_policy_mode.c 2786 2013-07-09 16:42:55 FreeWAF Development Team $
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

char *subpolicy_type[SUBPOLICY_NUM] = 
    {   "sql-injection-protect",
        "ldap-injection-protect",
        "email-injection-protect",
        "command-injection-protect",
        "code-injection-protect",
        "null-byte-injection-protect",
        "xss-attack-protect",
        "csrf-attack-protect",
        "overflow-attack-protect",
        "file-include-attack-protect",
        "misc-attack-protect",
        "path-traversal-attack-protect",
        "directory-index-protect",
        "spider-scanner-attack-protect",
        "trojan-protect",
        "xml-attack-protect",
        "weak-password-protect",
        "server-version-protect",
        "http-status-code-protect",
        "creditcard-information-protect",
        "server-error-information-protect",
        "program-code-protect",
        "magcard-information-protect",
        "idcard-information-protect",
        "file-download-protect",
        "file-upload-protect",
        "cookie-protect",
        "protocol-param-protect",
        "request-method-protect",
        "keyword-filter",
        "cc-protect"
    };

char scpname[MAX_SCPNAME_LEN];
apr_pool_t *psec;
struct security_list_head sec_policy_ring;

AP_DECLARE(int) security_policy_init(apr_pool_t *p)
{
    int rv;
    
    /* 分配安全策略的内存池 */
    rv = apr_pool_create(&psec, p); 
    if (rv) {
        return DECLINED;
    }
    
    apr_pool_tag(psec, "psec");  
    APR_RING_INIT(&sec_policy_ring, security_policy_s, ring);

#if 0
    rv = ap_secpolicy_list_add("default");
    if (rv != OK) {
        printf("create default security policy failure in security-policy list\n");           
        return DECLINED;
    }
#endif

    return OK;
}

/* 下面两个接口用来处理安全策略的配置 */
cparser_result_t cparser_cmd_pe_protect_engine_security_policy_secpname(cparser_context_t *context,
                    char **secpname_ptr)
{
    char prompt[CPARSER_MAX_PROMPT];
    char sec_policy_name[NAME_LEN_MAX];
    security_policy_t *ring_tmp, *ring_tmp_n;
    char temp_str[MAX_SCPNAME_LEN];
    char buf[COMMAND_LEN_MAX];

    if (context == NULL) {
        return CPARSER_NOT_OK;
    }
    
    if (context->parser->mode != CPARSER_MODE_CONFIG) {
        strncpy(temp_str, scpname, MAX_SCPNAME_LEN);
        /* 遍历安全策略链表 */
      //  strncpy(temp_str, scpname, STR_LEN_MAX);
        APR_RING_FOREACH_SAFE(ring_tmp, ring_tmp_n, &sec_policy_ring, security_policy_s, ring) {
            if (context->parser->mode == CPARSER_MODE_WRITE) {
                if (context->parser->fp == NULL) {
                    return CPARSER_NOT_OK;
                }
                
                cli_fprintf(context, "protect-engine security-policy %s\n", ring_tmp->name);
            } else {
                cli_printf(context, "!\n");
                cli_printf(context, "protect-engine security-policy %s\n", ring_tmp->name);
            }

            strncpy(scpname, ring_tmp->name, MAX_SCPNAME_LEN);
            
            context->parser->root_level++;
            context->parser->root[context->parser->root_level] = context->parser->cur_node->children;
            cparser_walk(context->parser, cparser_running_conf_walker, NULL, scpname);
            context->parser->cur_node = &cparser_node_st_configure_root_protect_engine_security_policy_secpname_eol;
            context->parser->root_level--; 
        }

        strncpy(scpname, temp_str, MAX_SCPNAME_LEN);
    } else {                                /* 添加一个安全策略 */
        if (secpname_ptr == NULL || *secpname_ptr == NULL) {
            return CPARSER_NOT_OK;
        }

        /* 由于show命令中存在detail关键字，会和安全策略名冲突，故约定不能创建detail安全策略 */
        if (strcmp(*secpname_ptr, "detail") == 0) {
            cli_printf_info(context, "can not create detail security policy\n");
            return CPARSER_OK;
        }

        /* 由于show命令中约定用'--'做为空的意思，故不能创建名为'--' 安全策略 */
        if (strcmp(*secpname_ptr, "--") == 0) {
            cli_printf_info(context, "can not create -- security policy\n");
            return CPARSER_NOT_OK;
        }
        
#if 0
        if (strcmp(*secpname_ptr, "default") == 0) {
            cli_printf_info(context, "can not create default security policy\n");
            return CPARSER_OK;
        }
#endif        
        sprintf(buf, "protect-engine security-policy %s", *secpname_ptr);
        admin_log_process(context, buf);
        
        strncpy(sec_policy_name, *secpname_ptr, NAME_LEN_MAX);
        sec_policy_name[NAME_LEN_MAX - 1] = '\0';
        
        APR_RING_FOREACH_SAFE(ring_tmp, ring_tmp_n, &sec_policy_ring, security_policy_s, ring) {
            if (!strncmp(sec_policy_name, ring_tmp->name, NAME_LEN_MAX)) { 
                goto _pe_security_policy_mode;
            }
        }
        
        add_security_policy(context, sec_policy_name);
        
_pe_security_policy_mode:    
        snprintf(prompt, CPARSER_MAX_PROMPT, "%s(security-policy)#", g_cli_prompt);
        strncpy(scpname, sec_policy_name, NAME_LEN_MAX);
        return cparser_submode_enter(context->parser, scpname, prompt);    
    }

    return CPARSER_OK;
}
    
cparser_result_t cparser_cmd_pe_no_protect_engine_security_policy_secpname(cparser_context_t *context,
                    char **secpname_ptr)
{
    security_policy_t *ring_tmp, *ring_tmp_n;
    int rv;
    char buf[COMMAND_LEN_MAX];

    if (context == NULL) {
        return CPARSER_NOT_OK;
    }
    
    if (context->parser->mode != CPARSER_MODE_CONFIG) {
        return CPARSER_OK;
    } else {
        if (secpname_ptr == NULL || *secpname_ptr == NULL) {
            return CPARSER_NOT_OK;
        }
         
        /* 不能删除默认安全策略 */
        if (!strncmp(*secpname_ptr, DEFAULT_POLICY, NAME_LEN_MAX)) {
            cli_printf_info(context, "cann't delete default policy\n");    
            return CPARSER_OK;
        }

        APR_RING_FOREACH_SAFE(ring_tmp, ring_tmp_n, &sec_policy_ring, security_policy_s, ring) {
            if (!strncmp(*secpname_ptr, ring_tmp->name, NAME_LEN_MAX)) {
                rv = ap_secpolicy_list_del(ring_tmp->name);
                if (rv != OK) {
                    cli_printf_info(context, "security policy is used by server policy, cann't deleted\n");          
                    return CPARSER_NOT_OK;
                }

                rv = convert_sec_policy_del(ring_tmp->name);
                if (rv != OK && rv != CONV_NOTEXIST) {
                    cli_printf_info(context, "delete security policy failure in convert interface\n");        
                    return CPARSER_NOT_OK;
                }

                APR_RING_REMOVE(ring_tmp, ring);
                apr_pool_destroy(ring_tmp->pool);

                break;
            }
        }
        
        if (ring_tmp == APR_RING_SENTINEL(&sec_policy_ring, security_policy_s, ring)) {
            cli_printf_info(context, "the deleted security policy does not exist\n");     
            return CPARSER_OK;
        }

        sprintf(buf, "no protect-engine security-policy %s", *secpname_ptr);
        admin_log_process(context, buf);
    }
    
    return CPARSER_OK;
}

/* 下面四个函数接口用来配置sql注入防护 */
cparser_result_t cparser_cmd_scp_sql_injection_protect_option(cparser_context_t *context,
    char **option_ptr)
{
    char prompt[CPARSER_MAX_PROMPT];
    security_policy_t *ring_tmp, *ring_tmp_n;
    int rv;
    char *temp;
    char buf[COMMAND_LEN_MAX];

    transfer_security_policy_name(context);
    temp = (char *)context->cookie[context->parser->root_level];
    
    if (context == NULL) {
        return CPARSER_NOT_OK;
    }
    
    if (context->parser->mode != CPARSER_MODE_CONFIG) {        
        APR_RING_FOREACH_SAFE(ring_tmp, ring_tmp_n, &sec_policy_ring, security_policy_s, ring) {
            if (strncmp(ring_tmp->name, temp, NAME_LEN_MAX) == 0) {
                cmd_c2p_sql(context,&(ring_tmp->sql_subply));
                break;
            }
        }
    } else { 
        if (option_ptr == NULL || *option_ptr == NULL) {
            return CPARSER_NOT_OK;
        }
        
        APR_RING_FOREACH_SAFE(ring_tmp, ring_tmp_n, &sec_policy_ring, security_policy_s, ring) {
            if (strncmp(ring_tmp->name, temp, NAME_LEN_MAX) == 0) {
                sec_policy_get_option(&(ring_tmp->sql_subply), option_ptr, buf);
                (ring_tmp->sql_subply).action = ACTION_PASS;
                (ring_tmp->sql_subply).log = 0;
                (ring_tmp->sql_subply).flag = 1;
                
                rv = convert_sec_subpolicy_set((sec_subpolicy_t*)&(ring_tmp->sql_subply));
                if (rv != APR_SUCCESS) {
                    cli_printf_info(context, "sql-injection-protect set failure\n");
                    return CPARSER_NOT_OK;
                }

                admin_log_process(context, buf);   
                break;
            }
        }

        snprintf(prompt, CPARSER_MAX_PROMPT, "%s(sql-injection)#", g_cli_prompt);
        return cparser_submode_enter(context->parser, temp, prompt);
    }

    return CPARSER_OK;
}

cparser_result_t cparser_cmd_scp_sql_injection_protect_action_action_option(cparser_context_t *context,
    char **action_ptr,
    char **option_ptr)
{
    char prompt[CPARSER_MAX_PROMPT];
    security_policy_t *ring_tmp, *ring_tmp_n;
    int rv;
    char *temp;
    char buf[COMMAND_LEN_MAX];

    transfer_security_policy_name(context);
    temp = (char *)context->cookie[context->parser->root_level];
    
    if (context == NULL) {
        return CPARSER_NOT_OK;
    }
    
    if (context->parser->mode != CPARSER_MODE_CONFIG) {
        return CPARSER_OK;
    } else {
        if (action_ptr == NULL || *action_ptr == NULL) {
            return CPARSER_NOT_OK;
        }

        APR_RING_FOREACH_SAFE(ring_tmp, ring_tmp_n, &sec_policy_ring, security_policy_s, ring) {
            if (strncmp(ring_tmp->name, temp, NAME_LEN_MAX) == 0) {
                if (option_ptr != NULL) {
                    sec_policy_get_action_option(&(ring_tmp->sql_subply), action_ptr, option_ptr, buf); 
                } else {
                    sec_policy_get_action(&(ring_tmp->sql_subply), action_ptr, buf);
                    (ring_tmp->sql_subply).status = ENABLE;
                }
                
                (ring_tmp->sql_subply).flag = 1;
                (ring_tmp->sql_subply).log = 0;
                
                rv = convert_sec_subpolicy_set((sec_subpolicy_t*)&(ring_tmp->sql_subply));
                if (rv != APR_SUCCESS) {
                    cli_printf_info(context, "sql-injection-protect set failure\n");
                    return CPARSER_NOT_OK;
                }

                admin_log_process(context, buf);
                break;
            }
        }
        
        context->parser->cur_node = &cparser_node_pe_protect_engine_security_policy_secpname_root_sql_injection_protect_option_eol;
        snprintf(prompt, CPARSER_MAX_PROMPT, "%s(sql-injection)#", g_cli_prompt);
        return cparser_submode_enter(context->parser, temp, prompt);
    }
 
    return CPARSER_OK;
}

cparser_result_t cparser_cmd_scp_sql_injection_protect_action_action_log_option(cparser_context_t *context,
    char **action_ptr,
    char **option_ptr)
{
    char prompt[CPARSER_MAX_PROMPT];
    security_policy_t *ring_tmp, *ring_tmp_n;
    int rv;
    char *temp;
    char buf[COMMAND_LEN_MAX];

    transfer_security_policy_name(context);
    temp = (char *)context->cookie[context->parser->root_level];

    if (context == NULL) {
        return CPARSER_NOT_OK; 
    }
    
    if (context->parser->mode != CPARSER_MODE_CONFIG) {
        return CPARSER_OK;
    } else {       
        APR_RING_FOREACH_SAFE(ring_tmp, ring_tmp_n, &sec_policy_ring, security_policy_s, ring) {
            if (strncmp(ring_tmp->name, temp, NAME_LEN_MAX) == 0) {
                if (option_ptr != NULL) {
                    sec_policy_get_action_log_option(&(ring_tmp->sql_subply), action_ptr, option_ptr, buf); 
                } else {
                    sec_policy_get_action_log(&(ring_tmp->sql_subply), action_ptr, buf);
                    (ring_tmp->sql_subply).status = ENABLE;
                }
                
                (ring_tmp->sql_subply).flag = 1;
                
                rv = convert_sec_subpolicy_set((sec_subpolicy_t*)&(ring_tmp->sql_subply));
                if (rv != APR_SUCCESS) {
                    cli_printf_info(context, "sql-injection-protect set failure\n");
                    return CPARSER_NOT_OK;
                }

                admin_log_process(context, buf);
                break;
            }
        }

        context->parser->cur_node = &cparser_node_pe_protect_engine_security_policy_secpname_root_sql_injection_protect_option_eol;
        snprintf(prompt, CPARSER_MAX_PROMPT, "%s(sql-injection)#", g_cli_prompt);
        return cparser_submode_enter(context->parser, temp, prompt);
    }

    return CPARSER_OK;
}

cparser_result_t cparser_cmd_scp_sql_injection_protect(cparser_context_t *context)
{
    char prompt[CPARSER_MAX_PROMPT];
    security_policy_t *ring_tmp, *ring_tmp_n;
    int rv;
    char *temp;
    char buf[COMMAND_LEN_MAX];
    transfer_security_policy_name(context);
    temp = (char *)context->cookie[context->parser->root_level];

    if (context == NULL) {
        return CPARSER_NOT_OK;
    }

    if (context->parser->mode != CPARSER_MODE_CONFIG) {
        return CPARSER_OK;
    } else {
        APR_RING_FOREACH_SAFE(ring_tmp, ring_tmp_n, &sec_policy_ring, security_policy_s, ring) {
            if (strncmp(ring_tmp->name, temp, NAME_LEN_MAX) == 0) {
                (ring_tmp->sql_subply).flag = 1;
                (ring_tmp->sql_subply).status = ENABLE;
                (ring_tmp->sql_subply).action = ACTION_PASS;
                (ring_tmp->sql_subply).log = 0;
                
                rv = convert_sec_subpolicy_set((sec_subpolicy_t*)&(ring_tmp->sql_subply));
                if (rv != APR_SUCCESS) {
                    cli_printf_info(context, "sql-injection-protect set failure\n");
                    return CPARSER_NOT_OK;
                }

                sprintf(buf, "sql-injection-protect");
                admin_log_process(context, buf);
                break;
            }
        }

        context->parser->cur_node = &cparser_node_pe_protect_engine_security_policy_secpname_root_sql_injection_protect_option_eol;
        snprintf(prompt, CPARSER_MAX_PROMPT, "%s(sql-injection)#", g_cli_prompt);
        return cparser_submode_enter(context->parser, temp, prompt);
    }

    return CPARSER_OK;
}

/* 下面四个接口用来配置弱密码防护 */
cparser_result_t cparser_cmd_scp_weak_password_protect_option(cparser_context_t *context,
    char **option_ptr)
{
    char prompt[CPARSER_MAX_PROMPT];
    security_policy_t *ring_tmp, *ring_tmp_n;
    int rv;
    char *temp;
    char buf[COMMAND_LEN_MAX];

    transfer_security_policy_name(context);
    temp = (char *)context->cookie[context->parser->root_level];
    
    if (context == NULL) {
        return CPARSER_NOT_OK;
    }
    
    if (context->parser->mode != CPARSER_MODE_CONFIG) {     
        APR_RING_FOREACH_SAFE(ring_tmp, ring_tmp_n, &sec_policy_ring, security_policy_s, ring) {
            if (strncmp(ring_tmp->name, temp, NAME_LEN_MAX) == 0) {
                cmd_c2p_weak_password(context, &(ring_tmp->weakpwd_subply));              
                break;
            }
        }
    } else { 
        if (option_ptr == NULL || *option_ptr == NULL) {
            return CPARSER_NOT_OK;
        }
        
        APR_RING_FOREACH_SAFE(ring_tmp, ring_tmp_n, &sec_policy_ring, security_policy_s, ring) {
            if (strncmp(ring_tmp->name, temp, NAME_LEN_MAX) == 0) {
                sec_policy_get_option(&(ring_tmp->weakpwd_subply), option_ptr, buf);
                (ring_tmp->weakpwd_subply).action = ACTION_PASS;
                (ring_tmp->weakpwd_subply).log = 0;
                (ring_tmp->weakpwd_subply).flag = 1;
                
                rv = convert_sec_subpolicy_set((sec_subpolicy_t*)&(ring_tmp->weakpwd_subply));
                if (rv != APR_SUCCESS) {
                    cli_printf_info(context, "weak-password-protect set failure\n");
                    return CPARSER_NOT_OK;
                }

                admin_log_process(context, buf);
                break;
            }
        }

        snprintf(prompt, CPARSER_MAX_PROMPT, "%s(weak-password)#", g_cli_prompt);
        return cparser_submode_enter(context->parser, temp, prompt);
    }

    return CPARSER_OK;
}

cparser_result_t cparser_cmd_scp_weak_password_protect_action_action_option(cparser_context_t *context,
    char **action_ptr,
    char **option_ptr)
{
    char prompt[CPARSER_MAX_PROMPT];
    security_policy_t *ring_tmp, *ring_tmp_n;
    int rv;
    char *temp;
    char buf[COMMAND_LEN_MAX];

    transfer_security_policy_name(context);
    temp = (char *)context->cookie[context->parser->root_level];
    
    if (context == NULL) {
        return CPARSER_NOT_OK;
    }
    
    if (context->parser->mode != CPARSER_MODE_CONFIG) {
        return CPARSER_OK;
    } else {
        if (action_ptr == NULL || *action_ptr == NULL) {
            return CPARSER_NOT_OK;
        }

        APR_RING_FOREACH_SAFE(ring_tmp, ring_tmp_n, &sec_policy_ring, security_policy_s, ring) {
            if (strncmp(ring_tmp->name, temp, NAME_LEN_MAX) == 0) {
                if (option_ptr != NULL) {
                    sec_policy_get_action_option(&(ring_tmp->weakpwd_subply), action_ptr, option_ptr, buf); 
                } else {
                    sec_policy_get_action(&(ring_tmp->weakpwd_subply), action_ptr, buf);
                    (ring_tmp->weakpwd_subply).status = ENABLE;
                }
                
                (ring_tmp->weakpwd_subply).flag = 1;
                (ring_tmp->weakpwd_subply).log = 0;
                
                rv = convert_sec_subpolicy_set((sec_subpolicy_t*)&(ring_tmp->weakpwd_subply));
                if (rv != APR_SUCCESS) {
                    cli_printf_info(context, "weak-password-protect set failure\n");
                    return CPARSER_NOT_OK;
                }

                admin_log_process(context, buf);
                break;
            }
        }
        
        context->parser->cur_node = &cparser_node_pe_protect_engine_security_policy_secpname_root_weak_password_protect_option_eol;
        snprintf(prompt, CPARSER_MAX_PROMPT, "%s(weak-password)#", g_cli_prompt);
        return cparser_submode_enter(context->parser, temp, prompt);
    }

    return CPARSER_OK;
}

cparser_result_t cparser_cmd_scp_weak_password_protect_action_action_log_option(cparser_context_t *context,
    char **action_ptr,
    char **option_ptr)
{
    char prompt[CPARSER_MAX_PROMPT];
    security_policy_t *ring_tmp, *ring_tmp_n;
    int rv;
    char *temp;
    char buf[COMMAND_LEN_MAX];

    transfer_security_policy_name(context);
    temp = (char *)context->cookie[context->parser->root_level];

    if (context == NULL) {
        return CPARSER_NOT_OK; 
    }
    
    if (context->parser->mode != CPARSER_MODE_CONFIG) {
        return CPARSER_OK;
    } else {       
        APR_RING_FOREACH_SAFE(ring_tmp, ring_tmp_n, &sec_policy_ring, security_policy_s, ring) {
            if (strncmp(ring_tmp->name, temp, NAME_LEN_MAX) == 0) {
                if (option_ptr != NULL) {
                    sec_policy_get_action_log_option(&(ring_tmp->weakpwd_subply), action_ptr, option_ptr, buf); 
                } else {
                    sec_policy_get_action_log(&(ring_tmp->weakpwd_subply), action_ptr, buf);
                    (ring_tmp->weakpwd_subply).status = ENABLE;
                }
                
                (ring_tmp->weakpwd_subply).flag = 1;
                
                rv = convert_sec_subpolicy_set((sec_subpolicy_t*)&(ring_tmp->weakpwd_subply));
                if (rv != APR_SUCCESS) {
                    cli_printf_info(context, "weak-password-protect set failure\n");
                    return CPARSER_NOT_OK;
                }

                admin_log_process(context, buf);
                break;
            }
        }

        context->parser->cur_node = &cparser_node_pe_protect_engine_security_policy_secpname_root_weak_password_protect_option_eol;
        snprintf(prompt, CPARSER_MAX_PROMPT, "%s(weak-password)#", g_cli_prompt);
        return cparser_submode_enter(context->parser, temp, prompt);
    }

    return CPARSER_OK;
}

cparser_result_t cparser_cmd_scp_weak_password_protect(cparser_context_t *context)
{
    char prompt[CPARSER_MAX_PROMPT];
    security_policy_t *ring_tmp, *ring_tmp_n;
    int rv;
    char *temp;
    char buf[COMMAND_LEN_MAX];

    transfer_security_policy_name(context);
    temp = (char *)context->cookie[context->parser->root_level];

    if (context == NULL) {
        return CPARSER_NOT_OK;
    }

    if (context->parser->mode != CPARSER_MODE_CONFIG) {
        return CPARSER_OK;
    } else {
        APR_RING_FOREACH_SAFE(ring_tmp, ring_tmp_n, &sec_policy_ring, security_policy_s, ring) {
            if (strncmp(ring_tmp->name, temp, NAME_LEN_MAX) == 0) {
                (ring_tmp->weakpwd_subply).flag = 1;
                (ring_tmp->weakpwd_subply).status = ENABLE;
                (ring_tmp->weakpwd_subply).action = ACTION_PASS;
                (ring_tmp->weakpwd_subply).log = 0;
                
                rv = convert_sec_subpolicy_set((sec_subpolicy_t*)&(ring_tmp->weakpwd_subply));
                if (rv != APR_SUCCESS) {
                    cli_printf_info(context, "weak-password-protect set failure\n");
                    return CPARSER_NOT_OK;
                }

                sprintf(buf, "weak-password-protect");
                admin_log_process(context, buf);
                break;
            }
        }

        context->parser->cur_node = &cparser_node_pe_protect_engine_security_policy_secpname_root_weak_password_protect_option_eol;
        snprintf(prompt, CPARSER_MAX_PROMPT, "%s(weak-password)#", g_cli_prompt);
        return cparser_submode_enter(context->parser, temp, prompt);
    }

    return CPARSER_OK;
}

/* 下面一个接口对弱密码下的url模式进行处理 */
cparser_result_t cparser_cmd_wpd_url_type_url_string_password_name_passwordname(cparser_context_t *context,
    char **type_ptr,
    char **url_string_ptr,
    char **passwordname_ptr)
{
    char sec_policy_name[NAME_LEN_MAX];
    char *str, *url;
    apr_array_header_t *result, *k;
    keyword_t **kw, *kw_sub;
    int i, rv, type;
    char **string;
    apr_pool_t *ptemp;
    keyword_t keyword;
    char **keyword1, **keyword2;
    const char *temp;
    char prompt[CPARSER_MAX_PROMPT];
    char buf[COMMAND_LEN_MAX];

    if (context == NULL) {
        return CPARSER_NOT_OK;
    }

    apr_pool_create(&ptemp, psec); 
    apr_pool_tag(ptemp, "ptemp");

    transfer_security_policy_name(context);

    if (context->parser->mode != CPARSER_MODE_CONFIG) {     
        strncpy(sec_policy_name, (char *)context->cookie[context->parser->root_level], NAME_LEN_MAX);
        
        result = apr_array_make(ptemp, 10, sizeof(keyword_t*));
        convert_sec_policy_list(sec_policy_name, WEAK_PASSWORD, &result);
        kw = (keyword_t**)result->elts;
        url = apr_pstrdup(ptemp, "");
        type = 0;
        for (i = 0; i < result->nelts; i++) {
            kw_sub = kw[i];
            k = kw_sub->keyword;
            string = (char**)k->elts;
            if (!strcmp(string[0], url) && type_compare(type, kw_sub->type)) {
                wp_url_keyword_printf(context, kw_sub->type, string);  
            } else {
                wp_url_printf(context, kw_sub->type, string);
                url = string[0];
                type = kw_sub->type;
                wp_url_keyword_printf(context, kw_sub->type, string);
            }
        }

        apr_pool_destroy(ptemp);
        return CPARSER_OK;
    } else {
        if (context == NULL || type_ptr == NULL || url_string_ptr == NULL || passwordname_ptr == NULL || 
            *type_ptr == NULL || *url_string_ptr == NULL || *passwordname_ptr == NULL) {
            return CPARSER_NOT_OK;
        }

        if (is_ascii(*url_string_ptr) != CONV_OK) {
            cli_printf_info(context, " configure error; weak password url cann't contains Chinese characters\n");
            apr_pool_destroy(ptemp);
            return CPARSER_NOT_OK;
        }

        if (is_ascii(*passwordname_ptr) != CONV_OK) {
            cli_printf_info(context, " configure error; weak password passwordname cann't contains Chinese characters\n");
            apr_pool_destroy(ptemp);
            return CPARSER_NOT_OK;
        }

        if (strcmp(*type_ptr, "plain-text") == 0) {
            keyword.type = 1;
            if ((*url_string_ptr)[0] != '/') {
                cli_printf_info(context, " url configure error, please enter absolute path\n");
                apr_pool_destroy(ptemp);
                return CPARSER_NOT_OK;
            } if ((*url_string_ptr)[1] == '/') {
                cli_printf_info(context, " url configure error, please enter correct path\n");
                apr_pool_destroy(ptemp);
                return CPARSER_NOT_OK;
            }
        } else if (strcmp(*type_ptr, "regular-exp") == 0) {
            keyword.type = 2;
        }
        
        temp = apr_pstrdup(ptemp, (char *)context->cookie[context->parser->root_level]);
        temp = ap_getword_conf(ptemp, &temp);
        str = apr_pstrdup(ptemp, "");
        str = apr_pstrcat(ptemp, str, temp, NULL);
        str = apr_pstrcat(ptemp, str, " ", NULL);
        str = apr_pstrcat(ptemp, str, *url_string_ptr, NULL);
        str = apr_pstrcat(ptemp, str, " ", NULL);
        str = apr_pstrcat(ptemp, str, *passwordname_ptr, NULL);
        str = apr_pstrcat(ptemp, str, " ", NULL);
        str = apr_pstrcat(ptemp, str, apr_itoa(ptemp, keyword.type), NULL); 

        strncpy((char *)context->cookie[context->parser->root_level], str, MAX_SCPNAME_LEN);

        keyword.pool = ptemp;
        strncpy(keyword.sec_policy, temp, NAME_LEN_MAX);
        keyword.sec_subpolicy = WEAK_PASSWORD;
        keyword.keyword = apr_array_make(ptemp, INIT_ARR_LEN, sizeof(char*));
        keyword1 = (char**)apr_array_push(keyword.keyword);
        *keyword1 = apr_pstrdup(ptemp, *url_string_ptr);
        keyword2 = (char**)apr_array_push(keyword.keyword);
        *keyword2 = apr_pstrdup(ptemp, *passwordname_ptr);
        keyword.flag = WP_CHECK_URL;
        
        rv = convert_keyword_add(&keyword);
        switch (rv) {
            case CONV_OK:
                break;
            case CONV_FAIL:
                apr_pool_destroy(ptemp);
                return CPARSER_OK;
            case CONV_EXIST:
                break;
            case CONV_CONFLICT:
                cli_printf_info(context, "configure the same url and  different passwordname, please del first, and configure again\n");
                apr_pool_destroy(ptemp);
                return CPARSER_OK;     /* 当配置相同的URL，不同的passwordname之前，需先删除之前的URL以及password，在进行配置 */
            default:
                break;
        } 

        sprintf(buf, "url %s %s password-name %s", *type_ptr, *url_string_ptr, *passwordname_ptr);
        admin_log_process(context, buf);
        apr_pool_destroy(ptemp);
        snprintf(prompt, CPARSER_MAX_PROMPT, "%s(wp-url)#", g_cli_prompt);
        return cparser_submode_enter(context->parser, (char *)context->cookie[context->parser->root_level], prompt);
    }
}

/* 下面四个接口用来配置ldap注入防护 */
cparser_result_t cparser_cmd_scp_ldap_injection_protect(cparser_context_t *context)
{
    security_policy_t *ring_tmp, *ring_tmp_n;
    int rv;
    char *temp;
    char buf[COMMAND_LEN_MAX];

    transfer_security_policy_name(context);
    temp = (char *)context->cookie[context->parser->root_level];

    if (context->parser->mode != CPARSER_MODE_CONFIG) {
        return CPARSER_OK;
    } else {
        APR_RING_FOREACH_SAFE(ring_tmp, ring_tmp_n, &sec_policy_ring, security_policy_s, ring) {
            if (strncmp(ring_tmp->name, temp, NAME_LEN_MAX) == 0) {
                (ring_tmp->ldap_subply).flag = 1;
                (ring_tmp->ldap_subply).status = ENABLE;
                (ring_tmp->ldap_subply).action = ACTION_PASS;
                (ring_tmp->ldap_subply).log = 0;
                
                rv = convert_sec_subpolicy_set((sec_subpolicy_t*)&(ring_tmp->ldap_subply));
                if (rv != APR_SUCCESS) {
                    cli_printf_info(context, "ldap-injection-protect set failure\n");
                    return CPARSER_NOT_OK;
                }

                sprintf(buf, "ldap-injection-protect");
                admin_log_process(context, buf);
                break;
            }     
        }
    }
    
    return CPARSER_OK;
}

cparser_result_t cparser_cmd_scp_ldap_injection_protect_action_action_option(cparser_context_t *context,
    char **action_ptr,
    char **option_ptr)
{
    security_policy_t *ring_tmp, *ring_tmp_n;
    int rv;
    char *temp;
    char buf[COMMAND_LEN_MAX];
    
    transfer_security_policy_name(context);
    temp = (char *)context->cookie[context->parser->root_level];
    
    if (context == NULL) {
        return CPARSER_NOT_OK;
    }
    
    if (context->parser->mode != CPARSER_MODE_CONFIG) {
        return CPARSER_OK;
    } else {
        if (action_ptr == NULL || *action_ptr == NULL) {
            return CPARSER_NOT_OK;
        }

        APR_RING_FOREACH_SAFE(ring_tmp, ring_tmp_n, &sec_policy_ring, security_policy_s, ring) {
            if (strncmp(ring_tmp->name, temp, NAME_LEN_MAX) == 0) {
                if (option_ptr != NULL) {
                    sec_policy_get_action_option(&(ring_tmp->ldap_subply), action_ptr, option_ptr, buf); 
                } else {
                    sec_policy_get_action(&(ring_tmp->ldap_subply), action_ptr, buf);
                    (ring_tmp->ldap_subply).status = ENABLE;
                }
                
                (ring_tmp->ldap_subply).flag = 1;
                (ring_tmp->ldap_subply).log = 0;
                
                rv = convert_sec_subpolicy_set((sec_subpolicy_t*)&(ring_tmp->ldap_subply));
                if (rv != APR_SUCCESS) {
                    cli_printf_info(context, "ldap-injection-protect set failure\n");
                    return CPARSER_NOT_OK;
                }

                admin_log_process(context, buf);
                break;
            }
        }
    }
    
    return CPARSER_OK;
}

cparser_result_t cparser_cmd_scp_ldap_injection_protect_action_action_log_option(cparser_context_t *context,
    char **action_ptr,
    char **option_ptr)
{
    security_policy_t *ring_tmp, *ring_tmp_n;
    int rv;
    char *temp;
    char buf[COMMAND_LEN_MAX];

    transfer_security_policy_name(context);
    temp = (char *)context->cookie[context->parser->root_level];

    if (context == NULL) {
        return CPARSER_NOT_OK; 
    }
    
    if (context->parser->mode != CPARSER_MODE_CONFIG) {
        return CPARSER_OK;
    } else {       
        APR_RING_FOREACH_SAFE(ring_tmp, ring_tmp_n, &sec_policy_ring, security_policy_s, ring) {
            if (strncmp(ring_tmp->name, temp, NAME_LEN_MAX) == 0) {
                if (option_ptr != NULL) {
                    sec_policy_get_action_log_option(&(ring_tmp->ldap_subply), action_ptr, option_ptr, buf); 
                } else {
                    sec_policy_get_action_log(&(ring_tmp->ldap_subply), action_ptr, buf);
                    (ring_tmp->ldap_subply).status = ENABLE;
                }
                
                (ring_tmp->ldap_subply).flag = 1;
                
                rv = convert_sec_subpolicy_set((sec_subpolicy_t*)&(ring_tmp->ldap_subply));
                if (rv != APR_SUCCESS) {
                    cli_printf_info(context, "ldap-injection-protect set failure\n");
                    return CPARSER_NOT_OK;
                }

                admin_log_process(context, buf);
                break;
            }
        }
    }
    
    return CPARSER_OK;
}
cparser_result_t cparser_cmd_scp_ldap_injection_protect_option(cparser_context_t *context,
    char **option_ptr)
{
    security_policy_t *ring_tmp, *ring_tmp_n;
    int rv;
    char *temp;
    char buf[COMMAND_LEN_MAX];

    transfer_security_policy_name(context);
    temp = (char *)context->cookie[context->parser->root_level];
    
    if (context == NULL) {
        return CPARSER_NOT_OK;
    }
    
    if (context->parser->mode != CPARSER_MODE_CONFIG) {        
        APR_RING_FOREACH_SAFE(ring_tmp, ring_tmp_n, &sec_policy_ring, security_policy_s, ring) {
            if (strncmp(ring_tmp->name, temp, NAME_LEN_MAX) == 0) {
                cmd_c2p_ldap(context,&(ring_tmp->ldap_subply));
                break;
            }
        }
    } else { 
        if (option_ptr == NULL || *option_ptr == NULL) {
            return CPARSER_NOT_OK;
        }
        
        APR_RING_FOREACH_SAFE(ring_tmp, ring_tmp_n, &sec_policy_ring, security_policy_s, ring) {
            if (strncmp(ring_tmp->name, temp, NAME_LEN_MAX) == 0) {
                sec_policy_get_option(&(ring_tmp->ldap_subply), option_ptr, buf);
                (ring_tmp->ldap_subply).action = ACTION_PASS;
                (ring_tmp->ldap_subply).log = 0;
                (ring_tmp->ldap_subply).flag = 1;
                
                rv = convert_sec_subpolicy_set((sec_subpolicy_t*)&(ring_tmp->ldap_subply));
                if (rv != APR_SUCCESS) {
                    cli_printf_info(context, "ldap-injection-protect set failure\n");
                    return CPARSER_NOT_OK;
                }

                admin_log_process(context, buf);
                break;
            }
        }
    }
    
    return CPARSER_OK;
}

/* 下面四个接口用来配置email注入防护 */
cparser_result_t cparser_cmd_scp_email_injection_protect(cparser_context_t *context)
{
    security_policy_t *ring_tmp, *ring_tmp_n;
    int rv;
    char *temp;
    char buf[COMMAND_LEN_MAX];

    transfer_security_policy_name(context);
    temp = (char *)context->cookie[context->parser->root_level];

    if (context->parser->mode != CPARSER_MODE_CONFIG) {
        return CPARSER_OK;
    } else {
        APR_RING_FOREACH_SAFE(ring_tmp, ring_tmp_n, &sec_policy_ring, security_policy_s, ring) {
            if (strncmp(ring_tmp->name, temp, NAME_LEN_MAX) == 0) {
                (ring_tmp->email_subply).flag = 1;
                (ring_tmp->email_subply).status = ENABLE;
                (ring_tmp->email_subply).action = ACTION_PASS;
                (ring_tmp->email_subply).log = 0;
                
                rv = convert_sec_subpolicy_set((sec_subpolicy_t*)&(ring_tmp->email_subply));
                if (rv != APR_SUCCESS) {
                    cli_printf_info(context, "email-injection-protect set failure\n");
                    return CPARSER_NOT_OK;
                }

                sprintf(buf, "email-injection-protect");
                admin_log_process(context, buf);
                break;
            }
        }
    }
    
    return CPARSER_OK; 
}

cparser_result_t cparser_cmd_scp_email_injection_protect_action_action_option(cparser_context_t *context,
    char **action_ptr,
    char **option_ptr)
{
    security_policy_t *ring_tmp, *ring_tmp_n;
    int rv;
    char *temp;
    char buf[COMMAND_LEN_MAX];
    
    transfer_security_policy_name(context);
    temp = (char *)context->cookie[context->parser->root_level];
    
    if (context == NULL) {
        return CPARSER_NOT_OK;
    }
    
    if (context->parser->mode != CPARSER_MODE_CONFIG) {
        return CPARSER_OK;
    } else {
        if (action_ptr == NULL || *action_ptr == NULL) {
            return CPARSER_NOT_OK;
        }

        APR_RING_FOREACH_SAFE(ring_tmp, ring_tmp_n, &sec_policy_ring, security_policy_s, ring) {
            if (strncmp(ring_tmp->name, temp, NAME_LEN_MAX) == 0) {
                if (option_ptr != NULL) {
                    sec_policy_get_action_option(&(ring_tmp->email_subply), action_ptr, option_ptr, buf); 
                } else {
                    sec_policy_get_action(&(ring_tmp->email_subply), action_ptr, buf);
                    (ring_tmp->email_subply).status = ENABLE;
                }
                
                (ring_tmp->email_subply).flag = 1;
                (ring_tmp->email_subply).log = 0;
                
                rv = convert_sec_subpolicy_set((sec_subpolicy_t*)&(ring_tmp->email_subply));
                if (rv != APR_SUCCESS) {
                    cli_printf_info(context, "email-injection-protect set failure\n");
                    return CPARSER_NOT_OK;
                }

                admin_log_process(context, buf);
                break;
            }
        }
    }
    
    return CPARSER_OK;
}

cparser_result_t cparser_cmd_scp_email_injection_protect_action_action_log_option(cparser_context_t *context,
    char **action_ptr,
    char **option_ptr)
{
    security_policy_t *ring_tmp, *ring_tmp_n;
    int rv;
    char *temp;
    char buf[COMMAND_LEN_MAX];

    transfer_security_policy_name(context);
    temp = (char *)context->cookie[context->parser->root_level];

    if (context == NULL) {
        return CPARSER_NOT_OK; 
    }
    
    if (context->parser->mode != CPARSER_MODE_CONFIG) {
        return CPARSER_OK;
    } else {       
        APR_RING_FOREACH_SAFE(ring_tmp, ring_tmp_n, &sec_policy_ring, security_policy_s, ring) {
            if (strncmp(ring_tmp->name, temp, NAME_LEN_MAX) == 0) {
                if (option_ptr != NULL) {
                    sec_policy_get_action_log_option(&(ring_tmp->email_subply), action_ptr, option_ptr, buf); 
                } else {
                    sec_policy_get_action_log(&(ring_tmp->email_subply), action_ptr, buf);
                    (ring_tmp->email_subply).status = ENABLE;
                }
                
                (ring_tmp->email_subply).flag = 1;
                
                rv = convert_sec_subpolicy_set((sec_subpolicy_t*)&(ring_tmp->email_subply));
                if (rv != APR_SUCCESS) {
                    cli_printf_info(context, "email-injection-protect set failure\n");
                    return CPARSER_NOT_OK;
                }

                admin_log_process(context, buf);
                break;
            }
        }
    }
    
    return CPARSER_OK;
}
cparser_result_t cparser_cmd_scp_email_injection_protect_option(cparser_context_t *context,
    char **option_ptr)
{
    security_policy_t *ring_tmp, *ring_tmp_n;
    int rv;
    char *temp;
    char buf[COMMAND_LEN_MAX];

    transfer_security_policy_name(context);
    temp = (char *)context->cookie[context->parser->root_level];
    
    if (context == NULL) {
        return CPARSER_NOT_OK;
    }
    
    if (context->parser->mode != CPARSER_MODE_CONFIG) {        
        APR_RING_FOREACH_SAFE(ring_tmp, ring_tmp_n, &sec_policy_ring, security_policy_s, ring) {
            if (strncmp(ring_tmp->name, temp, NAME_LEN_MAX) == 0) {
                cmd_c2p_email(context,&(ring_tmp->email_subply));
                break;
            }
        }
    } else { 
        if (option_ptr == NULL || *option_ptr == NULL) {
            return CPARSER_NOT_OK;
        }
        
        APR_RING_FOREACH_SAFE(ring_tmp, ring_tmp_n, &sec_policy_ring, security_policy_s, ring) {
            if (strncmp(ring_tmp->name, temp, NAME_LEN_MAX) == 0) {
                sec_policy_get_option(&(ring_tmp->email_subply), option_ptr, buf);
                (ring_tmp->email_subply).action = ACTION_PASS;
                (ring_tmp->email_subply).log = 0;
                (ring_tmp->email_subply).flag = 1;
                
                rv = convert_sec_subpolicy_set((sec_subpolicy_t*)&(ring_tmp->email_subply));
                if (rv != APR_SUCCESS) {
                    cli_printf_info(context, "email-injection-protect set failure\n");
                    return CPARSER_NOT_OK;
                }

                admin_log_process(context, buf);
                break;
            }
        }
    }

    return CPARSER_OK;
}

/* 下面四个接口用来配置command注入防护 */
cparser_result_t cparser_cmd_scp_command_injection_protect(cparser_context_t *context)
{
    char prompt[CPARSER_MAX_PROMPT];
    security_policy_t *ring_tmp, *ring_tmp_n;
    int rv;
    char *temp;
    char buf[COMMAND_LEN_MAX];

    transfer_security_policy_name(context);
    temp = (char *)context->cookie[context->parser->root_level];

    if (context == NULL) {
        return CPARSER_NOT_OK;
    }

    if (context->parser->mode != CPARSER_MODE_CONFIG) {
        return CPARSER_OK;
    } else {
        APR_RING_FOREACH_SAFE(ring_tmp, ring_tmp_n, &sec_policy_ring, security_policy_s, ring) {
            if (strncmp(ring_tmp->name, temp, NAME_LEN_MAX) == 0) {
                (ring_tmp->cmd_subply).flag = 1;
                (ring_tmp->cmd_subply).status = ENABLE;
                (ring_tmp->cmd_subply).action = ACTION_PASS;
                (ring_tmp->cmd_subply).log = 0;
                
                rv = convert_sec_subpolicy_set((sec_subpolicy_t*)&(ring_tmp->cmd_subply));
                if (rv != APR_SUCCESS) {
                    cli_printf_info(context, "command-injection-protect set failure\n");
                    return CPARSER_NOT_OK;
                }

                sprintf(buf, "command-injection-protect");
                admin_log_process(context, buf);
                break;
            }
        }

        context->parser->cur_node = &cparser_node_pe_protect_engine_security_policy_secpname_root_command_injection_protect_option_eol;
        snprintf(prompt, CPARSER_MAX_PROMPT, "%s(cmd-injection)#", g_cli_prompt);
        return cparser_submode_enter(context->parser, temp, prompt);
    }
    
    return CPARSER_OK;
}

cparser_result_t cparser_cmd_scp_command_injection_protect_action_action_option(cparser_context_t *context,
    char **action_ptr,
    char **option_ptr)
{
    char prompt[CPARSER_MAX_PROMPT];
    security_policy_t *ring_tmp, *ring_tmp_n;
    int rv;
    char *temp;
    char buf[COMMAND_LEN_MAX];

    transfer_security_policy_name(context);
    temp = (char *)context->cookie[context->parser->root_level];
    
    if (context == NULL) {
        return CPARSER_NOT_OK;
    }
    
    if (context->parser->mode != CPARSER_MODE_CONFIG) {
        return CPARSER_OK;
    } else {
        if (action_ptr == NULL || *action_ptr == NULL) {
            return CPARSER_NOT_OK;
        }

        APR_RING_FOREACH_SAFE(ring_tmp, ring_tmp_n, &sec_policy_ring, security_policy_s, ring) {
            if (strncmp(ring_tmp->name, temp, NAME_LEN_MAX) == 0) {
                if (option_ptr != NULL) {
                    sec_policy_get_action_option(&(ring_tmp->cmd_subply), action_ptr, option_ptr, buf); 
                } else {
                    sec_policy_get_action(&(ring_tmp->cmd_subply), action_ptr, buf);
                    (ring_tmp->cmd_subply).status = ENABLE;
                }
                
                (ring_tmp->cmd_subply).flag = 1;
                (ring_tmp->cmd_subply).log = 0;
                
                rv = convert_sec_subpolicy_set((sec_subpolicy_t*)&(ring_tmp->cmd_subply));
                if (rv != APR_SUCCESS) {
                    cli_printf_info(context, "command-injection-protect set failure\n");
                    return CPARSER_NOT_OK;
                }

                admin_log_process(context, buf);
                break;
            }
        }
        
        context->parser->cur_node = &cparser_node_pe_protect_engine_security_policy_secpname_root_command_injection_protect_option_eol;
        snprintf(prompt, CPARSER_MAX_PROMPT, "%s(cmd-injection)#", g_cli_prompt);
        return cparser_submode_enter(context->parser, temp, prompt);
    }
    
    return CPARSER_OK;
}

cparser_result_t cparser_cmd_scp_command_injection_protect_action_action_log_option(cparser_context_t *context,
    char **action_ptr,
    char **option_ptr)
{
    char prompt[CPARSER_MAX_PROMPT];
    security_policy_t *ring_tmp, *ring_tmp_n;
    int rv;
    char *temp;
    char buf[COMMAND_LEN_MAX];

    transfer_security_policy_name(context);
    temp = (char *)context->cookie[context->parser->root_level];

    if (context == NULL) {
        return CPARSER_NOT_OK; 
    }
    
    if (context->parser->mode != CPARSER_MODE_CONFIG) {
        return CPARSER_OK;
    } else {       
        APR_RING_FOREACH_SAFE(ring_tmp, ring_tmp_n, &sec_policy_ring, security_policy_s, ring) {
            if (strncmp(ring_tmp->name, temp, NAME_LEN_MAX) == 0) {
                if (option_ptr != NULL) {
                    sec_policy_get_action_log_option(&(ring_tmp->cmd_subply), action_ptr, option_ptr, buf); 
                } else {
                    sec_policy_get_action_log(&(ring_tmp->cmd_subply), action_ptr, buf);
                    (ring_tmp->cmd_subply).status = ENABLE;
                }
                
                (ring_tmp->cmd_subply).flag = 1;
                
                rv = convert_sec_subpolicy_set((sec_subpolicy_t*)&(ring_tmp->cmd_subply));
                if (rv != APR_SUCCESS) {
                    cli_printf_info(context, "command-injection-protect set failure\n");
                    return CPARSER_NOT_OK;
                }

                admin_log_process(context, buf);
                break;
            }
        }

        context->parser->cur_node = &cparser_node_pe_protect_engine_security_policy_secpname_root_command_injection_protect_option_eol;
        snprintf(prompt, CPARSER_MAX_PROMPT, "%s(cmd-injection)#", g_cli_prompt);
        return cparser_submode_enter(context->parser, temp, prompt);
    }
    
    return CPARSER_OK;
}

cparser_result_t cparser_cmd_scp_command_injection_protect_option(cparser_context_t *context,
    char **option_ptr)
{
    char prompt[CPARSER_MAX_PROMPT];
    security_policy_t *ring_tmp, *ring_tmp_n;
    int rv;
    char *temp;
    char buf[COMMAND_LEN_MAX];

    transfer_security_policy_name(context);
    temp = (char *)context->cookie[context->parser->root_level];
    
    if (context == NULL) {
        return CPARSER_NOT_OK;
    }
    
    if (context->parser->mode != CPARSER_MODE_CONFIG) {        
        APR_RING_FOREACH_SAFE(ring_tmp, ring_tmp_n, &sec_policy_ring, security_policy_s, ring) {
            if (strncmp(ring_tmp->name, temp, NAME_LEN_MAX) == 0) {
                cmd_c2p_command(context, &(ring_tmp->cmd_subply));
                break;
            }
        }
    } else { 
        if (option_ptr == NULL || *option_ptr == NULL) {
            return CPARSER_NOT_OK;
        }
        
        APR_RING_FOREACH_SAFE(ring_tmp, ring_tmp_n, &sec_policy_ring, security_policy_s, ring) {
            if (strncmp(ring_tmp->name, temp, NAME_LEN_MAX) == 0) {
                sec_policy_get_option(&(ring_tmp->cmd_subply), option_ptr, buf);
                (ring_tmp->cmd_subply).action = ACTION_PASS;
                (ring_tmp->cmd_subply).log = 0;
                (ring_tmp->cmd_subply).flag = 1;
                
                rv = convert_sec_subpolicy_set((sec_subpolicy_t*)&(ring_tmp->cmd_subply));
                if (rv != APR_SUCCESS) {
                    cli_printf_info(context, "command-injection-protect set failure\n");
                    return CPARSER_NOT_OK;
                }

                admin_log_process(context, buf);
                break;
            }
        }

        snprintf(prompt, CPARSER_MAX_PROMPT, "%s(cmd-injection)#", g_cli_prompt);
        return cparser_submode_enter(context->parser, temp, prompt);
    }
    
    return CPARSER_OK;
}

/* 下面四个接口用来配置code注入防护 */
cparser_result_t cparser_cmd_scp_code_injection_protect(cparser_context_t *context)
{
    char prompt[CPARSER_MAX_PROMPT];
    security_policy_t *ring_tmp, *ring_tmp_n;
    int rv;
    char *temp;
    char buf[COMMAND_LEN_MAX];

    transfer_security_policy_name(context);
    temp = (char *)context->cookie[context->parser->root_level];

    if (context == NULL) {
        return CPARSER_NOT_OK;
    }

    if (context->parser->mode != CPARSER_MODE_CONFIG) {
        return CPARSER_OK;
    } else {
        APR_RING_FOREACH_SAFE(ring_tmp, ring_tmp_n, &sec_policy_ring, security_policy_s, ring) {
            if (strncmp(ring_tmp->name, temp, NAME_LEN_MAX) == 0) {
                (ring_tmp->code_subply).flag = 1;
                (ring_tmp->code_subply).status = ENABLE;
                (ring_tmp->code_subply).action = ACTION_PASS;
                (ring_tmp->code_subply).log = 0;
                
                rv = convert_sec_subpolicy_set((sec_subpolicy_t*)&(ring_tmp->code_subply));
                if (rv != APR_SUCCESS) {
                    cli_printf_info(context, "code-injection-protect set failure\n");
                    return CPARSER_NOT_OK;
                }

                sprintf(buf, "code-injection-protect");
                admin_log_process(context, buf);
                break;
            }
        }

        context->parser->cur_node = &cparser_node_pe_protect_engine_security_policy_secpname_root_code_injection_protect_option_eol;
        snprintf(prompt, CPARSER_MAX_PROMPT, "%s(code-injection)#", g_cli_prompt);
        return cparser_submode_enter(context->parser, temp, prompt);
    }
    
    return CPARSER_OK;

}

cparser_result_t cparser_cmd_scp_code_injection_protect_action_action_option(cparser_context_t *context,
    char **action_ptr,
    char **option_ptr)
{
    char prompt[CPARSER_MAX_PROMPT];
    security_policy_t *ring_tmp, *ring_tmp_n;
    int rv;
    char *temp;
    char buf[COMMAND_LEN_MAX];

    transfer_security_policy_name(context);
    temp = (char *)context->cookie[context->parser->root_level];
    
    if (context == NULL) {
        return CPARSER_NOT_OK;
    }
    
    if (context->parser->mode != CPARSER_MODE_CONFIG) {
        return CPARSER_OK;
    } else {
        if (action_ptr == NULL || *action_ptr == NULL) {
            return CPARSER_NOT_OK;
        }

        APR_RING_FOREACH_SAFE(ring_tmp, ring_tmp_n, &sec_policy_ring, security_policy_s, ring) {
            if (strncmp(ring_tmp->name, temp, NAME_LEN_MAX) == 0) {
                if (option_ptr != NULL) {
                    sec_policy_get_action_option(&(ring_tmp->code_subply), action_ptr, option_ptr, buf); 
                } else {
                    sec_policy_get_action(&(ring_tmp->code_subply), action_ptr, buf);
                    (ring_tmp->code_subply).status = ENABLE;
                }
                
                (ring_tmp->code_subply).flag = 1;
                (ring_tmp->code_subply).log = 0;
                
                rv = convert_sec_subpolicy_set((sec_subpolicy_t*)&(ring_tmp->code_subply));
                if (rv != APR_SUCCESS) {
                    cli_printf_info(context, "code-injection-protect set failure\n");
                    return CPARSER_NOT_OK;
                }

                admin_log_process(context, buf);
                break;
            }
        }
        
        context->parser->cur_node = &cparser_node_pe_protect_engine_security_policy_secpname_root_code_injection_protect_option_eol;
        snprintf(prompt, CPARSER_MAX_PROMPT, "%s(code-injection)#", g_cli_prompt);
        return cparser_submode_enter(context->parser, temp, prompt);
    }
    
    return CPARSER_OK;

}

cparser_result_t cparser_cmd_scp_code_injection_protect_action_action_log_option(cparser_context_t *context,
    char **action_ptr,
    char **option_ptr)
{
    char prompt[CPARSER_MAX_PROMPT];
    security_policy_t *ring_tmp, *ring_tmp_n;
    int rv;
    char *temp;
    char buf[COMMAND_LEN_MAX];

    transfer_security_policy_name(context);
    temp = (char *)context->cookie[context->parser->root_level];

    if (context == NULL) {
        return CPARSER_NOT_OK; 
    }
    
    if (context->parser->mode != CPARSER_MODE_CONFIG) {
        return CPARSER_OK;
    } else {       
        APR_RING_FOREACH_SAFE(ring_tmp, ring_tmp_n, &sec_policy_ring, security_policy_s, ring) {
            if (strncmp(ring_tmp->name, temp, NAME_LEN_MAX) == 0) {
                if (option_ptr != NULL) {
                    sec_policy_get_action_log_option(&(ring_tmp->code_subply), action_ptr, option_ptr, buf); 
                } else {
                    sec_policy_get_action_log(&(ring_tmp->code_subply), action_ptr, buf);
                    (ring_tmp->code_subply).status = ENABLE;
                }
                
                (ring_tmp->code_subply).flag = 1;
                
                rv = convert_sec_subpolicy_set((sec_subpolicy_t*)&(ring_tmp->code_subply));
                if (rv != APR_SUCCESS) {
                    cli_printf_info(context, "code-injection-protect set failure\n");
                    return CPARSER_NOT_OK;
                }

                admin_log_process(context, buf);
                break;
            }
        }

        context->parser->cur_node = &cparser_node_pe_protect_engine_security_policy_secpname_root_code_injection_protect_option_eol;
        snprintf(prompt, CPARSER_MAX_PROMPT, "%s(code-injection)#", g_cli_prompt);
        return cparser_submode_enter(context->parser, temp, prompt);
    }
    
    return CPARSER_OK;
}

cparser_result_t cparser_cmd_scp_code_injection_protect_option(cparser_context_t *context,
    char **option_ptr)
{
    char prompt[CPARSER_MAX_PROMPT];
    security_policy_t *ring_tmp, *ring_tmp_n;
    int rv;
    char *temp;
    char buf[COMMAND_LEN_MAX];

    transfer_security_policy_name(context);
    temp = (char *)context->cookie[context->parser->root_level];
    
    if (context == NULL) {
        return CPARSER_NOT_OK;
    }
    
    if (context->parser->mode != CPARSER_MODE_CONFIG) {        
        APR_RING_FOREACH_SAFE(ring_tmp, ring_tmp_n, &sec_policy_ring, security_policy_s, ring) {
            if (strncmp(ring_tmp->name, temp, NAME_LEN_MAX) == 0) {
                cmd_c2p_code(context, &(ring_tmp->code_subply));
                break;
            }
        }
    } else { 
        if (option_ptr == NULL || *option_ptr == NULL) {
            return CPARSER_NOT_OK;
        }
        
        APR_RING_FOREACH_SAFE(ring_tmp, ring_tmp_n, &sec_policy_ring, security_policy_s, ring) {
            if (strncmp(ring_tmp->name, temp, NAME_LEN_MAX) == 0) {
                sec_policy_get_option(&(ring_tmp->code_subply), option_ptr, buf);
                (ring_tmp->code_subply).action = ACTION_PASS;
                (ring_tmp->code_subply).log = 0;
                (ring_tmp->code_subply).flag = 1;
                
                rv = convert_sec_subpolicy_set((sec_subpolicy_t*)&(ring_tmp->code_subply));
                if (rv != APR_SUCCESS) {
                    cli_printf_info(context, "code-injection-protect set failure\n");
                    return CPARSER_NOT_OK;
                }

                admin_log_process(context, buf);
                break;
            }
        }

        snprintf(prompt, CPARSER_MAX_PROMPT, "%s(code-injection)#", g_cli_prompt);
        return cparser_submode_enter(context->parser, temp, prompt);
    }
    
    return CPARSER_OK;
}

/* 下面四个接口用来配置null-byte注入防护 */
cparser_result_t cparser_cmd_scp_null_byte_injection_protect(cparser_context_t *context)
{
    security_policy_t *ring_tmp, *ring_tmp_n;
    int rv;
    char *temp;
    char buf[COMMAND_LEN_MAX];

    transfer_security_policy_name(context);
    temp = (char *)context->cookie[context->parser->root_level];

    if (context->parser->mode != CPARSER_MODE_CONFIG) {
        return CPARSER_OK;
    } else {
        APR_RING_FOREACH_SAFE(ring_tmp, ring_tmp_n, &sec_policy_ring, security_policy_s, ring) {
            if (strncmp(ring_tmp->name, temp, NAME_LEN_MAX) == 0) {
                (ring_tmp->null_subply).flag = 1;
                (ring_tmp->null_subply).status = ENABLE;
                (ring_tmp->null_subply).action = ACTION_PASS;
                (ring_tmp->null_subply).log = 0;
                
                rv = convert_sec_subpolicy_set((sec_subpolicy_t*)&(ring_tmp->null_subply));
                if (rv != APR_SUCCESS) {
                    cli_printf_info(context, "null-byte-injection-protect set failure\n");
                    return CPARSER_NOT_OK;
                }

                sprintf(buf, "null-byte-injection-protect");
                admin_log_process(context, buf);
                break;
            }
        }
    }
    
    return CPARSER_OK;
}

cparser_result_t cparser_cmd_scp_null_byte_injection_protect_action_action_option(cparser_context_t *context,
    char **action_ptr,
    char **option_ptr)
{
    security_policy_t *ring_tmp, *ring_tmp_n;
    int rv;
    char *temp;
    char buf[COMMAND_LEN_MAX];
    
    transfer_security_policy_name(context);
    temp = (char *)context->cookie[context->parser->root_level];
    
    if (context == NULL) {
        return CPARSER_NOT_OK;
    }
    
    if (context->parser->mode != CPARSER_MODE_CONFIG) {
        return CPARSER_OK;
    } else {
        if (action_ptr == NULL || *action_ptr == NULL) {
            return CPARSER_NOT_OK;
        }

        APR_RING_FOREACH_SAFE(ring_tmp, ring_tmp_n, &sec_policy_ring, security_policy_s, ring) {
            if (strncmp(ring_tmp->name, temp, NAME_LEN_MAX) == 0) {
                if (option_ptr != NULL) {
                    sec_policy_get_action_option(&(ring_tmp->null_subply), action_ptr, option_ptr, buf); 
                } else {
                    sec_policy_get_action(&(ring_tmp->null_subply), action_ptr, buf);
                    (ring_tmp->null_subply).status = ENABLE;
                }
                
                (ring_tmp->null_subply).flag = 1;
                (ring_tmp->null_subply).log = 0;
                
                rv = convert_sec_subpolicy_set((sec_subpolicy_t*)&(ring_tmp->null_subply));
                if (rv != APR_SUCCESS) {
                    cli_printf_info(context, "null-byte-injection-protect set failure\n");
                    return CPARSER_NOT_OK;
                }

                admin_log_process(context, buf);
                break;
            }
        }
    }
    
    return CPARSER_OK;
}

cparser_result_t cparser_cmd_scp_null_byte_injection_protect_action_action_log_option(cparser_context_t *context,
    char **action_ptr,
    char **option_ptr)
{
    security_policy_t *ring_tmp, *ring_tmp_n;
    int rv;
    char *temp;
    char buf[COMMAND_LEN_MAX];

    transfer_security_policy_name(context);
    temp = (char *)context->cookie[context->parser->root_level];

    if (context == NULL) {
        return CPARSER_NOT_OK; 
    }
    
    if (context->parser->mode != CPARSER_MODE_CONFIG) {
        return CPARSER_OK;
    } else {       
        APR_RING_FOREACH_SAFE(ring_tmp, ring_tmp_n, &sec_policy_ring, security_policy_s, ring) {
            if (strncmp(ring_tmp->name, temp, NAME_LEN_MAX) == 0) {
                if (option_ptr != NULL) {
                    sec_policy_get_action_log_option(&(ring_tmp->null_subply), action_ptr, option_ptr, buf); 
                } else {
                    sec_policy_get_action_log(&(ring_tmp->null_subply), action_ptr, buf);
                    (ring_tmp->null_subply).status = ENABLE;
                }
                
                (ring_tmp->null_subply).flag = 1;
                
                rv = convert_sec_subpolicy_set((sec_subpolicy_t*)&(ring_tmp->null_subply));
                if (rv != APR_SUCCESS) {
                    cli_printf_info(context, "null-byte-injection-protect set failure\n");
                    return CPARSER_NOT_OK;
                }

                admin_log_process(context, buf);
                break;
            }
        }
    }
    
    return CPARSER_OK;
}

cparser_result_t cparser_cmd_scp_null_byte_injection_protect_option(cparser_context_t *context,
    char **option_ptr)
{
    security_policy_t *ring_tmp, *ring_tmp_n;
    int rv;
    char *temp;
    char buf[COMMAND_LEN_MAX];

    transfer_security_policy_name(context);
    temp = (char *)context->cookie[context->parser->root_level];
    
    if (context == NULL) {
        return CPARSER_NOT_OK;
    }
    
    if (context->parser->mode != CPARSER_MODE_CONFIG) {        
        APR_RING_FOREACH_SAFE(ring_tmp, ring_tmp_n, &sec_policy_ring, security_policy_s, ring) {
            if (strncmp(ring_tmp->name, temp, NAME_LEN_MAX) == 0) {
                cmd_c2p_null(context,&(ring_tmp->null_subply));
                break;
            }
        }
    } else { 
        if (option_ptr == NULL || *option_ptr == NULL) {
            return CPARSER_NOT_OK;
        }
        
        APR_RING_FOREACH_SAFE(ring_tmp, ring_tmp_n, &sec_policy_ring, security_policy_s, ring) {
            if (strncmp(ring_tmp->name, temp, NAME_LEN_MAX) == 0) {
                sec_policy_get_option(&(ring_tmp->null_subply), option_ptr, buf);
                (ring_tmp->null_subply).action = ACTION_PASS;
                (ring_tmp->null_subply).log = 0;
                (ring_tmp->null_subply).flag = 1;
                
                rv = convert_sec_subpolicy_set((sec_subpolicy_t*)&(ring_tmp->null_subply));
                if (rv != APR_SUCCESS) {
                    cli_printf_info(context, "null-byte-injection-protect set failure\n");
                    return CPARSER_NOT_OK;
                }

                admin_log_process(context, buf);
                break;
            }
        }
    }
    
    return CPARSER_OK;

}

/* 下面四个接口用来配置xss攻击防护 */
cparser_result_t cparser_cmd_scp_xss_attack_protect(cparser_context_t *context)
{
    char prompt[CPARSER_MAX_PROMPT];
    security_policy_t *ring_tmp, *ring_tmp_n;
    int rv;
    char *temp;
    char buf[COMMAND_LEN_MAX];

    transfer_security_policy_name(context);
    temp = (char *)context->cookie[context->parser->root_level];

    if (context == NULL) {
        return CPARSER_NOT_OK;
    }

    if (context->parser->mode != CPARSER_MODE_CONFIG) {
        return CPARSER_OK;
    } else {
        APR_RING_FOREACH_SAFE(ring_tmp, ring_tmp_n, &sec_policy_ring, security_policy_s, ring) {
            if (strncmp(ring_tmp->name, temp, NAME_LEN_MAX) == 0) {
                (ring_tmp->xss_subply).flag = 1;
                (ring_tmp->xss_subply).status = ENABLE;
                (ring_tmp->xss_subply).action = ACTION_PASS;
                (ring_tmp->xss_subply).log = 0;
                
                rv = convert_sec_subpolicy_set((sec_subpolicy_t*)&(ring_tmp->xss_subply));
                if (rv != APR_SUCCESS) {
                    cli_printf_info(context, "xss-attack-protect set failure\n");
                    return CPARSER_NOT_OK;
                }

                sprintf(buf, "xss-attack-protect");
                admin_log_process(context, buf);
                break;
            }
        }

        context->parser->cur_node = &cparser_node_pe_protect_engine_security_policy_secpname_root_xss_attack_protect_option_eol;
        snprintf(prompt, CPARSER_MAX_PROMPT, "%s(xss)#", g_cli_prompt);
        return cparser_submode_enter(context->parser, temp, prompt);
    }
    
    return CPARSER_OK;
}

cparser_result_t cparser_cmd_scp_xss_attack_protect_action_action_option(cparser_context_t *context,
    char **action_ptr,
    char **option_ptr)
{
    char prompt[CPARSER_MAX_PROMPT];
    security_policy_t *ring_tmp, *ring_tmp_n;
    int rv;
    char *temp;
    char buf[COMMAND_LEN_MAX];

    transfer_security_policy_name(context);
    temp = (char *)context->cookie[context->parser->root_level];
    
    if (context == NULL) {
        return CPARSER_NOT_OK;
    }
    
    if (context->parser->mode != CPARSER_MODE_CONFIG) {
        return CPARSER_OK;
    } else {
        if (action_ptr == NULL || *action_ptr == NULL) {
            return CPARSER_NOT_OK;
        }

        APR_RING_FOREACH_SAFE(ring_tmp, ring_tmp_n, &sec_policy_ring, security_policy_s, ring) {
            if (strncmp(ring_tmp->name, temp, NAME_LEN_MAX) == 0) {
                if (option_ptr != NULL) {
                    sec_policy_get_action_option(&(ring_tmp->xss_subply), action_ptr, option_ptr, buf); 
                } else {
                    sec_policy_get_action(&(ring_tmp->xss_subply), action_ptr, buf);
                    (ring_tmp->xss_subply).status = ENABLE;
                }
                
                (ring_tmp->xss_subply).flag = 1;
                (ring_tmp->xss_subply).log = 0;
                
                rv = convert_sec_subpolicy_set((sec_subpolicy_t*)&(ring_tmp->xss_subply));
                if (rv != APR_SUCCESS) {
                    cli_printf_info(context, "xss-attack-protect set failure\n");
                    return CPARSER_NOT_OK;
                }

                admin_log_process(context, buf);
                break;
            }
        }
        
        context->parser->cur_node = &cparser_node_pe_protect_engine_security_policy_secpname_root_xss_attack_protect_option_eol;
        snprintf(prompt, CPARSER_MAX_PROMPT, "%s(xss)#", g_cli_prompt);
        return cparser_submode_enter(context->parser, temp, prompt);
    }
    
    return CPARSER_OK;
}

cparser_result_t cparser_cmd_scp_xss_attack_protect_action_action_log_option(cparser_context_t *context,
    char **action_ptr,
    char **option_ptr)
{
    char prompt[CPARSER_MAX_PROMPT];
    security_policy_t *ring_tmp, *ring_tmp_n;
    int rv;
    char *temp;
    char buf[COMMAND_LEN_MAX];

    transfer_security_policy_name(context);
    temp = (char *)context->cookie[context->parser->root_level];

    if (context == NULL) {
        return CPARSER_NOT_OK; 
    }
    
    if (context->parser->mode != CPARSER_MODE_CONFIG) {
        return CPARSER_OK;
    } else {       
        APR_RING_FOREACH_SAFE(ring_tmp, ring_tmp_n, &sec_policy_ring, security_policy_s, ring) {
            if (strncmp(ring_tmp->name, temp, NAME_LEN_MAX) == 0) {
                if (option_ptr != NULL) {
                    sec_policy_get_action_log_option(&(ring_tmp->xss_subply), action_ptr, option_ptr, buf); 
                } else {
                    sec_policy_get_action_log(&(ring_tmp->xss_subply), action_ptr, buf);
                    (ring_tmp->xss_subply).status = ENABLE;
                }
                
                (ring_tmp->xss_subply).flag = 1;
                
                rv = convert_sec_subpolicy_set((sec_subpolicy_t*)&(ring_tmp->xss_subply));
                if (rv != APR_SUCCESS) {
                    cli_printf_info(context, "xss-attack-protect set failure\n");
                    return CPARSER_NOT_OK;
                }

                admin_log_process(context, buf);
                break;
            }
        }

        context->parser->cur_node = &cparser_node_pe_protect_engine_security_policy_secpname_root_xss_attack_protect_option_eol;
        snprintf(prompt, CPARSER_MAX_PROMPT, "%s(xss)#", g_cli_prompt);
        return cparser_submode_enter(context->parser, temp, prompt);
    }
    
    return CPARSER_OK;
}

cparser_result_t cparser_cmd_scp_xss_attack_protect_option(cparser_context_t *context,
    char **option_ptr)
{
    char prompt[CPARSER_MAX_PROMPT];
    security_policy_t *ring_tmp, *ring_tmp_n;
    int rv;
    char *temp;
    char buf[COMMAND_LEN_MAX];

    transfer_security_policy_name(context);
    temp = (char *)context->cookie[context->parser->root_level];
    
    if (context == NULL) {
        return CPARSER_NOT_OK;
    }
    
    if (context->parser->mode != CPARSER_MODE_CONFIG) {        
        APR_RING_FOREACH_SAFE(ring_tmp, ring_tmp_n, &sec_policy_ring, security_policy_s, ring) {
            if (strncmp(ring_tmp->name, temp, NAME_LEN_MAX) == 0) {
                cmd_c2p_xss(context, &(ring_tmp->xss_subply));
                break;
            }
        }
    } else { 
        if (option_ptr == NULL || *option_ptr == NULL) {
            return CPARSER_NOT_OK;
        }
        
        APR_RING_FOREACH_SAFE(ring_tmp, ring_tmp_n, &sec_policy_ring, security_policy_s, ring) {
            if (strncmp(ring_tmp->name, temp, NAME_LEN_MAX) == 0) {
                sec_policy_get_option(&(ring_tmp->xss_subply), option_ptr, buf);
                (ring_tmp->xss_subply).action = ACTION_PASS;
                (ring_tmp->xss_subply).log = 0;
                (ring_tmp->xss_subply).flag = 1;
                
                rv = convert_sec_subpolicy_set((sec_subpolicy_t*)&(ring_tmp->xss_subply));
                if (rv != APR_SUCCESS) {
                    cli_printf_info(context, "xss-attack-protect set failure\n");
                    return CPARSER_NOT_OK;
                }

                admin_log_process(context, buf);
                break;
            }
        }

        snprintf(prompt, CPARSER_MAX_PROMPT, "%s(xss)#", g_cli_prompt);
        return cparser_submode_enter(context->parser, temp, prompt);
    }
    
    return CPARSER_OK;
}

/* 下面四个接口用来配置csrf攻击防护 */
cparser_result_t cparser_cmd_scp_csrf_attack_protect(cparser_context_t *context)
{
    security_policy_t *ring_tmp, *ring_tmp_n;
    int rv;
    char *temp;
    char buf[COMMAND_LEN_MAX];
    char prompt[CPARSER_MAX_PROMPT];

    transfer_security_policy_name(context);
    temp = (char *)context->cookie[context->parser->root_level];

    if (context->parser->mode != CPARSER_MODE_CONFIG) {
        return CPARSER_OK;
    } else {
        APR_RING_FOREACH_SAFE(ring_tmp, ring_tmp_n, &sec_policy_ring, security_policy_s, ring) {
            if (strncmp(ring_tmp->name, temp, NAME_LEN_MAX) == 0) {
                (ring_tmp->csrf_subply).flag = 1;
                (ring_tmp->csrf_subply).status = ENABLE;
                (ring_tmp->csrf_subply).action = ACTION_PASS;
                (ring_tmp->csrf_subply).log = 0;
                
                rv = convert_sec_subpolicy_set((sec_subpolicy_t*)&(ring_tmp->csrf_subply));
                if (rv != APR_SUCCESS) {
                    cli_printf_info(context, "csrf-attack-protect set failure\n");
                    return CPARSER_NOT_OK;
                }

                sprintf(buf, "csrf-attack-protect");
                admin_log_process(context, buf);
                break;
            }
        }
    }

    context->parser->cur_node = &cparser_node_pe_protect_engine_security_policy_secpname_root_csrf_attack_protect_option_eol;
    snprintf(prompt, CPARSER_MAX_PROMPT, "%s(csrf)#", g_cli_prompt);
    return cparser_submode_enter(context->parser, temp, prompt);
}

cparser_result_t cparser_cmd_scp_csrf_attack_protect_action_action_option(cparser_context_t *context,
    char **action_ptr,
    char **option_ptr)
{
    security_policy_t *ring_tmp, *ring_tmp_n;
    int rv;
    char *temp;
    char buf[COMMAND_LEN_MAX];
    char prompt[CPARSER_MAX_PROMPT];
    
    transfer_security_policy_name(context);
    temp = (char *)context->cookie[context->parser->root_level];
    
    if (context == NULL) {
        return CPARSER_NOT_OK;
    }
    
    if (context->parser->mode != CPARSER_MODE_CONFIG) {
        return CPARSER_OK;
    } else {
        if (action_ptr == NULL || *action_ptr == NULL) {
            return CPARSER_NOT_OK;
        }

        APR_RING_FOREACH_SAFE(ring_tmp, ring_tmp_n, &sec_policy_ring, security_policy_s, ring) {
            if (strncmp(ring_tmp->name, temp, NAME_LEN_MAX) == 0) {
                if (option_ptr != NULL) {
                    sec_policy_get_action_option(&(ring_tmp->csrf_subply), action_ptr, option_ptr, buf); 
                } else {
                    sec_policy_get_action(&(ring_tmp->csrf_subply), action_ptr, buf);
                    (ring_tmp->csrf_subply).status = ENABLE;
                }
                
                (ring_tmp->csrf_subply).flag = 1;
                (ring_tmp->csrf_subply).log = 0;
                
                rv = convert_sec_subpolicy_set((sec_subpolicy_t*)&(ring_tmp->csrf_subply));
                if (rv != APR_SUCCESS) {
                    cli_printf_info(context, "csrf-attack-protect set failure\n");
                    return CPARSER_NOT_OK;
                }

                admin_log_process(context, buf);
                break;
            }
        }
    }

    context->parser->cur_node = &cparser_node_pe_protect_engine_security_policy_secpname_root_csrf_attack_protect_option_eol;
    snprintf(prompt, CPARSER_MAX_PROMPT, "%s(csrf)#", g_cli_prompt);
    return cparser_submode_enter(context->parser, temp, prompt);
}

cparser_result_t cparser_cmd_scp_csrf_attack_protect_action_action_log_option(cparser_context_t *context,
    char **action_ptr,
    char **option_ptr)
{
    security_policy_t *ring_tmp, *ring_tmp_n;
    int rv;
    char *temp;
    char buf[COMMAND_LEN_MAX];
    char prompt[CPARSER_MAX_PROMPT];

    transfer_security_policy_name(context);
    temp = (char *)context->cookie[context->parser->root_level];

    if (context == NULL) {
        return CPARSER_NOT_OK; 
    }
    
    if (context->parser->mode != CPARSER_MODE_CONFIG) {
        return CPARSER_OK;
    } else {       
        APR_RING_FOREACH_SAFE(ring_tmp, ring_tmp_n, &sec_policy_ring, security_policy_s, ring) {
            if (strncmp(ring_tmp->name, temp, NAME_LEN_MAX) == 0) {
                if (option_ptr != NULL) {
                    sec_policy_get_action_log_option(&(ring_tmp->csrf_subply), action_ptr, option_ptr, buf); 
                } else {
                    sec_policy_get_action_log(&(ring_tmp->csrf_subply), action_ptr, buf);
                    (ring_tmp->csrf_subply).status = ENABLE;
                }
                
                (ring_tmp->csrf_subply).flag = 1;
                
                rv = convert_sec_subpolicy_set((sec_subpolicy_t*)&(ring_tmp->csrf_subply));
                if (rv != APR_SUCCESS) {
                    cli_printf_info(context, "csrf-attack-protect set failure\n");
                    return CPARSER_NOT_OK;
                }

                admin_log_process(context, buf);
                break;
            }
        }
    }
    
    context->parser->cur_node = &cparser_node_pe_protect_engine_security_policy_secpname_root_csrf_attack_protect_option_eol;
    snprintf(prompt, CPARSER_MAX_PROMPT, "%s(csrf)#", g_cli_prompt);
    return cparser_submode_enter(context->parser, temp, prompt);
}

cparser_result_t cparser_cmd_scp_csrf_attack_protect_option(cparser_context_t *context,
    char **option_ptr)
{
    security_policy_t *ring_tmp, *ring_tmp_n;
    int rv;
    char *temp;
    char buf[COMMAND_LEN_MAX];
    char prompt[CPARSER_MAX_PROMPT];

    transfer_security_policy_name(context);
    temp = (char *)context->cookie[context->parser->root_level];
    
    if (context == NULL) {
        return CPARSER_NOT_OK;
    }
    
    if (context->parser->mode != CPARSER_MODE_CONFIG) {        
        APR_RING_FOREACH_SAFE(ring_tmp, ring_tmp_n, &sec_policy_ring, security_policy_s, ring) {
            if (strncmp(ring_tmp->name, temp, NAME_LEN_MAX) == 0) {
                cmd_c2p_csrf(context,&(ring_tmp->csrf_subply));
                break;
            }
        }
        
        return CPARSER_OK;
    } else { 
        if (option_ptr == NULL || *option_ptr == NULL) {
            return CPARSER_NOT_OK;
        }
        
        APR_RING_FOREACH_SAFE(ring_tmp, ring_tmp_n, &sec_policy_ring, security_policy_s, ring) {
            if (strncmp(ring_tmp->name, temp, NAME_LEN_MAX) == 0) {
                sec_policy_get_option(&(ring_tmp->csrf_subply), option_ptr, buf);
                (ring_tmp->csrf_subply).action = ACTION_PASS;
                (ring_tmp->csrf_subply).log = 0;
                (ring_tmp->csrf_subply).flag = 1;
                
                rv = convert_sec_subpolicy_set((sec_subpolicy_t*)&(ring_tmp->csrf_subply));
                if (rv != APR_SUCCESS) {
                    cli_printf_info(context, "csrf-attack-protect set failure\n");
                    return CPARSER_NOT_OK;
                }

                admin_log_process(context, buf);
                break;
            }
        }

		snprintf(prompt, CPARSER_MAX_PROMPT, "%s(csrf)#", g_cli_prompt);
        return cparser_submode_enter(context->parser, temp, prompt);
    }
}

/* 下面四个接口用来配置overflow攻击防护 */
cparser_result_t cparser_cmd_scp_overflow_attack_protect(cparser_context_t *context)
{
    security_policy_t *ring_tmp, *ring_tmp_n;
    int rv;
    char *temp;
    char buf[COMMAND_LEN_MAX];

    transfer_security_policy_name(context);
    temp = (char *)context->cookie[context->parser->root_level];

    if (context->parser->mode != CPARSER_MODE_CONFIG) {
        return CPARSER_OK;
    } else {
        APR_RING_FOREACH_SAFE(ring_tmp, ring_tmp_n, &sec_policy_ring, security_policy_s, ring) {
            if (strncmp(ring_tmp->name, temp, NAME_LEN_MAX) == 0) {
                (ring_tmp->overflow_subply).flag = 1;
                (ring_tmp->overflow_subply).status = ENABLE;
                (ring_tmp->overflow_subply).action = ACTION_PASS;
                (ring_tmp->overflow_subply).log = 0;
                
                rv = convert_sec_subpolicy_set((sec_subpolicy_t*)&(ring_tmp->overflow_subply));
                if (rv != APR_SUCCESS) {
                    cli_printf_info(context, "overflow-attack-protect set failure\n");
                    return CPARSER_NOT_OK;
                }

                sprintf(buf, "overflow-attack-protect");
                admin_log_process(context, buf);
                break;
            }
        }
    }
    
    return CPARSER_OK;
}

cparser_result_t cparser_cmd_scp_overflow_attack_protect_action_action_option(cparser_context_t *context,
    char **action_ptr,
    char **option_ptr)
{
    security_policy_t *ring_tmp, *ring_tmp_n;
    int rv;
    char *temp;
    char buf[COMMAND_LEN_MAX];
    
    transfer_security_policy_name(context);
    temp = (char *)context->cookie[context->parser->root_level];
    
    if (context == NULL) {
        return CPARSER_NOT_OK;
    }
    
    if (context->parser->mode != CPARSER_MODE_CONFIG) {
        return CPARSER_OK;
    } else {
        if (action_ptr == NULL || *action_ptr == NULL) {
            return CPARSER_NOT_OK;
        }

        APR_RING_FOREACH_SAFE(ring_tmp, ring_tmp_n, &sec_policy_ring, security_policy_s, ring) {
            if (strncmp(ring_tmp->name, temp, NAME_LEN_MAX) == 0) {
                if (option_ptr != NULL) {
                    sec_policy_get_action_option(&(ring_tmp->overflow_subply), action_ptr, option_ptr, buf); 
                } else {
                    sec_policy_get_action(&(ring_tmp->overflow_subply), action_ptr, buf);
                    (ring_tmp->overflow_subply).status = ENABLE;
                }
                
                (ring_tmp->overflow_subply).flag = 1;
                (ring_tmp->overflow_subply).log = 0;
                
                rv = convert_sec_subpolicy_set((sec_subpolicy_t*)&(ring_tmp->overflow_subply));
                if (rv != APR_SUCCESS) {
                    cli_printf_info(context, "overflow-attack-protect set failure\n");
                    return CPARSER_NOT_OK;
                }

                admin_log_process(context, buf);
                break;
            }
        }
    }
    
    return CPARSER_OK;
}

cparser_result_t cparser_cmd_scp_overflow_attack_protect_action_action_log_option(cparser_context_t *context,
    char **action_ptr,
    char **option_ptr)
{
    security_policy_t *ring_tmp, *ring_tmp_n;
    int rv;
    char *temp;
    char buf[COMMAND_LEN_MAX];

    transfer_security_policy_name(context);
    temp = (char *)context->cookie[context->parser->root_level];

    if (context == NULL) {
        return CPARSER_NOT_OK; 
    }
    
    if (context->parser->mode != CPARSER_MODE_CONFIG) {
        return CPARSER_OK;
    } else {       
        APR_RING_FOREACH_SAFE(ring_tmp, ring_tmp_n, &sec_policy_ring, security_policy_s, ring) {
            if (strncmp(ring_tmp->name, temp, NAME_LEN_MAX) == 0) {
                if (option_ptr != NULL) {
                    sec_policy_get_action_log_option(&(ring_tmp->overflow_subply), action_ptr, option_ptr, buf); 
                } else {
                    sec_policy_get_action_log(&(ring_tmp->overflow_subply), action_ptr, buf);
                    (ring_tmp->overflow_subply).status = ENABLE;
                }
                
                (ring_tmp->overflow_subply).flag = 1;
                
                rv = convert_sec_subpolicy_set((sec_subpolicy_t*)&(ring_tmp->overflow_subply));
                if (rv != APR_SUCCESS) {
                    cli_printf_info(context, "overflow-attack-protect set failure\n");
                    return CPARSER_NOT_OK;
                }

                admin_log_process(context, buf);
                break;
            }
        }
    }
    
    return CPARSER_OK;
}

cparser_result_t cparser_cmd_scp_overflow_attack_protect_option(cparser_context_t *context,
    char **option_ptr)
{
    security_policy_t *ring_tmp, *ring_tmp_n;
    int rv;
    char *temp;
    char buf[COMMAND_LEN_MAX];

    transfer_security_policy_name(context);
    temp = (char *)context->cookie[context->parser->root_level];
    
    if (context == NULL) {
        return CPARSER_NOT_OK;
    }
    
    if (context->parser->mode != CPARSER_MODE_CONFIG) {        
        APR_RING_FOREACH_SAFE(ring_tmp, ring_tmp_n, &sec_policy_ring, security_policy_s, ring) {
            if (strncmp(ring_tmp->name, temp, NAME_LEN_MAX) == 0) {
                cmd_c2p_overflow(context,&(ring_tmp->overflow_subply));
                break;
            }
        }
    } else { 
        if (option_ptr == NULL || *option_ptr == NULL) {
            return CPARSER_NOT_OK;
        }
        
        APR_RING_FOREACH_SAFE(ring_tmp, ring_tmp_n, &sec_policy_ring, security_policy_s, ring) {
            if (strncmp(ring_tmp->name, temp, NAME_LEN_MAX) == 0) {
                sec_policy_get_option(&(ring_tmp->overflow_subply), option_ptr, buf);
                (ring_tmp->overflow_subply).action = ACTION_PASS;
                (ring_tmp->overflow_subply).log = 0;
                (ring_tmp->overflow_subply).flag = 1;
                
                rv = convert_sec_subpolicy_set((sec_subpolicy_t*)&(ring_tmp->overflow_subply));
                if (rv != APR_SUCCESS) {
                    cli_printf_info(context, "overflow-attack-protect set failure\n");
                    return CPARSER_NOT_OK;
                }

                admin_log_process(context, buf);
                break;
            }
        }
    }
    
    return CPARSER_OK;
}

/* 下面四个接口用来配置file-include攻击防护 */
cparser_result_t cparser_cmd_scp_file_include_attack_protect(cparser_context_t *context)
{
    security_policy_t *ring_tmp, *ring_tmp_n;
    int rv;
    char *temp;
    char buf[COMMAND_LEN_MAX];

    transfer_security_policy_name(context);
    temp = (char *)context->cookie[context->parser->root_level];

    if (context->parser->mode != CPARSER_MODE_CONFIG) {
        return CPARSER_OK;
    } else {
        APR_RING_FOREACH_SAFE(ring_tmp, ring_tmp_n, &sec_policy_ring, security_policy_s, ring) {
            if (strncmp(ring_tmp->name, temp, NAME_LEN_MAX) == 0) {
                (ring_tmp->file_subply).flag = 1;
                (ring_tmp->file_subply).status = ENABLE;
                (ring_tmp->file_subply).action = ACTION_PASS;
                (ring_tmp->file_subply).log = 0;
                
                rv = convert_sec_subpolicy_set((sec_subpolicy_t*)&(ring_tmp->file_subply));
                if (rv != APR_SUCCESS) {
                    cli_printf_info(context, "file-include-attack-protect set failure\n");
                    return CPARSER_NOT_OK;
                }

                sprintf(buf, "file-include-attack-protect");
                admin_log_process(context, buf);
                break;
            }
        }
    }
    
    return CPARSER_OK;
}

cparser_result_t cparser_cmd_scp_file_include_attack_protect_action_action_option(cparser_context_t *context,
    char **action_ptr,
    char **option_ptr)
{
    security_policy_t *ring_tmp, *ring_tmp_n;
    int rv;
    char *temp;
    char buf[COMMAND_LEN_MAX];
    
    transfer_security_policy_name(context);
    temp = (char *)context->cookie[context->parser->root_level];
    
    if (context == NULL) {
        return CPARSER_NOT_OK;
    }
    
    if (context->parser->mode != CPARSER_MODE_CONFIG) {
        return CPARSER_OK;
    } else {
        if (action_ptr == NULL || *action_ptr == NULL) {
            return CPARSER_NOT_OK;
        }

        APR_RING_FOREACH_SAFE(ring_tmp, ring_tmp_n, &sec_policy_ring, security_policy_s, ring) {
            if (strncmp(ring_tmp->name, temp, NAME_LEN_MAX) == 0) {
                if (option_ptr != NULL) {
                    sec_policy_get_action_option(&(ring_tmp->file_subply), action_ptr, option_ptr, buf); 
                } else {
                    sec_policy_get_action(&(ring_tmp->file_subply), action_ptr, buf);
                    (ring_tmp->file_subply).status = ENABLE;
                }
                
                (ring_tmp->file_subply).flag = 1;
                (ring_tmp->file_subply).log = 0;
                
                rv = convert_sec_subpolicy_set((sec_subpolicy_t*)&(ring_tmp->file_subply));
                if (rv != APR_SUCCESS) {
                    cli_printf_info(context, "file-include-attack-protect set failure\n");
                    return CPARSER_NOT_OK;
                }

                admin_log_process(context, buf);
                break;
            }
        }
    }
    
    return CPARSER_OK;
}

cparser_result_t cparser_cmd_scp_file_include_attack_protect_action_action_log_option(cparser_context_t *context,
    char **action_ptr,
    char **option_ptr)
{
    security_policy_t *ring_tmp, *ring_tmp_n;
    int rv;
    char *temp;
    char buf[COMMAND_LEN_MAX];

    transfer_security_policy_name(context);
    temp = (char *)context->cookie[context->parser->root_level];

    if (context == NULL) {
        return CPARSER_NOT_OK; 
    }
    
    if (context->parser->mode != CPARSER_MODE_CONFIG) {
        return CPARSER_OK;
    } else {       
        APR_RING_FOREACH_SAFE(ring_tmp, ring_tmp_n, &sec_policy_ring, security_policy_s, ring) {
            if (strncmp(ring_tmp->name, temp, NAME_LEN_MAX) == 0) {
                if (option_ptr != NULL) {
                    sec_policy_get_action_log_option(&(ring_tmp->file_subply), action_ptr, option_ptr, buf); 
                } else {
                    sec_policy_get_action_log(&(ring_tmp->file_subply), action_ptr, buf);
                    (ring_tmp->file_subply).status = ENABLE;
                }
                
                (ring_tmp->file_subply).flag = 1;
                
                rv = convert_sec_subpolicy_set((sec_subpolicy_t*)&(ring_tmp->file_subply));
                if (rv != APR_SUCCESS) {
                    cli_printf_info(context, "file-include-attack-protect set failure\n");
                    return CPARSER_NOT_OK;
                }

                admin_log_process(context, buf);
                break;
            }
        }
    }
    
    return CPARSER_OK;
}

cparser_result_t cparser_cmd_scp_file_include_attack_protect_option(cparser_context_t *context,
    char **option_ptr)
{
    security_policy_t *ring_tmp, *ring_tmp_n;
    int rv;
    char *temp;
    char buf[COMMAND_LEN_MAX];

    transfer_security_policy_name(context);
    temp = (char *)context->cookie[context->parser->root_level];
    
    if (context == NULL) {
        return CPARSER_NOT_OK;
    }
    
    if (context->parser->mode != CPARSER_MODE_CONFIG) {        
        APR_RING_FOREACH_SAFE(ring_tmp, ring_tmp_n, &sec_policy_ring, security_policy_s, ring) {
            if (strncmp(ring_tmp->name, temp, NAME_LEN_MAX) == 0) {
                cmd_c2p_file(context,&(ring_tmp->file_subply));
                break;
            }
        }
    } else { 
        if (option_ptr == NULL || *option_ptr == NULL) {
            return CPARSER_NOT_OK;
        }
        
        APR_RING_FOREACH_SAFE(ring_tmp, ring_tmp_n, &sec_policy_ring, security_policy_s, ring) {
            if (strncmp(ring_tmp->name, temp, NAME_LEN_MAX) == 0) {
                sec_policy_get_option(&(ring_tmp->file_subply), option_ptr, buf);
                (ring_tmp->file_subply).action = ACTION_PASS;
                (ring_tmp->file_subply).log = 0;
                (ring_tmp->file_subply).flag = 1;
                
                rv = convert_sec_subpolicy_set((sec_subpolicy_t*)&(ring_tmp->file_subply));
                if (rv != APR_SUCCESS) {
                    cli_printf_info(context, "file-include-attack-protect set failure\n");
                    return CPARSER_NOT_OK;
                }

                admin_log_process(context, buf);
                break;
            }
        }
    }
    
    return CPARSER_OK;
}

/* 下面四个接口用来配置misc-include攻击防护 */
cparser_result_t cparser_cmd_scp_misc_attack_protect(cparser_context_t *context)
{
    security_policy_t *ring_tmp, *ring_tmp_n;
    int rv;
    char *temp;
    char buf[COMMAND_LEN_MAX];

    transfer_security_policy_name(context);
    temp = (char *)context->cookie[context->parser->root_level];

    if (context->parser->mode != CPARSER_MODE_CONFIG) {
        return CPARSER_OK;
    } else {
        APR_RING_FOREACH_SAFE(ring_tmp, ring_tmp_n, &sec_policy_ring, security_policy_s, ring) {
            if (strncmp(ring_tmp->name, temp, NAME_LEN_MAX) == 0) {
                (ring_tmp->base_subply).flag = 1;
                (ring_tmp->base_subply).status = ENABLE;
                (ring_tmp->base_subply).action = ACTION_PASS;
                (ring_tmp->base_subply).log = 0;
                
                rv = convert_sec_subpolicy_set((sec_subpolicy_t*)&(ring_tmp->base_subply));
                if (rv != APR_SUCCESS) {
                    cli_printf_info(context, "misc-attack-protect set failure\n");
                    return CPARSER_NOT_OK;
                }

                sprintf(buf, "misc-attack-protect");
                admin_log_process(context, buf);
                break;
            }
        }
    }
    
    return CPARSER_OK;

}

cparser_result_t cparser_cmd_scp_misc_attack_protect_action_action_option(cparser_context_t *context,
    char **action_ptr,
    char **option_ptr)
{
    security_policy_t *ring_tmp, *ring_tmp_n;
    int rv;
    char *temp;
    char buf[COMMAND_LEN_MAX];
    
    transfer_security_policy_name(context);
    temp = (char *)context->cookie[context->parser->root_level];
    
    if (context == NULL) {
        return CPARSER_NOT_OK;
    }
    
    if (context->parser->mode != CPARSER_MODE_CONFIG) {
        return CPARSER_OK;
    } else {
        if (action_ptr == NULL || *action_ptr == NULL) {
            return CPARSER_NOT_OK;
        }

        APR_RING_FOREACH_SAFE(ring_tmp, ring_tmp_n, &sec_policy_ring, security_policy_s, ring) {
            if (strncmp(ring_tmp->name, temp, NAME_LEN_MAX) == 0) {
                if (option_ptr != NULL) {
                    sec_policy_get_action_option(&(ring_tmp->base_subply), action_ptr, option_ptr, buf); 
                } else {
                    sec_policy_get_action(&(ring_tmp->base_subply), action_ptr, buf);
                    (ring_tmp->base_subply).status = ENABLE;
                }
                
                (ring_tmp->base_subply).flag = 1;
                (ring_tmp->base_subply).log = 0;
                
                rv = convert_sec_subpolicy_set((sec_subpolicy_t*)&(ring_tmp->base_subply));
                if (rv != APR_SUCCESS) {
                    cli_printf_info(context, "misc-attack-protect set failure\n");
                    return CPARSER_NOT_OK;
                }

                admin_log_process(context, buf);
                break;
            }
        }
    }
    
    return CPARSER_OK;
}

cparser_result_t cparser_cmd_scp_misc_attack_protect_action_action_log_option(cparser_context_t *context,
    char **action_ptr,
    char **option_ptr)
{
    security_policy_t *ring_tmp, *ring_tmp_n;
    int rv;
    char *temp;
    char buf[COMMAND_LEN_MAX];

    transfer_security_policy_name(context);
    temp = (char *)context->cookie[context->parser->root_level];

    if (context == NULL) {
        return CPARSER_NOT_OK; 
    }
    
    if (context->parser->mode != CPARSER_MODE_CONFIG) {
        return CPARSER_OK;
    } else {       
        APR_RING_FOREACH_SAFE(ring_tmp, ring_tmp_n, &sec_policy_ring, security_policy_s, ring) {
            if (strncmp(ring_tmp->name, temp, NAME_LEN_MAX) == 0) {
                if (option_ptr != NULL) {
                    sec_policy_get_action_log_option(&(ring_tmp->base_subply), action_ptr, option_ptr, buf); 
                } else {
                    sec_policy_get_action_log(&(ring_tmp->base_subply), action_ptr, buf);
                    (ring_tmp->base_subply).status = ENABLE;
                }
                
                (ring_tmp->base_subply).flag = 1;
                
                rv = convert_sec_subpolicy_set((sec_subpolicy_t*)&(ring_tmp->base_subply));
                if (rv != APR_SUCCESS) {
                    cli_printf_info(context, "misc-attack-protect set failure\n");
                    return CPARSER_NOT_OK;
                }

                admin_log_process(context, buf);
                break;
            }
        }
    }
    
    return CPARSER_OK;
}
cparser_result_t cparser_cmd_scp_misc_attack_protect_option(cparser_context_t *context,
    char **option_ptr)
{
    security_policy_t *ring_tmp, *ring_tmp_n;
    int rv;
    char *temp;
    char buf[COMMAND_LEN_MAX];

    transfer_security_policy_name(context);
    temp = (char *)context->cookie[context->parser->root_level];
    
    if (context == NULL) {
        return CPARSER_NOT_OK;
    }
    
    if (context->parser->mode != CPARSER_MODE_CONFIG) {        
        APR_RING_FOREACH_SAFE(ring_tmp, ring_tmp_n, &sec_policy_ring, security_policy_s, ring) {
            if (strncmp(ring_tmp->name, temp, NAME_LEN_MAX) == 0) {
                cmd_c2p_base(context,&(ring_tmp->base_subply));
                break;
            }
        }
    } else { 
        if (option_ptr == NULL || *option_ptr == NULL) {
            return CPARSER_NOT_OK;
        }
        
        APR_RING_FOREACH_SAFE(ring_tmp, ring_tmp_n, &sec_policy_ring, security_policy_s, ring) {
            if (strncmp(ring_tmp->name, temp, NAME_LEN_MAX) == 0) {
                sec_policy_get_option(&(ring_tmp->base_subply), option_ptr, buf);
                (ring_tmp->base_subply).action = ACTION_PASS;
                (ring_tmp->base_subply).log = 0;
                (ring_tmp->base_subply).flag = 1;
                
                rv = convert_sec_subpolicy_set((sec_subpolicy_t*)&(ring_tmp->base_subply));
                if (rv != APR_SUCCESS) {
                    cli_printf_info(context, "misc-attack-protect set failure\n");
                    return CPARSER_NOT_OK;
                }

                admin_log_process(context, buf);
                break;
            }
        }
    }
    
    return CPARSER_OK;
}

/* 下面四个接口用来配置path_traversal攻击防护 */
cparser_result_t cparser_cmd_scp_path_traversal_attack_protect(cparser_context_t *context)
{
    security_policy_t *ring_tmp, *ring_tmp_n;
    int rv;
    char *temp;
    char buf[COMMAND_LEN_MAX];

    transfer_security_policy_name(context);
    temp = (char *)context->cookie[context->parser->root_level];

    if (context->parser->mode != CPARSER_MODE_CONFIG) {
        return CPARSER_OK;
    } else {
        APR_RING_FOREACH_SAFE(ring_tmp, ring_tmp_n, &sec_policy_ring, security_policy_s, ring) {
            if (strncmp(ring_tmp->name, temp, NAME_LEN_MAX) == 0) {
                (ring_tmp->path_subply).flag = 1;
                (ring_tmp->path_subply).status = ENABLE;
                (ring_tmp->path_subply).action = ACTION_PASS;
                (ring_tmp->path_subply).log = 0;
                
                rv = convert_sec_subpolicy_set((sec_subpolicy_t*)&(ring_tmp->path_subply));
                if (rv != APR_SUCCESS) {
                    cli_printf_info(context, "path-traversal-attack-protect set failure\n");
                    return CPARSER_NOT_OK;
                }

                sprintf(buf, "path-traversal-attack-protect");
                admin_log_process(context, buf);
                break;
            }
        }
    }
    
    return CPARSER_OK;
}

cparser_result_t cparser_cmd_scp_path_traversal_attack_protect_action_action_option(cparser_context_t *context,
    char **action_ptr,
    char **option_ptr)
{
    security_policy_t *ring_tmp, *ring_tmp_n;
    int rv;
    char *temp;
    char buf[COMMAND_LEN_MAX];
    
    transfer_security_policy_name(context);
    temp = (char *)context->cookie[context->parser->root_level];
    
    if (context == NULL) {
        return CPARSER_NOT_OK;
    }
    
    if (context->parser->mode != CPARSER_MODE_CONFIG) {
        return CPARSER_OK;
    } else {
        if (action_ptr == NULL || *action_ptr == NULL) {
            return CPARSER_NOT_OK;
        }

        APR_RING_FOREACH_SAFE(ring_tmp, ring_tmp_n, &sec_policy_ring, security_policy_s, ring) {
            if (strncmp(ring_tmp->name, temp, NAME_LEN_MAX) == 0) {
                if (option_ptr != NULL) {
                    sec_policy_get_action_option(&(ring_tmp->path_subply), action_ptr, option_ptr, buf); 
                } else {
                    sec_policy_get_action(&(ring_tmp->path_subply), action_ptr, buf);
                    (ring_tmp->path_subply).status = ENABLE;
                }
                
                (ring_tmp->path_subply).flag = 1;
                (ring_tmp->path_subply).log = 0;
                
                rv = convert_sec_subpolicy_set((sec_subpolicy_t*)&(ring_tmp->path_subply));
                if (rv != APR_SUCCESS) {
                    cli_printf_info(context, "path-traversal-attack-protect set failure\n");
                    return CPARSER_NOT_OK;
                }

                admin_log_process(context, buf);
                break;
            }
        }
    }
    
    return CPARSER_OK;
}

cparser_result_t cparser_cmd_scp_path_traversal_attack_protect_action_action_log_option(cparser_context_t *context,
    char **action_ptr,
    char **option_ptr)
{
    security_policy_t *ring_tmp, *ring_tmp_n;
    int rv;
    char *temp;
    char buf[COMMAND_LEN_MAX];

    transfer_security_policy_name(context);
    temp = (char *)context->cookie[context->parser->root_level];

    if (context == NULL) {
        return CPARSER_NOT_OK; 
    }
    
    if (context->parser->mode != CPARSER_MODE_CONFIG) {
        return CPARSER_OK;
    } else {       
        APR_RING_FOREACH_SAFE(ring_tmp, ring_tmp_n, &sec_policy_ring, security_policy_s, ring) {
            if (strncmp(ring_tmp->name, temp, NAME_LEN_MAX) == 0) {
                if (option_ptr != NULL) {
                    sec_policy_get_action_log_option(&(ring_tmp->path_subply), action_ptr, option_ptr, buf); 
                } else {
                    sec_policy_get_action_log(&(ring_tmp->path_subply), action_ptr, buf);
                    (ring_tmp->path_subply).status = ENABLE;
                }
                
                (ring_tmp->path_subply).flag = 1;
                
                rv = convert_sec_subpolicy_set((sec_subpolicy_t*)&(ring_tmp->path_subply));
                if (rv != APR_SUCCESS) {
                    cli_printf_info(context, "path-traversal-attack-protect set failure\n");
                    return CPARSER_NOT_OK;
                }

                admin_log_process(context, buf);
                break;
            }
        }
    }
    
    return CPARSER_OK;
}

cparser_result_t cparser_cmd_scp_path_traversal_attack_protect_option(cparser_context_t *context,
    char **option_ptr)
{
    security_policy_t *ring_tmp, *ring_tmp_n;
    int rv;
    char *temp;
    char buf[COMMAND_LEN_MAX];

    transfer_security_policy_name(context);
    temp = (char *)context->cookie[context->parser->root_level];
    
    if (context == NULL) {
        return CPARSER_NOT_OK;
    }
    
    if (context->parser->mode != CPARSER_MODE_CONFIG) {        
        APR_RING_FOREACH_SAFE(ring_tmp, ring_tmp_n, &sec_policy_ring, security_policy_s, ring) {
            if (strncmp(ring_tmp->name, temp, NAME_LEN_MAX) == 0) {
                cmd_c2p_path(context,&(ring_tmp->path_subply));
                break;
            }
        }
    } else { 
        if (option_ptr == NULL || *option_ptr == NULL) {
            return CPARSER_NOT_OK;
        }
        
        APR_RING_FOREACH_SAFE(ring_tmp, ring_tmp_n, &sec_policy_ring, security_policy_s, ring) {
            if (strncmp(ring_tmp->name, temp, NAME_LEN_MAX) == 0) {
                sec_policy_get_option(&(ring_tmp->path_subply), option_ptr, buf);
                (ring_tmp->path_subply).action = ACTION_PASS;
                (ring_tmp->path_subply).log = 0;
                (ring_tmp->path_subply).flag = 1;
                
                rv = convert_sec_subpolicy_set((sec_subpolicy_t*)&(ring_tmp->path_subply));
                if (rv != APR_SUCCESS) {
                    cli_printf_info(context, "path-traversal-attack-protect set failure\n");
                    return CPARSER_NOT_OK;
                }

                admin_log_process(context, buf);
                break;
            }
        }
    }
    
    return CPARSER_OK;

}

/* 下面四个接口用来配置directory_index防护 */
cparser_result_t cparser_cmd_scp_directory_index_protect(cparser_context_t *context)
{
    security_policy_t *ring_tmp, *ring_tmp_n;
    int rv;
    char *temp;
    char buf[COMMAND_LEN_MAX];

    transfer_security_policy_name(context);
    temp = (char *)context->cookie[context->parser->root_level];

    if (context->parser->mode != CPARSER_MODE_CONFIG) {
        return CPARSER_OK;
    } else {
        APR_RING_FOREACH_SAFE(ring_tmp, ring_tmp_n, &sec_policy_ring, security_policy_s, ring) {
            if (strncmp(ring_tmp->name, temp, NAME_LEN_MAX) == 0) {
                (ring_tmp->dir_subply).flag = 1;
                (ring_tmp->dir_subply).status = ENABLE;
                (ring_tmp->dir_subply).action = ACTION_PASS;
                (ring_tmp->dir_subply).log = 0;
                
                rv = convert_sec_subpolicy_set((sec_subpolicy_t*)&(ring_tmp->dir_subply));
                if (rv != APR_SUCCESS) {
                    cli_printf_info(context, "directory-index-protect set failure\n");
                    return CPARSER_NOT_OK;
                }

                sprintf(buf, "directory-index-protect");
                admin_log_process(context, buf);
                break;
            }
        }
    }
    
    return CPARSER_OK;
}

cparser_result_t cparser_cmd_scp_directory_index_protect_action_action_option(cparser_context_t *context,
    char **action_ptr,
    char **option_ptr)
{
    security_policy_t *ring_tmp, *ring_tmp_n;
    int rv;
    char *temp;
    char buf[COMMAND_LEN_MAX];
    
    transfer_security_policy_name(context);
    temp = (char *)context->cookie[context->parser->root_level];
    
    if (context == NULL) {
        return CPARSER_NOT_OK;
    }
    
    if (context->parser->mode != CPARSER_MODE_CONFIG) {
        return CPARSER_OK;
    } else {
        if (action_ptr == NULL || *action_ptr == NULL) {
            return CPARSER_NOT_OK;
        }

        APR_RING_FOREACH_SAFE(ring_tmp, ring_tmp_n, &sec_policy_ring, security_policy_s, ring) {
            if (strncmp(ring_tmp->name, temp, NAME_LEN_MAX) == 0) {
                if (option_ptr != NULL) {
                    sec_policy_get_action_option(&(ring_tmp->dir_subply), action_ptr, option_ptr, buf); 
                } else {
                    sec_policy_get_action(&(ring_tmp->dir_subply), action_ptr, buf);
                    (ring_tmp->dir_subply).status = ENABLE;
                }
                
                (ring_tmp->dir_subply).flag = 1;
                (ring_tmp->dir_subply).log = 0;
                
                rv = convert_sec_subpolicy_set((sec_subpolicy_t*)&(ring_tmp->dir_subply));
                if (rv != APR_SUCCESS) {
                    cli_printf_info(context, "directory-index-protect set failure\n");
                    return CPARSER_NOT_OK;
                }

                admin_log_process(context, buf);
                break;
            }
        }
    }
    
    return CPARSER_OK;
}

cparser_result_t cparser_cmd_scp_directory_index_protect_action_action_log_option(cparser_context_t *context,
    char **action_ptr,
    char **option_ptr)
{
    security_policy_t *ring_tmp, *ring_tmp_n;
    int rv;
    char *temp;
    char buf[COMMAND_LEN_MAX];

    transfer_security_policy_name(context);
    temp = (char *)context->cookie[context->parser->root_level];

    if (context == NULL) {
        return CPARSER_NOT_OK; 
    }
    
    if (context->parser->mode != CPARSER_MODE_CONFIG) {
        return CPARSER_OK;
    } else {       
        APR_RING_FOREACH_SAFE(ring_tmp, ring_tmp_n, &sec_policy_ring, security_policy_s, ring) {
            if (strncmp(ring_tmp->name, temp, NAME_LEN_MAX) == 0) {
                if (option_ptr != NULL) {
                    sec_policy_get_action_log_option(&(ring_tmp->dir_subply), action_ptr, option_ptr, buf); 
                } else {
                    sec_policy_get_action_log(&(ring_tmp->dir_subply), action_ptr, buf);
                    (ring_tmp->dir_subply).status = ENABLE;
                }
                
                (ring_tmp->dir_subply).flag = 1;
                
                rv = convert_sec_subpolicy_set((sec_subpolicy_t*)&(ring_tmp->dir_subply));
                if (rv != APR_SUCCESS) {
                    cli_printf_info(context, "directory-index-protect set failure\n");
                    return CPARSER_NOT_OK;
                }

                admin_log_process(context, buf);
                break;
            }
        }
    }
    
    return CPARSER_OK;

}

cparser_result_t cparser_cmd_scp_directory_index_protect_option(cparser_context_t *context,
    char **option_ptr)
{
    security_policy_t *ring_tmp, *ring_tmp_n;
    int rv;
    char *temp;
    char buf[COMMAND_LEN_MAX];

    transfer_security_policy_name(context);
    temp = (char *)context->cookie[context->parser->root_level];
    
    if (context == NULL) {
        return CPARSER_NOT_OK;
    }
    
    if (context->parser->mode != CPARSER_MODE_CONFIG) {        
        APR_RING_FOREACH_SAFE(ring_tmp, ring_tmp_n, &sec_policy_ring, security_policy_s, ring) {
            if (strncmp(ring_tmp->name, temp, NAME_LEN_MAX) == 0) {
                cmd_c2p_directory(context,&(ring_tmp->dir_subply));
                break;
            }
        }
    } else { 
        if (option_ptr == NULL || *option_ptr == NULL) {
            return CPARSER_NOT_OK;
        }
        
        APR_RING_FOREACH_SAFE(ring_tmp, ring_tmp_n, &sec_policy_ring, security_policy_s, ring) {
            if (strncmp(ring_tmp->name, temp, NAME_LEN_MAX) == 0) {
                sec_policy_get_option(&(ring_tmp->dir_subply), option_ptr, buf);
                (ring_tmp->dir_subply).action = ACTION_PASS;
                (ring_tmp->dir_subply).log = 0;
                (ring_tmp->dir_subply).flag = 1;
                
                rv = convert_sec_subpolicy_set((sec_subpolicy_t*)&(ring_tmp->dir_subply));
                if (rv != APR_SUCCESS) {
                    cli_printf_info(context, "directory-index-protect set failure\n");
                    return CPARSER_NOT_OK;
                }

                admin_log_process(context, buf);
                break;
            }
        }
    }
    
    return CPARSER_OK;

}

/* 下面四个接口用来配置spider_scanner攻击防护 */
cparser_result_t cparser_cmd_scp_spider_scanner_attack_protect(cparser_context_t *context)
{
    char prompt[CPARSER_MAX_PROMPT];
    security_policy_t *ring_tmp, *ring_tmp_n;
    int rv;
    char *temp;
    char buf[COMMAND_LEN_MAX];

    transfer_security_policy_name(context);
    temp = (char *)context->cookie[context->parser->root_level];

    if (context == NULL) {
        return CPARSER_NOT_OK;
    }

    if (context->parser->mode != CPARSER_MODE_CONFIG) {
        return CPARSER_OK;
    } else {
        APR_RING_FOREACH_SAFE(ring_tmp, ring_tmp_n, &sec_policy_ring, security_policy_s, ring) {
            if (strncmp(ring_tmp->name, temp, NAME_LEN_MAX) == 0) {
                (ring_tmp->spider_subply).flag = 1;
                (ring_tmp->spider_subply).status = ENABLE;
                (ring_tmp->spider_subply).action = ACTION_PASS;
                (ring_tmp->spider_subply).log = 0;
                
                rv = convert_sec_subpolicy_set((sec_subpolicy_t*)&(ring_tmp->spider_subply));
                if (rv != APR_SUCCESS) {
                    cli_printf_info(context, "spider-scanner-attack-protect set failure\n");
                    return CPARSER_NOT_OK;
                }

                sprintf(buf, "spider-scanner-attack-protect");
                admin_log_process(context, buf);
                break;
            }
        }

        context->parser->cur_node = &cparser_node_pe_protect_engine_security_policy_secpname_root_spider_scanner_attack_protect_option_eol;
        snprintf(prompt, CPARSER_MAX_PROMPT, "%s(spider)#", g_cli_prompt);
        return cparser_submode_enter(context->parser, temp, prompt);
    }
    
    return CPARSER_OK;
}

cparser_result_t cparser_cmd_scp_spider_scanner_attack_protect_action_action_option(cparser_context_t *context,
    char **action_ptr,
    char **option_ptr)
{
    char prompt[CPARSER_MAX_PROMPT];
    security_policy_t *ring_tmp, *ring_tmp_n;
    int rv;
    char *temp;
    char buf[COMMAND_LEN_MAX];

    transfer_security_policy_name(context);
    temp = (char *)context->cookie[context->parser->root_level];
    
    if (context == NULL) {
        return CPARSER_NOT_OK;
    }
    
    if (context->parser->mode != CPARSER_MODE_CONFIG) {
        return CPARSER_OK;
    } else {
        if (action_ptr == NULL || *action_ptr == NULL) {
            return CPARSER_NOT_OK;
        }

        APR_RING_FOREACH_SAFE(ring_tmp, ring_tmp_n, &sec_policy_ring, security_policy_s, ring) {
            if (strncmp(ring_tmp->name, temp, NAME_LEN_MAX) == 0) {
                if (option_ptr != NULL) {
                    sec_policy_get_action_option(&(ring_tmp->spider_subply), action_ptr, option_ptr, buf); 
                } else {
                    sec_policy_get_action(&(ring_tmp->spider_subply), action_ptr, buf);
                    (ring_tmp->spider_subply).status = ENABLE;
                }
                
                (ring_tmp->spider_subply).flag = 1;
                (ring_tmp->spider_subply).log = 0;
                
                rv = convert_sec_subpolicy_set((sec_subpolicy_t*)&(ring_tmp->spider_subply));
                if (rv != APR_SUCCESS) {
                    cli_printf_info(context, "spider-scanner-attack-protect set failure\n");
                    return CPARSER_NOT_OK;
                }

                admin_log_process(context, buf);
                break;
            }
        }
        
        context->parser->cur_node = &cparser_node_pe_protect_engine_security_policy_secpname_root_spider_scanner_attack_protect_option_eol;
        snprintf(prompt, CPARSER_MAX_PROMPT, "%s(spider)#", g_cli_prompt);
        return cparser_submode_enter(context->parser, temp, prompt);
    }
    
    return CPARSER_OK;
}

cparser_result_t cparser_cmd_scp_spider_scanner_attack_protect_action_action_log_option(cparser_context_t *context,
    char **action_ptr,
    char **option_ptr)
{
    char prompt[CPARSER_MAX_PROMPT];
    security_policy_t *ring_tmp, *ring_tmp_n;
    int rv;
    char *temp;
    char buf[COMMAND_LEN_MAX];

    transfer_security_policy_name(context);
    temp = (char *)context->cookie[context->parser->root_level];

    if (context == NULL) {
        return CPARSER_NOT_OK; 
    }
    
    if (context->parser->mode != CPARSER_MODE_CONFIG) {
        return CPARSER_OK;
    } else {       
        APR_RING_FOREACH_SAFE(ring_tmp, ring_tmp_n, &sec_policy_ring, security_policy_s, ring) {
            if (strncmp(ring_tmp->name, temp, NAME_LEN_MAX) == 0) {
                if (option_ptr != NULL) {
                    sec_policy_get_action_log_option(&(ring_tmp->spider_subply), action_ptr, option_ptr, buf); 
                } else {
                    sec_policy_get_action_log(&(ring_tmp->spider_subply), action_ptr, buf);
                    (ring_tmp->spider_subply).status = ENABLE;
                }
                
                (ring_tmp->spider_subply).flag = 1;
                
                rv = convert_sec_subpolicy_set((sec_subpolicy_t*)&(ring_tmp->spider_subply));
                if (rv != APR_SUCCESS) {
                    cli_printf_info(context, "spider-scanner-attack-protect set failure\n");
                    return CPARSER_NOT_OK;
                }

                admin_log_process(context, buf);
                break;
            }
        }

        context->parser->cur_node = &cparser_node_pe_protect_engine_security_policy_secpname_root_spider_scanner_attack_protect_option_eol;
        snprintf(prompt, CPARSER_MAX_PROMPT, "%s(spider)#", g_cli_prompt);
        return cparser_submode_enter(context->parser, temp, prompt);
    }
    
    return CPARSER_OK;
}

cparser_result_t cparser_cmd_scp_spider_scanner_attack_protect_option(cparser_context_t *context,
    char **option_ptr)
{
    char prompt[CPARSER_MAX_PROMPT];
    security_policy_t *ring_tmp, *ring_tmp_n;
    int rv;
    char *temp;
    char buf[COMMAND_LEN_MAX];

    transfer_security_policy_name(context);
    temp = (char *)context->cookie[context->parser->root_level];
    
    if (context == NULL) {
        return CPARSER_NOT_OK;
    }
    
    if (context->parser->mode != CPARSER_MODE_CONFIG) {        
        APR_RING_FOREACH_SAFE(ring_tmp, ring_tmp_n, &sec_policy_ring, security_policy_s, ring) {
            if (strncmp(ring_tmp->name, temp, NAME_LEN_MAX) == 0) {
                cmd_c2p_spider(context, &(ring_tmp->spider_subply));
                break;
            }
        }
    } else { 
        if (option_ptr == NULL || *option_ptr == NULL) {
            return CPARSER_NOT_OK;
        }
        
        APR_RING_FOREACH_SAFE(ring_tmp, ring_tmp_n, &sec_policy_ring, security_policy_s, ring) {
            if (strncmp(ring_tmp->name, temp, NAME_LEN_MAX) == 0) {
                sec_policy_get_option(&(ring_tmp->spider_subply), option_ptr, buf);
                (ring_tmp->spider_subply).action = ACTION_PASS;
                (ring_tmp->spider_subply).log = 0;
                (ring_tmp->spider_subply).flag = 1;
                
                rv = convert_sec_subpolicy_set((sec_subpolicy_t*)&(ring_tmp->spider_subply));
                if (rv != APR_SUCCESS) {
                    cli_printf_info(context, "spider-scanner-attack-protect set failure\n");
                    return CPARSER_NOT_OK;
                }

                admin_log_process(context, buf);
                break;
            }
        }

        snprintf(prompt, CPARSER_MAX_PROMPT, "%s(spider)#", g_cli_prompt);
        return cparser_submode_enter(context->parser, temp, prompt);
    }
    
    return CPARSER_OK;
}

/* 下面四个接口用来配置trojan防护 */
cparser_result_t cparser_cmd_scp_trojan_protect(cparser_context_t *context)
{
    char prompt[CPARSER_MAX_PROMPT];
    security_policy_t *ring_tmp, *ring_tmp_n;
    int rv;
    char *temp;
    char buf[COMMAND_LEN_MAX];

    transfer_security_policy_name(context);
    temp = (char *)context->cookie[context->parser->root_level];

    if (context == NULL) {
        return CPARSER_NOT_OK;
    }

    if (context->parser->mode != CPARSER_MODE_CONFIG) {
        return CPARSER_OK;
    } else {
        APR_RING_FOREACH_SAFE(ring_tmp, ring_tmp_n, &sec_policy_ring, security_policy_s, ring) {
            if (strncmp(ring_tmp->name, temp, NAME_LEN_MAX) == 0) {
                (ring_tmp->trojan_subply).flag = 1;
                (ring_tmp->trojan_subply).status = ENABLE;
                (ring_tmp->trojan_subply).action = ACTION_PASS;
                (ring_tmp->trojan_subply).log = 0;
                
                rv = convert_sec_subpolicy_set((sec_subpolicy_t*)&(ring_tmp->trojan_subply));
                if (rv != APR_SUCCESS) {
                    cli_printf_info(context, "trojan-protect set failure\n");
                    return CPARSER_NOT_OK;
                }

                sprintf(buf, "trojan-protect");
                admin_log_process(context, buf);
                break;
            }
        }

        context->parser->cur_node = &cparser_node_pe_protect_engine_security_policy_secpname_root_trojan_protect_option_eol;
        snprintf(prompt, CPARSER_MAX_PROMPT, "%s(trojan)#", g_cli_prompt);
        return cparser_submode_enter(context->parser, temp, prompt);
    }
    
    return CPARSER_OK;
}

cparser_result_t cparser_cmd_scp_trojan_protect_action_action_option(cparser_context_t *context,
    char **action_ptr,
    char **option_ptr)
{
    char prompt[CPARSER_MAX_PROMPT];
    security_policy_t *ring_tmp, *ring_tmp_n;
    int rv;
    char *temp;
    char buf[COMMAND_LEN_MAX];

    transfer_security_policy_name(context);
    temp = (char *)context->cookie[context->parser->root_level];

    if (context == NULL) {
        return CPARSER_NOT_OK;
    }

    if (context->parser->mode != CPARSER_MODE_CONFIG) {
        return CPARSER_OK;
    } else {
        APR_RING_FOREACH_SAFE(ring_tmp, ring_tmp_n, &sec_policy_ring, security_policy_s, ring) {
            if (strncmp(ring_tmp->name, temp, NAME_LEN_MAX) == 0) {
                if (option_ptr != NULL) {
                    sec_policy_get_action_option(&(ring_tmp->trojan_subply), action_ptr, option_ptr, buf); 
                } else {
                    sec_policy_get_action(&(ring_tmp->trojan_subply), action_ptr, buf);
                    (ring_tmp->trojan_subply).status = ENABLE;
                }
                
                (ring_tmp->trojan_subply).flag = 1;
                (ring_tmp->trojan_subply).log = 0;
                
                rv = convert_sec_subpolicy_set((sec_subpolicy_t*)&(ring_tmp->trojan_subply));
                if (rv != APR_SUCCESS) {
                    cli_printf_info(context, "trojan-protect set failure\n");
                    return CPARSER_NOT_OK;
                }

                admin_log_process(context, buf);
                break;
            }
        }

        context->parser->cur_node = &cparser_node_pe_protect_engine_security_policy_secpname_root_trojan_protect_option_eol;
        snprintf(prompt, CPARSER_MAX_PROMPT, "%s(trojan)#", g_cli_prompt);
        return cparser_submode_enter(context->parser, temp, prompt);
    }
    
    return CPARSER_OK;
}

cparser_result_t cparser_cmd_scp_trojan_protect_action_action_log_option(cparser_context_t *context,
    char **action_ptr,
    char **option_ptr)
{
    char prompt[CPARSER_MAX_PROMPT];
    security_policy_t *ring_tmp, *ring_tmp_n;
    int rv;
    char *temp;
    char buf[COMMAND_LEN_MAX];

    transfer_security_policy_name(context);
    temp = (char *)context->cookie[context->parser->root_level];

    if (context == NULL) {
        return CPARSER_NOT_OK; 
    }
    
    if (context->parser->mode != CPARSER_MODE_CONFIG) {
        return CPARSER_OK;
    } else {       
        APR_RING_FOREACH_SAFE(ring_tmp, ring_tmp_n, &sec_policy_ring, security_policy_s, ring) {
            if (strncmp(ring_tmp->name, temp, NAME_LEN_MAX) == 0) {
                if (option_ptr != NULL) {
                    sec_policy_get_action_log_option(&(ring_tmp->trojan_subply), action_ptr, option_ptr, buf); 
                } else {
                    sec_policy_get_action_log(&(ring_tmp->trojan_subply), action_ptr, buf);
                    (ring_tmp->trojan_subply).status = ENABLE;
                }
                
                (ring_tmp->trojan_subply).flag = 1;
                
                rv = convert_sec_subpolicy_set((sec_subpolicy_t*)&(ring_tmp->trojan_subply));
                if (rv != APR_SUCCESS) {
                    cli_printf_info(context, "trojan-protect set failure\n");
                    return CPARSER_NOT_OK;
                }

                admin_log_process(context, buf);
                break;
            }
        }

        context->parser->cur_node = &cparser_node_pe_protect_engine_security_policy_secpname_root_trojan_protect_option_eol;
        snprintf(prompt, CPARSER_MAX_PROMPT, "%s(trojan)#", g_cli_prompt);
        return cparser_submode_enter(context->parser, temp, prompt);
    }
    
    return CPARSER_OK;
}

cparser_result_t cparser_cmd_scp_trojan_protect_option(cparser_context_t *context,
    char **option_ptr)
{
    char prompt[CPARSER_MAX_PROMPT];
    security_policy_t *ring_tmp, *ring_tmp_n;
    int rv;
    char *temp;
    char buf[COMMAND_LEN_MAX];

    transfer_security_policy_name(context);
    temp = (char *)context->cookie[context->parser->root_level];
    
    if (context == NULL) {
        return CPARSER_NOT_OK;
    }
    
    if (context->parser->mode != CPARSER_MODE_CONFIG) {        
        APR_RING_FOREACH_SAFE(ring_tmp, ring_tmp_n, &sec_policy_ring, security_policy_s, ring) {
            if (strncmp(ring_tmp->name, temp, NAME_LEN_MAX) == 0) {
                cmd_c2p_trojan(context, &(ring_tmp->trojan_subply));
                break;
            }
        }
    } else { 
        if (option_ptr == NULL || *option_ptr == NULL) {
            return CPARSER_NOT_OK;
        }
        
        APR_RING_FOREACH_SAFE(ring_tmp, ring_tmp_n, &sec_policy_ring, security_policy_s, ring) {
            if (strncmp(ring_tmp->name, temp, NAME_LEN_MAX) == 0) {
                sec_policy_get_option(&(ring_tmp->trojan_subply), option_ptr, buf);
                (ring_tmp->trojan_subply).action = ACTION_PASS;
                (ring_tmp->trojan_subply).log = 0;
                (ring_tmp->trojan_subply).flag = 1;
                
                rv = convert_sec_subpolicy_set((sec_subpolicy_t*)&(ring_tmp->trojan_subply));
                if (rv != APR_SUCCESS) {
                    cli_printf_info(context, "trojan-protect set failure\n");
                    return CPARSER_NOT_OK;
                }

                admin_log_process(context, buf);
                break;
            }
        }

        snprintf(prompt, CPARSER_MAX_PROMPT, "%s(trojan)#", g_cli_prompt);
        return cparser_submode_enter(context->parser, temp, prompt);
    }
    
    return CPARSER_OK; 
}

/* 下面四个接口用来配置xml攻击防护 */
cparser_result_t cparser_cmd_scp_xml_attack_protect(cparser_context_t *context)
{
    security_policy_t *ring_tmp, *ring_tmp_n;
    int rv;
    char *temp;
    char buf[COMMAND_LEN_MAX];

    transfer_security_policy_name(context);
    temp = (char *)context->cookie[context->parser->root_level];

    if (context->parser->mode != CPARSER_MODE_CONFIG) {
        return CPARSER_OK;
    } else {
        APR_RING_FOREACH_SAFE(ring_tmp, ring_tmp_n, &sec_policy_ring, security_policy_s, ring) {
            if (strncmp(ring_tmp->name, temp, NAME_LEN_MAX) == 0) {
                (ring_tmp->xml_subply).flag = 1;
                (ring_tmp->xml_subply).status = ENABLE;
                (ring_tmp->xml_subply).action = ACTION_PASS;
                (ring_tmp->xml_subply).log = 0;
                
                rv = convert_sec_subpolicy_set((sec_subpolicy_t*)&(ring_tmp->xml_subply));
                if (rv != APR_SUCCESS) {
                    cli_printf_info(context, "xml-attack-protect set failure\n");
                    return CPARSER_NOT_OK;
                }

                sprintf(buf, "xml-attack-protect");
                admin_log_process(context, buf);
                break;
            }
        }
    }
    
    return CPARSER_OK;
}

cparser_result_t cparser_cmd_scp_xml_attack_protect_action_action_option(cparser_context_t *context,
    char **action_ptr,
    char **option_ptr)
{
    security_policy_t *ring_tmp, *ring_tmp_n;
    int rv;
    char *temp;
    char buf[COMMAND_LEN_MAX];
    
    transfer_security_policy_name(context);
    temp = (char *)context->cookie[context->parser->root_level];
    
    if (context == NULL) {
        return CPARSER_NOT_OK;
    }
    
    if (context->parser->mode != CPARSER_MODE_CONFIG) {
        return CPARSER_OK;
    } else {
        if (action_ptr == NULL || *action_ptr == NULL) {
            return CPARSER_NOT_OK;
        }

        APR_RING_FOREACH_SAFE(ring_tmp, ring_tmp_n, &sec_policy_ring, security_policy_s, ring) {
            if (strncmp(ring_tmp->name, temp, NAME_LEN_MAX) == 0) {
                if (option_ptr != NULL) {
                    sec_policy_get_action_option(&(ring_tmp->xml_subply), action_ptr, option_ptr, buf); 
                } else {
                    sec_policy_get_action(&(ring_tmp->xml_subply), action_ptr, buf);
                    (ring_tmp->xml_subply).status = ENABLE;
                }
                
                (ring_tmp->xml_subply).flag = 1;
                (ring_tmp->xml_subply).log = 0;
                
                rv = convert_sec_subpolicy_set((sec_subpolicy_t*)&(ring_tmp->xml_subply));
                if (rv != APR_SUCCESS) {
                    cli_printf_info(context, "xml-attack-protect set failure\n");
                    return CPARSER_NOT_OK;
                }

                admin_log_process(context, buf);
                break;
            }
        }
    }
    
    return CPARSER_OK;
}

cparser_result_t cparser_cmd_scp_xml_attack_protect_action_action_log_option(cparser_context_t *context,
    char **action_ptr,
    char **option_ptr)
{
    security_policy_t *ring_tmp, *ring_tmp_n;
    int rv;
    char *temp;
    char buf[COMMAND_LEN_MAX];

    transfer_security_policy_name(context);
    temp = (char *)context->cookie[context->parser->root_level];

    if (context == NULL) {
        return CPARSER_NOT_OK; 
    }
    
    if (context->parser->mode != CPARSER_MODE_CONFIG) {
        return CPARSER_OK;
    } else {       
        APR_RING_FOREACH_SAFE(ring_tmp, ring_tmp_n, &sec_policy_ring, security_policy_s, ring) {
            if (strncmp(ring_tmp->name, temp, NAME_LEN_MAX) == 0) {
                if (option_ptr != NULL) {
                    sec_policy_get_action_log_option(&(ring_tmp->xml_subply), action_ptr, option_ptr, buf); 
                } else {
                    sec_policy_get_action_log(&(ring_tmp->xml_subply), action_ptr, buf);
                    (ring_tmp->xml_subply).status = ENABLE;
                }
                
                (ring_tmp->xml_subply).flag = 1;
                
                rv = convert_sec_subpolicy_set((sec_subpolicy_t*)&(ring_tmp->xml_subply));
                if (rv != APR_SUCCESS) {
                    cli_printf_info(context, "xml-attack-protect set failure\n");
                    return CPARSER_NOT_OK;
                }

                admin_log_process(context, buf);
                break;
            }
        }
    }
    
    return CPARSER_OK;

}

cparser_result_t cparser_cmd_scp_xml_attack_protect_option(cparser_context_t *context,
    char **option_ptr)
{
    security_policy_t *ring_tmp, *ring_tmp_n;
    int rv;
    char *temp;
    char buf[COMMAND_LEN_MAX];

    transfer_security_policy_name(context);
    temp = (char *)context->cookie[context->parser->root_level];
    
    if (context == NULL) {
        return CPARSER_NOT_OK;
    }
    
    if (context->parser->mode != CPARSER_MODE_CONFIG) {        
        APR_RING_FOREACH_SAFE(ring_tmp, ring_tmp_n, &sec_policy_ring, security_policy_s, ring) {
            if (strncmp(ring_tmp->name, temp, NAME_LEN_MAX) == 0) {
                cmd_c2p_xml(context, &(ring_tmp->xml_subply));
                break;
            }
        }
    } else { 
        if (option_ptr == NULL || *option_ptr == NULL) {
            return CPARSER_NOT_OK;
        }
        
        APR_RING_FOREACH_SAFE(ring_tmp, ring_tmp_n, &sec_policy_ring, security_policy_s, ring) {
            if (strncmp(ring_tmp->name, temp, NAME_LEN_MAX) == 0) {
                sec_policy_get_option(&(ring_tmp->xml_subply), option_ptr, buf);
                (ring_tmp->xml_subply).action = ACTION_PASS;
                (ring_tmp->xml_subply).log = 0;
                (ring_tmp->xml_subply).flag = 1;
                
                rv = convert_sec_subpolicy_set((sec_subpolicy_t*)&(ring_tmp->xml_subply));
                if (rv != APR_SUCCESS) {
                    cli_printf_info(context, "xml-attack-protect set failure\n");
                    return CPARSER_NOT_OK;
                }

                admin_log_process(context, buf);
                break;
            }
        }
    }
    
    return CPARSER_OK;

}

/* 下面四个接口用来配置http_status_code防护 */
cparser_result_t cparser_cmd_scp_http_status_code_protect(cparser_context_t *context)
{
    security_policy_t *ring_tmp, *ring_tmp_n;
    int rv;
    char *temp;
    char buf[COMMAND_LEN_MAX];

    transfer_security_policy_name(context);
    temp = (char *)context->cookie[context->parser->root_level];

    if (context->parser->mode != CPARSER_MODE_CONFIG) {
        return CPARSER_OK;
    } else {
        APR_RING_FOREACH_SAFE(ring_tmp, ring_tmp_n, &sec_policy_ring, security_policy_s, ring) {
            if (strncmp(ring_tmp->name, temp, NAME_LEN_MAX) == 0) {
                (ring_tmp->http_subply).flag = 1;
                (ring_tmp->http_subply).status = ENABLE;
                (ring_tmp->http_subply).action = ACTION_PASS;
                (ring_tmp->http_subply).log = 0;
                
                rv = convert_sec_subpolicy_set((sec_subpolicy_t*)&(ring_tmp->http_subply));
                if (rv != APR_SUCCESS) {
                    cli_printf_info(context, "http-status-code-protect set failure\n");
                    return CPARSER_NOT_OK;
                }

                sprintf(buf, "http-status-code-protect");
                admin_log_process(context, buf);
                break;
            }
        }
    }
    
    return CPARSER_OK;
}

cparser_result_t cparser_cmd_scp_http_status_code_protect_action_action_option(cparser_context_t *context,
    char **action_ptr,
    char **option_ptr)
{
    security_policy_t *ring_tmp, *ring_tmp_n;
    int rv;
    char *temp;
    char buf[COMMAND_LEN_MAX];
    
    transfer_security_policy_name(context);
    temp = (char *)context->cookie[context->parser->root_level];
    
    if (context == NULL) {
        return CPARSER_NOT_OK;
    }
    
    if (context->parser->mode != CPARSER_MODE_CONFIG) {
        return CPARSER_OK;
    } else {
        if (action_ptr == NULL || *action_ptr == NULL) {
            return CPARSER_NOT_OK;
        }

        APR_RING_FOREACH_SAFE(ring_tmp, ring_tmp_n, &sec_policy_ring, security_policy_s, ring) {
            if (strncmp(ring_tmp->name, temp, NAME_LEN_MAX) == 0) {
                if (option_ptr != NULL) {
                    sec_policy_get_action_option(&(ring_tmp->http_subply), action_ptr, option_ptr, buf); 
                } else {
                    sec_policy_get_action(&(ring_tmp->http_subply), action_ptr, buf);
                    (ring_tmp->http_subply).status = ENABLE;
                }
                
                (ring_tmp->http_subply).flag = 1;
                (ring_tmp->http_subply).log = 0;
                
                rv = convert_sec_subpolicy_set((sec_subpolicy_t*)&(ring_tmp->http_subply));
                if (rv != APR_SUCCESS) {
                    cli_printf_info(context, "http-status-code-protect set failure\n");
                    return CPARSER_NOT_OK;
                }

                admin_log_process(context, buf);
                break;
            }
        }
    }
    
    return CPARSER_OK;

}

cparser_result_t cparser_cmd_scp_http_status_code_protect_action_action_log_option(cparser_context_t *context,
    char **action_ptr,
    char **option_ptr)
{
    security_policy_t *ring_tmp, *ring_tmp_n;
    int rv;
    char *temp;
    char buf[COMMAND_LEN_MAX];

    transfer_security_policy_name(context);
    temp = (char *)context->cookie[context->parser->root_level];

    if (context == NULL) {
        return CPARSER_NOT_OK; 
    }
    
    if (context->parser->mode != CPARSER_MODE_CONFIG) {
        return CPARSER_OK;
    } else {       
        APR_RING_FOREACH_SAFE(ring_tmp, ring_tmp_n, &sec_policy_ring, security_policy_s, ring) {
            if (strncmp(ring_tmp->name, temp, NAME_LEN_MAX) == 0) {
                if (option_ptr != NULL) {
                    sec_policy_get_action_log_option(&(ring_tmp->http_subply), action_ptr, option_ptr, buf); 
                } else {
                    sec_policy_get_action_log(&(ring_tmp->http_subply), action_ptr, buf);
                    (ring_tmp->http_subply).status = ENABLE;
                }
                
                (ring_tmp->http_subply).flag = 1;
                
                rv = convert_sec_subpolicy_set((sec_subpolicy_t*)&(ring_tmp->http_subply));
                if (rv != APR_SUCCESS) {
                    cli_printf_info(context, "http-status-code-protect set failure\n");
                    return CPARSER_NOT_OK;
                }

                admin_log_process(context, buf);
                break;
            }
        }
    }
    
    return CPARSER_OK;
}

cparser_result_t cparser_cmd_scp_http_status_code_protect_option(cparser_context_t *context,
    char **option_ptr)
{
    security_policy_t *ring_tmp, *ring_tmp_n;
    int rv;
    char *temp;
    char buf[COMMAND_LEN_MAX];

    transfer_security_policy_name(context);
    temp = (char *)context->cookie[context->parser->root_level];
    
    if (context == NULL) {
        return CPARSER_NOT_OK;
    }
    
    if (context->parser->mode != CPARSER_MODE_CONFIG) {        
        APR_RING_FOREACH_SAFE(ring_tmp, ring_tmp_n, &sec_policy_ring, security_policy_s, ring) {
            if (strncmp(ring_tmp->name, temp, NAME_LEN_MAX) == 0) {
                cmd_c2p_http(context, &(ring_tmp->http_subply));
                break;
            }
        }
    } else { 
        if (option_ptr == NULL || *option_ptr == NULL) {
            return CPARSER_NOT_OK;
        }
        
        APR_RING_FOREACH_SAFE(ring_tmp, ring_tmp_n, &sec_policy_ring, security_policy_s, ring) {
            if (strncmp(ring_tmp->name, temp, NAME_LEN_MAX) == 0) {
                sec_policy_get_option(&(ring_tmp->http_subply), option_ptr, buf);
                (ring_tmp->http_subply).action = ACTION_PASS;
                (ring_tmp->http_subply).log = 0;
                (ring_tmp->http_subply).flag = 1;
                
                rv = convert_sec_subpolicy_set((sec_subpolicy_t*)&(ring_tmp->http_subply));
                if (rv != APR_SUCCESS) {
                    cli_printf_info(context, "http-status-code-protect  set failure\n");
                    return CPARSER_NOT_OK;
                }

                admin_log_process(context, buf);
                break;
            }
        }
    }
    
    return CPARSER_OK;
}

/* 下面四个接口用来配置server_error_information防护 */
cparser_result_t cparser_cmd_scp_server_error_information_protect(cparser_context_t *context)
{
    security_policy_t *ring_tmp, *ring_tmp_n;
    int rv;
    char *temp;
    char buf[COMMAND_LEN_MAX];

    transfer_security_policy_name(context);
    temp = (char *)context->cookie[context->parser->root_level];

    if (context->parser->mode != CPARSER_MODE_CONFIG) {
        return CPARSER_OK;
    } else {
        APR_RING_FOREACH_SAFE(ring_tmp, ring_tmp_n, &sec_policy_ring, security_policy_s, ring) {
            if (strncmp(ring_tmp->name, temp, NAME_LEN_MAX) == 0) {
                (ring_tmp->server_subply).flag = 1;
                (ring_tmp->server_subply).status = ENABLE;
                (ring_tmp->server_subply).action = ACTION_PASS;
                (ring_tmp->server_subply).log = 0;
                
                rv = convert_sec_subpolicy_set((sec_subpolicy_t*)&(ring_tmp->server_subply));
                if (rv != APR_SUCCESS) {
                    cli_printf_info(context, "server-error-information-protect set failure\n");
                    return CPARSER_NOT_OK;
                }

                sprintf(buf, "server-error-information-protect");
                admin_log_process(context, buf);
                break;
            }
        }
    }
    
    return CPARSER_OK;
}

cparser_result_t cparser_cmd_scp_server_error_information_protect_action_action_option(cparser_context_t *context,
    char **action_ptr,
    char **option_ptr)
{
    security_policy_t *ring_tmp, *ring_tmp_n;
    int rv;
    char *temp;
    char buf[COMMAND_LEN_MAX];
    
    transfer_security_policy_name(context);
    temp = (char *)context->cookie[context->parser->root_level];
    
    if (context == NULL) {
        return CPARSER_NOT_OK;
    }
    
    if (context->parser->mode != CPARSER_MODE_CONFIG) {
        return CPARSER_OK;
    } else {
        if (action_ptr == NULL || *action_ptr == NULL) {
            return CPARSER_NOT_OK;
        }

        APR_RING_FOREACH_SAFE(ring_tmp, ring_tmp_n, &sec_policy_ring, security_policy_s, ring) {
            if (strncmp(ring_tmp->name, temp, NAME_LEN_MAX) == 0) {
                if (option_ptr != NULL) {
                    sec_policy_get_action_option(&(ring_tmp->server_subply), action_ptr, option_ptr, buf); 
                } else {
                    sec_policy_get_action(&(ring_tmp->server_subply), action_ptr, buf);
                    (ring_tmp->server_subply).status = ENABLE;
                }
                
                (ring_tmp->server_subply).flag = 1;
                (ring_tmp->server_subply).log = 0;
                
                rv = convert_sec_subpolicy_set((sec_subpolicy_t*)&(ring_tmp->server_subply));
                if (rv != APR_SUCCESS) {
                    cli_printf_info(context, "server-error-information-protect set failure\n");
                    return CPARSER_NOT_OK;
                }

                admin_log_process(context, buf);
                break;
            }
        }
    }
    
    return CPARSER_OK;
}

cparser_result_t cparser_cmd_scp_server_error_information_protect_option(cparser_context_t *context,
    char **option_ptr)
{
    security_policy_t *ring_tmp, *ring_tmp_n;
    int rv;
    char *temp;
    char buf[COMMAND_LEN_MAX];

    transfer_security_policy_name(context);
    temp = (char *)context->cookie[context->parser->root_level];
    
    if (context == NULL) {
        return CPARSER_NOT_OK;
    }
    
    if (context->parser->mode != CPARSER_MODE_CONFIG) {        
        APR_RING_FOREACH_SAFE(ring_tmp, ring_tmp_n, &sec_policy_ring, security_policy_s, ring) {
            if (strncmp(ring_tmp->name, temp, NAME_LEN_MAX) == 0) {
                cmd_c2p_server_error(context, &(ring_tmp->server_subply));
                break;
            }
        }
    } else { 
        if (option_ptr == NULL || *option_ptr == NULL) {
            return CPARSER_NOT_OK;
        }
        
        APR_RING_FOREACH_SAFE(ring_tmp, ring_tmp_n, &sec_policy_ring, security_policy_s, ring) {
            if (strncmp(ring_tmp->name, temp, NAME_LEN_MAX) == 0) {
                sec_policy_get_option(&(ring_tmp->server_subply), option_ptr, buf);
                (ring_tmp->server_subply).action = ACTION_PASS;
                (ring_tmp->server_subply).log = 0;
                (ring_tmp->server_subply).flag = 1;
                
                rv = convert_sec_subpolicy_set((sec_subpolicy_t*)&(ring_tmp->server_subply));
                if (rv != APR_SUCCESS) {
                    cli_printf_info(context, "server-error-information-protect set failure\n");
                    return CPARSER_NOT_OK;
                }

                admin_log_process(context, buf);
                break;
            }
        }
    }
    
    return CPARSER_OK;
}

cparser_result_t cparser_cmd_scp_server_error_information_protect_action_action_log_option(cparser_context_t *context,
    char **action_ptr,
    char **option_ptr)
{
    security_policy_t *ring_tmp, *ring_tmp_n;
    int rv;
    char *temp;
    char buf[COMMAND_LEN_MAX];

    transfer_security_policy_name(context);
    temp = (char *)context->cookie[context->parser->root_level];

    if (context == NULL) {
        return CPARSER_NOT_OK; 
    }
    
    if (context->parser->mode != CPARSER_MODE_CONFIG) {
        return CPARSER_OK;
    } else {       
        APR_RING_FOREACH_SAFE(ring_tmp, ring_tmp_n, &sec_policy_ring, security_policy_s, ring) {
            if (strncmp(ring_tmp->name, temp, NAME_LEN_MAX) == 0) {
                if (option_ptr != NULL) {
                    sec_policy_get_action_log_option(&(ring_tmp->server_subply), action_ptr, option_ptr, buf); 
                } else {
                    sec_policy_get_action_log(&(ring_tmp->server_subply), action_ptr, buf);
                    (ring_tmp->server_subply).status = ENABLE;
                }
                
                (ring_tmp->server_subply).flag = 1;
                
                rv = convert_sec_subpolicy_set((sec_subpolicy_t*)&(ring_tmp->server_subply));
                if (rv != APR_SUCCESS) {
                    cli_printf_info(context, "server-error-information-protect set failure\n");
                    return CPARSER_NOT_OK;
                }

                admin_log_process(context, buf);
                break;
            }
        }
    }
    
    return CPARSER_OK;

}

/* 下面四个接口用来配置program_code防护 */
cparser_result_t cparser_cmd_scp_program_code_protect(cparser_context_t *context)
{
    security_policy_t *ring_tmp, *ring_tmp_n;
    int rv;
    char *temp;
    char buf[COMMAND_LEN_MAX];

    transfer_security_policy_name(context);
    temp = (char *)context->cookie[context->parser->root_level];

    if (context->parser->mode != CPARSER_MODE_CONFIG) {
        return CPARSER_OK;
    } else {
        APR_RING_FOREACH_SAFE(ring_tmp, ring_tmp_n, &sec_policy_ring, security_policy_s, ring) {
            if (strncmp(ring_tmp->name, temp, NAME_LEN_MAX) == 0) {
                (ring_tmp->program_subply).flag = 1;
                (ring_tmp->program_subply).status = ENABLE;
                (ring_tmp->program_subply).action = ACTION_PASS;
                (ring_tmp->program_subply).log = 0;
                
                rv = convert_sec_subpolicy_set((sec_subpolicy_t*)&(ring_tmp->program_subply));
                if (rv != APR_SUCCESS) {
                    cli_printf_info(context, "program-code-protect set failure\n");
                    return CPARSER_NOT_OK;
                }

                sprintf(buf, "program-code-protect");
                admin_log_process(context, buf);
                break;
            }
        }
    }
    
    return CPARSER_OK;
}

cparser_result_t cparser_cmd_scp_program_code_protect_action_action_option(cparser_context_t *context,
    char **action_ptr,
    char **option_ptr)
{
    security_policy_t *ring_tmp, *ring_tmp_n;
    int rv;
    char *temp;
    char buf[COMMAND_LEN_MAX];
    
    transfer_security_policy_name(context);
    temp = (char *)context->cookie[context->parser->root_level];
    
    if (context == NULL) {
        return CPARSER_NOT_OK;
    }
    
    if (context->parser->mode != CPARSER_MODE_CONFIG) {
        return CPARSER_OK;
    } else {
        if (action_ptr == NULL || *action_ptr == NULL) {
            return CPARSER_NOT_OK;
        }

        APR_RING_FOREACH_SAFE(ring_tmp, ring_tmp_n, &sec_policy_ring, security_policy_s, ring) {
            if (strncmp(ring_tmp->name, temp, NAME_LEN_MAX) == 0) {
                if (option_ptr != NULL) {
                    sec_policy_get_action_option(&(ring_tmp->program_subply), action_ptr, option_ptr, buf); 
                } else {
                    sec_policy_get_action(&(ring_tmp->program_subply), action_ptr, buf);
                    (ring_tmp->program_subply).status = ENABLE;
                }
                
                (ring_tmp->program_subply).flag = 1;
                (ring_tmp->program_subply).log = 0;
                
                rv = convert_sec_subpolicy_set((sec_subpolicy_t*)&(ring_tmp->program_subply));
                if (rv != APR_SUCCESS) {
                    cli_printf_info(context, "program-code-protect set failure\n");
                    return CPARSER_NOT_OK;
                }

                admin_log_process(context, buf);
                break;
            }
        }
    }
    
    return CPARSER_OK;
}

cparser_result_t cparser_cmd_scp_program_code_protect_action_action_log_option(cparser_context_t *context,
    char **action_ptr,
    char **option_ptr)
{
    security_policy_t *ring_tmp, *ring_tmp_n;
    int rv;
    char *temp;
    char buf[COMMAND_LEN_MAX];

    transfer_security_policy_name(context);
    temp = (char *)context->cookie[context->parser->root_level];

    if (context == NULL) {
        return CPARSER_NOT_OK; 
    }
    
    if (context->parser->mode != CPARSER_MODE_CONFIG) {
        return CPARSER_OK;
    } else {       
        APR_RING_FOREACH_SAFE(ring_tmp, ring_tmp_n, &sec_policy_ring, security_policy_s, ring) {
            if (strncmp(ring_tmp->name, temp, NAME_LEN_MAX) == 0) {
                if (option_ptr != NULL) {
                    sec_policy_get_action_log_option(&(ring_tmp->program_subply), action_ptr, option_ptr, buf); 
                } else {
                    sec_policy_get_action_log(&(ring_tmp->program_subply), action_ptr, buf);
                    (ring_tmp->program_subply).status = ENABLE;
                }
                
                (ring_tmp->program_subply).flag = 1;
                
                rv = convert_sec_subpolicy_set((sec_subpolicy_t*)&(ring_tmp->program_subply));
                if (rv != APR_SUCCESS) {
                    cli_printf_info(context, "program-code-protect set failure\n");
                    return CPARSER_NOT_OK;
                }

                admin_log_process(context, buf);
                break;
            }
        }
    }
    
    return CPARSER_OK;
}

cparser_result_t cparser_cmd_scp_program_code_protect_option(cparser_context_t *context,
    char **option_ptr)
{
    security_policy_t *ring_tmp, *ring_tmp_n;
    int rv;
    char *temp;
    char buf[COMMAND_LEN_MAX];

    transfer_security_policy_name(context);
    temp = (char *)context->cookie[context->parser->root_level];
    
    if (context == NULL) {
        return CPARSER_NOT_OK;
    }
    
    if (context->parser->mode != CPARSER_MODE_CONFIG) {        
        APR_RING_FOREACH_SAFE(ring_tmp, ring_tmp_n, &sec_policy_ring, security_policy_s, ring) {
            if (strncmp(ring_tmp->name, temp, NAME_LEN_MAX) == 0) {
                cmd_c2p_program(context, &(ring_tmp->program_subply));
                break;
            }
        }
    } else { 
        if (option_ptr == NULL || *option_ptr == NULL) {
            return CPARSER_NOT_OK;
        }
        
        APR_RING_FOREACH_SAFE(ring_tmp, ring_tmp_n, &sec_policy_ring, security_policy_s, ring) {
            if (strncmp(ring_tmp->name, temp, NAME_LEN_MAX) == 0) {
                sec_policy_get_option(&(ring_tmp->program_subply), option_ptr, buf);
                (ring_tmp->program_subply).action = ACTION_PASS;
                (ring_tmp->program_subply).log = 0;
                (ring_tmp->program_subply).flag = 1;
                
                rv = convert_sec_subpolicy_set((sec_subpolicy_t*)&(ring_tmp->program_subply));
                if (rv != APR_SUCCESS) {
                    cli_printf_info(context, "program-code-protect set failure\n");
                    return CPARSER_NOT_OK;
                }

                admin_log_process(context, buf);
                break;
            }
        }
    }
    
    return CPARSER_OK;

}

/* 下面四个接口用来配置magcard_information防护 */
cparser_result_t cparser_cmd_scp_magcard_information_protect(cparser_context_t *context)
{
    security_policy_t *ring_tmp, *ring_tmp_n;
    int rv;
    char *temp;
    char buf[COMMAND_LEN_MAX];

    transfer_security_policy_name(context);
    temp = (char *)context->cookie[context->parser->root_level];

    if (context->parser->mode != CPARSER_MODE_CONFIG) {
        return CPARSER_OK;
    } else {
        APR_RING_FOREACH_SAFE(ring_tmp, ring_tmp_n, &sec_policy_ring, security_policy_s, ring) {
            if (strncmp(ring_tmp->name, temp, NAME_LEN_MAX) == 0) {
                (ring_tmp->magcard_subply).flag = 1;
                (ring_tmp->magcard_subply).status = ENABLE;
                (ring_tmp->magcard_subply).action = ACTION_PASS;
                (ring_tmp->magcard_subply).log = 0;
                
                rv = convert_sec_subpolicy_set((sec_subpolicy_t*)&(ring_tmp->magcard_subply));
                if (rv != APR_SUCCESS) {
                    cli_printf_info(context, "magcard-information-protect set failure\n");
                    return CPARSER_NOT_OK;
                }

                sprintf(buf, "magcard-information-protect");
                admin_log_process(context, buf);
                break;
            }
        }
    }
    
    return CPARSER_OK;
}

cparser_result_t cparser_cmd_scp_magcard_information_protect_action_action_option(cparser_context_t *context,
    char **action_ptr,
    char **option_ptr)
{
    security_policy_t *ring_tmp, *ring_tmp_n;
    int rv;
    char *temp;
    char buf[COMMAND_LEN_MAX];
    
    transfer_security_policy_name(context);
    temp = (char *)context->cookie[context->parser->root_level];
    
    if (context == NULL) {
        return CPARSER_NOT_OK;
    }
    
    if (context->parser->mode != CPARSER_MODE_CONFIG) {
        return CPARSER_OK;
    } else {
        if (action_ptr == NULL || *action_ptr == NULL) {
            return CPARSER_NOT_OK;
        }

        APR_RING_FOREACH_SAFE(ring_tmp, ring_tmp_n, &sec_policy_ring, security_policy_s, ring) {
            if (strncmp(ring_tmp->name, temp, NAME_LEN_MAX) == 0) {
                if (option_ptr != NULL) {
                    sec_policy_get_action_option(&(ring_tmp->magcard_subply), action_ptr, option_ptr, buf); 
                } else {
                    sec_policy_get_action(&(ring_tmp->magcard_subply), action_ptr, buf);
                    (ring_tmp->magcard_subply).status = ENABLE;
                }
                
                (ring_tmp->magcard_subply).flag = 1;
                (ring_tmp->magcard_subply).log = 0;
                
                rv = convert_sec_subpolicy_set((sec_subpolicy_t*)&(ring_tmp->magcard_subply));
                if (rv != APR_SUCCESS) {
                    cli_printf_info(context, "magcard-information-protect set failure\n");
                    return CPARSER_NOT_OK;
                }

                admin_log_process(context, buf);
                break;
            }
        }
    }
    
    return CPARSER_OK;
}

cparser_result_t cparser_cmd_scp_magcard_information_protect_action_action_log_option(cparser_context_t *context,
    char **action_ptr,
    char **option_ptr)
{
    security_policy_t *ring_tmp, *ring_tmp_n;
    int rv;
    char *temp;
    char buf[COMMAND_LEN_MAX];

    transfer_security_policy_name(context);
    temp = (char *)context->cookie[context->parser->root_level];

    if (context == NULL) {
        return CPARSER_NOT_OK; 
    }
    
    if (context->parser->mode != CPARSER_MODE_CONFIG) {
        return CPARSER_OK;
    } else {       
        APR_RING_FOREACH_SAFE(ring_tmp, ring_tmp_n, &sec_policy_ring, security_policy_s, ring) {
            if (strncmp(ring_tmp->name, temp, NAME_LEN_MAX) == 0) {
                if (option_ptr != NULL) {
                    sec_policy_get_action_log_option(&(ring_tmp->magcard_subply), action_ptr, option_ptr, buf); 
                } else {
                    sec_policy_get_action_log(&(ring_tmp->magcard_subply), action_ptr, buf);
                    (ring_tmp->magcard_subply).status = ENABLE;
                }
                
                (ring_tmp->magcard_subply).flag = 1;
                
                rv = convert_sec_subpolicy_set((sec_subpolicy_t*)&(ring_tmp->magcard_subply));
                if (rv != APR_SUCCESS) {
                    cli_printf_info(context, "magcard-information-protect set failure\n");
                    return CPARSER_NOT_OK;
                }

                admin_log_process(context, buf);
                break;
            }
        }
    }
    
    return CPARSER_OK;
}

cparser_result_t cparser_cmd_scp_magcard_information_protect_option(cparser_context_t *context,
    char **option_ptr)
{
    security_policy_t *ring_tmp, *ring_tmp_n;
    int rv;
    char *temp;
    char buf[COMMAND_LEN_MAX];

    transfer_security_policy_name(context);
    temp = (char *)context->cookie[context->parser->root_level];
    
    if (context == NULL) {
        return CPARSER_NOT_OK;
    }
    
    if (context->parser->mode != CPARSER_MODE_CONFIG) {        
        APR_RING_FOREACH_SAFE(ring_tmp, ring_tmp_n, &sec_policy_ring, security_policy_s, ring) {
            if (strncmp(ring_tmp->name, temp, NAME_LEN_MAX) == 0) {
                cmd_c2p_magcard(context, &(ring_tmp->magcard_subply));
                break;
            }
        }
    } else { 
        if (option_ptr == NULL || *option_ptr == NULL) {
            return CPARSER_NOT_OK;
        }
        
        APR_RING_FOREACH_SAFE(ring_tmp, ring_tmp_n, &sec_policy_ring, security_policy_s, ring) {
            if (strncmp(ring_tmp->name, temp, NAME_LEN_MAX) == 0) {
                sec_policy_get_option(&(ring_tmp->magcard_subply), option_ptr, buf);
                (ring_tmp->magcard_subply).action = ACTION_PASS;
                (ring_tmp->magcard_subply).log = 0;
                (ring_tmp->magcard_subply).flag = 1;
                
                rv = convert_sec_subpolicy_set((sec_subpolicy_t*)&(ring_tmp->magcard_subply));
                if (rv != APR_SUCCESS) {
                    cli_printf_info(context, "magcard-information-protect set failure\n");
                    return CPARSER_NOT_OK;
                }

                admin_log_process(context, buf);
                break;
            }
        }
    }
    
    return CPARSER_OK;
}

/* 下面三个接口用来配置server_version防护 */
cparser_result_t cparser_cmd_scp_server_version_protect(cparser_context_t *context)
{
    char prompt[CPARSER_MAX_PROMPT];
    security_policy_t *ring_tmp, *ring_tmp_n;
    int rv;
    char *temp;
    char buf[COMMAND_LEN_MAX];

    transfer_security_policy_name(context);
    temp = (char *)context->cookie[context->parser->root_level];

    if (context->parser->mode != CPARSER_MODE_CONFIG) {
        return CPARSER_OK;
    } else {
        APR_RING_FOREACH_SAFE(ring_tmp, ring_tmp_n, &sec_policy_ring, security_policy_s, ring) {
            if (strncmp(ring_tmp->name, temp, NAME_LEN_MAX) == 0) {
                (ring_tmp->version_subply).flag = 1;
                (ring_tmp->version_subply).status = ENABLE;
                (ring_tmp->version_subply).log = 0;
                
                rv = convert_sec_subpolicy_set((sec_subpolicy_t*)&(ring_tmp->version_subply));
                if (rv != APR_SUCCESS) {
                    cli_printf_info(context, "server-version-protect set failure\n");
                    return CPARSER_NOT_OK;
                }

                sprintf(buf, "server-version-protect");
                admin_log_process(context, buf);
                break;
            }
        }

        context->parser->cur_node = &cparser_node_pe_protect_engine_security_policy_secpname_root_server_version_protect_option_eol;
        snprintf(prompt, CPARSER_MAX_PROMPT, "%s(server-version)#", g_cli_prompt);
        return cparser_submode_enter(context->parser, temp, prompt);
    }
}

cparser_result_t cparser_cmd_scp_server_version_protect_log_option(cparser_context_t *context,
    char **option_ptr)
{
    char prompt[CPARSER_MAX_PROMPT];
    security_policy_t *ring_tmp, *ring_tmp_n;
    int rv;
    char *temp;
    char buf[COMMAND_LEN_MAX];

    transfer_security_policy_name(context);
    temp = (char *)context->cookie[context->parser->root_level];

    if (context == NULL) {
        return CPARSER_NOT_OK; 
    }
    
    if (context->parser->mode != CPARSER_MODE_CONFIG) {
        return CPARSER_OK;
    } else {       
        APR_RING_FOREACH_SAFE(ring_tmp, ring_tmp_n, &sec_policy_ring, security_policy_s, ring) {
            if (strncmp(ring_tmp->name, temp, NAME_LEN_MAX) == 0) {
                if (option_ptr != NULL) {
                    sec_policy_get_log_option(&(ring_tmp->version_subply), option_ptr, buf); 
                } else {
                    (ring_tmp->version_subply).status = ENABLE;
                    (ring_tmp->version_subply).log = 1;
                    sprintf(buf, "server-version-protect log");
                }
                
                (ring_tmp->version_subply).flag = 1;
                
                rv = convert_sec_subpolicy_set((sec_subpolicy_t*)&(ring_tmp->version_subply));
                if (rv != APR_SUCCESS) {
                    cli_printf_info(context, "server-version-protect set failure\n");
                    return CPARSER_NOT_OK;
                }

                admin_log_process(context, buf);
                break;
            }
        }

        context->parser->cur_node = &cparser_node_pe_protect_engine_security_policy_secpname_root_server_version_protect_option_eol;
        snprintf(prompt, CPARSER_MAX_PROMPT, "%s(server-version)#", g_cli_prompt);
        return cparser_submode_enter(context->parser, temp, prompt);
    }
}

cparser_result_t cparser_cmd_scp_server_version_protect_option(cparser_context_t *context,
    char **option_ptr)
{
    char prompt[CPARSER_MAX_PROMPT];
    security_policy_t *ring_tmp, *ring_tmp_n;
    int rv;
    char *temp;
    char buf[COMMAND_LEN_MAX];

    transfer_security_policy_name(context);
    temp = (char *)context->cookie[context->parser->root_level];
    
    if (context == NULL) {
        return CPARSER_NOT_OK;
    }
    
    if (context->parser->mode != CPARSER_MODE_CONFIG) {        
        APR_RING_FOREACH_SAFE(ring_tmp, ring_tmp_n, &sec_policy_ring, security_policy_s, ring) {
            if (strncmp(ring_tmp->name, temp, NAME_LEN_MAX) == 0) {
                cmd_c2p_server_version(context, &(ring_tmp->version_subply));
                break;
            }
        }

        return CPARSER_OK;
    } else { 
        if (option_ptr == NULL || *option_ptr == NULL) {
            return CPARSER_NOT_OK;
        }
        
        APR_RING_FOREACH_SAFE(ring_tmp, ring_tmp_n, &sec_policy_ring, security_policy_s, ring) {
            if (strncmp(ring_tmp->name, temp, NAME_LEN_MAX) == 0) {
                sec_policy_get_option(&(ring_tmp->version_subply), option_ptr, buf);
                (ring_tmp->version_subply).log = 0;
                (ring_tmp->version_subply).flag = 1;
                
                rv = convert_sec_subpolicy_set((sec_subpolicy_t*)&(ring_tmp->version_subply));
                if (rv != APR_SUCCESS) {
                    cli_printf_info(context, "server-version-protect set failure\n");
                    return CPARSER_NOT_OK;
                }

                admin_log_process(context, buf);
                break;
            }
        }
        
        snprintf(prompt, CPARSER_MAX_PROMPT, "%s(server-version)#", g_cli_prompt);
        return cparser_submode_enter(context->parser, temp, prompt);
    }
}

/* 下面三个接口用来配置creditcard_information防护 */
cparser_result_t cparser_cmd_scp_creditcard_information_protect(cparser_context_t *context)
{
    char prompt[CPARSER_MAX_PROMPT];
    security_policy_t *ring_tmp, *ring_tmp_n;
    int rv;
    char *temp;
    char buf[COMMAND_LEN_MAX];

    transfer_security_policy_name(context);
    temp = (char *)context->cookie[context->parser->root_level];

    if (context->parser->mode != CPARSER_MODE_CONFIG) {
        return CPARSER_OK;
    } else {
        APR_RING_FOREACH_SAFE(ring_tmp, ring_tmp_n, &sec_policy_ring, security_policy_s, ring) {
            if (strncmp(ring_tmp->name, temp, NAME_LEN_MAX) == 0) {
                (ring_tmp->iccard_subply).flag = 1;
                (ring_tmp->iccard_subply).status = ENABLE;
                (ring_tmp->iccard_subply).log = 0;
                
                rv = convert_sec_subpolicy_set((sec_subpolicy_t*)&(ring_tmp->iccard_subply));
                if (rv != APR_SUCCESS) {
                    cli_printf_info(context, "creditcard-information-protect set failure\n");
                    return CPARSER_NOT_OK;
                }

                sprintf(buf, "creditcard-information-protect");
                admin_log_process(context, buf);
                break;
            }
        }

        context->parser->cur_node = &cparser_node_pe_protect_engine_security_policy_secpname_root_creditcard_information_protect_option_eol;
        snprintf(prompt, CPARSER_MAX_PROMPT, "%s(creditcard)#", g_cli_prompt);
        return cparser_submode_enter(context->parser, temp, prompt);
    }
}

cparser_result_t cparser_cmd_scp_creditcard_information_protect_log_option(cparser_context_t *context,
    char **option_ptr)
{
    char prompt[CPARSER_MAX_PROMPT];
    security_policy_t *ring_tmp, *ring_tmp_n;
    int rv;
    char *temp;
    char buf[COMMAND_LEN_MAX];

    transfer_security_policy_name(context);
    temp = (char *)context->cookie[context->parser->root_level];

    if (context == NULL) {
        return CPARSER_NOT_OK; 
    }
    
    if (context->parser->mode != CPARSER_MODE_CONFIG) {
        return CPARSER_OK;
    } else {       
        APR_RING_FOREACH_SAFE(ring_tmp, ring_tmp_n, &sec_policy_ring, security_policy_s, ring) {
            if (strncmp(ring_tmp->name, temp, NAME_LEN_MAX) == 0) {
                if (option_ptr != NULL) {
                    sec_policy_get_log_option(&(ring_tmp->iccard_subply), option_ptr, buf); 
                } else {
                    (ring_tmp->iccard_subply).status = ENABLE;
                    (ring_tmp->iccard_subply).log = 1;
                    sprintf(buf, "creditcard-information-protect log");
                }
                
                (ring_tmp->iccard_subply).flag = 1;
                
                rv = convert_sec_subpolicy_set((sec_subpolicy_t*)&(ring_tmp->iccard_subply));
                if (rv != APR_SUCCESS) {
                    cli_printf_info(context, "creditcard-information-protect set failure\n");
                    return CPARSER_NOT_OK;
                }

                admin_log_process(context, buf);
                break;
            }
        }

        context->parser->cur_node = &cparser_node_pe_protect_engine_security_policy_secpname_root_creditcard_information_protect_option_eol;
        snprintf(prompt, CPARSER_MAX_PROMPT, "%s(creditcard)#", g_cli_prompt);
        return cparser_submode_enter(context->parser, temp, prompt);
    }
}

cparser_result_t cparser_cmd_scp_creditcard_information_protect_option(cparser_context_t *context,
    char **option_ptr)
{
    char prompt[CPARSER_MAX_PROMPT];
    security_policy_t *ring_tmp, *ring_tmp_n;
    int rv;
    char *temp;
    char buf[COMMAND_LEN_MAX];

    transfer_security_policy_name(context);
    temp = (char *)context->cookie[context->parser->root_level];
    
    if (context == NULL) {
        return CPARSER_NOT_OK;
    }
    
    if (context->parser->mode != CPARSER_MODE_CONFIG) {        
        APR_RING_FOREACH_SAFE(ring_tmp, ring_tmp_n, &sec_policy_ring, security_policy_s, ring) {
            if (strncmp(ring_tmp->name, temp, NAME_LEN_MAX) == 0) {
                cmd_c2p_iccard(context, &(ring_tmp->iccard_subply));
                break;
            }
        }
        
        return CPARSER_OK;
    } else { 
        if (option_ptr == NULL || *option_ptr == NULL) {
            return CPARSER_NOT_OK;
        }
        
        APR_RING_FOREACH_SAFE(ring_tmp, ring_tmp_n, &sec_policy_ring, security_policy_s, ring) {
            if (strncmp(ring_tmp->name, temp, NAME_LEN_MAX) == 0) {
                sec_policy_get_option(&(ring_tmp->iccard_subply), option_ptr, buf);
                (ring_tmp->iccard_subply).log = 0;
                (ring_tmp->iccard_subply).flag = 1;
                
                rv = convert_sec_subpolicy_set((sec_subpolicy_t*)&(ring_tmp->iccard_subply));
                if (rv != APR_SUCCESS) {
                    cli_printf_info(context, "creditcard-information-protect set failure\n");
                    return CPARSER_NOT_OK;
                }

                admin_log_process(context, buf);
                break;
            }
        }

        snprintf(prompt, CPARSER_MAX_PROMPT, "%s(creditcard)#", g_cli_prompt);
        return cparser_submode_enter(context->parser, temp, prompt);
    }
}

/* 下面三个接口用来配置idcard_information防护 */
cparser_result_t cparser_cmd_scp_idcard_information_protect(cparser_context_t *context)
{
    char prompt[CPARSER_MAX_PROMPT];
    security_policy_t *ring_tmp, *ring_tmp_n;
    int rv;
    char *temp;
    char buf[COMMAND_LEN_MAX];

    transfer_security_policy_name(context);
    temp = (char *)context->cookie[context->parser->root_level];

    if (context->parser->mode != CPARSER_MODE_CONFIG) {
        return CPARSER_OK;
    } else {
        APR_RING_FOREACH_SAFE(ring_tmp, ring_tmp_n, &sec_policy_ring, security_policy_s, ring) {
            if (strncmp(ring_tmp->name, temp, NAME_LEN_MAX) == 0) {
                (ring_tmp->idcard_subply).flag = 1;
                (ring_tmp->idcard_subply).status = ENABLE;
                (ring_tmp->idcard_subply).log = 0;
                
                rv = convert_sec_subpolicy_set((sec_subpolicy_t*)&(ring_tmp->idcard_subply));
                if (rv != APR_SUCCESS) {
                    cli_printf_info(context, "idcard-information-protect set failure\n");
                    return CPARSER_NOT_OK;
                }

                sprintf(buf, "idcard-information-protect");
                admin_log_process(context, buf);
                break;
            }
        }

        context->parser->cur_node = &cparser_node_pe_protect_engine_security_policy_secpname_root_idcard_information_protect_option_eol;
        snprintf(prompt, CPARSER_MAX_PROMPT, "%s(idcard)#", g_cli_prompt);
        return cparser_submode_enter(context->parser, temp, prompt);
    }
}

cparser_result_t cparser_cmd_scp_idcard_information_protect_log_option(cparser_context_t *context,
    char **option_ptr)
{
    char prompt[CPARSER_MAX_PROMPT];
    security_policy_t *ring_tmp, *ring_tmp_n;
    int rv;
    char *temp;
    char buf[COMMAND_LEN_MAX];

    transfer_security_policy_name(context);
    temp = (char *)context->cookie[context->parser->root_level];

    if (context == NULL) {
        return CPARSER_NOT_OK; 
    }
    
    if (context->parser->mode != CPARSER_MODE_CONFIG) {
        return CPARSER_OK;
    } else {       
        APR_RING_FOREACH_SAFE(ring_tmp, ring_tmp_n, &sec_policy_ring, security_policy_s, ring) {
            if (strncmp(ring_tmp->name, temp, NAME_LEN_MAX) == 0) {
                if (option_ptr != NULL) {
                    sec_policy_get_log_option(&(ring_tmp->idcard_subply), option_ptr, buf); 
                } else {
                    (ring_tmp->idcard_subply).status = ENABLE;
                    (ring_tmp->idcard_subply).log = 1;
                    sprintf(buf, "idcard-information-protect log");
                }
                
                (ring_tmp->idcard_subply).flag = 1;
                
                rv = convert_sec_subpolicy_set((sec_subpolicy_t*)&(ring_tmp->idcard_subply));
                if (rv != APR_SUCCESS) {
                    cli_printf_info(context, "idcard-information-protect set failure\n");
                    return CPARSER_NOT_OK;
                }

                admin_log_process(context, buf);
                break;
            }
        }

        context->parser->cur_node = &cparser_node_pe_protect_engine_security_policy_secpname_root_idcard_information_protect_option_eol;
        snprintf(prompt, CPARSER_MAX_PROMPT, "%s(idcard)#", g_cli_prompt);
        return cparser_submode_enter(context->parser, temp, prompt);
    }
}

cparser_result_t cparser_cmd_scp_idcard_information_protect_option(cparser_context_t *context,
    char **option_ptr)
{
    char prompt[CPARSER_MAX_PROMPT];
    security_policy_t *ring_tmp, *ring_tmp_n;
    int rv;
    char *temp;
    char buf[COMMAND_LEN_MAX];

    transfer_security_policy_name(context);
    temp = (char *)context->cookie[context->parser->root_level];
    
    if (context == NULL) {
        return CPARSER_NOT_OK;
    }
    
    if (context->parser->mode != CPARSER_MODE_CONFIG) {        
        APR_RING_FOREACH_SAFE(ring_tmp, ring_tmp_n, &sec_policy_ring, security_policy_s, ring) {
            if (strncmp(ring_tmp->name, temp, NAME_LEN_MAX) == 0) {
                cmd_c2p_idcard(context, &(ring_tmp->idcard_subply));
                break;
            }
        }

        return CPARSER_OK;
    } else { 
        if (option_ptr == NULL || *option_ptr == NULL) {
            return CPARSER_NOT_OK;
        }
        
        APR_RING_FOREACH_SAFE(ring_tmp, ring_tmp_n, &sec_policy_ring, security_policy_s, ring) {
            if (strncmp(ring_tmp->name, temp, NAME_LEN_MAX) == 0) {
                sec_policy_get_option(&(ring_tmp->idcard_subply), option_ptr, buf);
                (ring_tmp->idcard_subply).log = 0;
                (ring_tmp->idcard_subply).flag = 1;
                
                rv = convert_sec_subpolicy_set((sec_subpolicy_t*)&(ring_tmp->idcard_subply));
                if (rv != APR_SUCCESS) {
                    cli_printf_info(context, "idcard-information-protect set failure\n");
                    return CPARSER_NOT_OK;
                }

                admin_log_process(context, buf);
                break;
            }
        }

        snprintf(prompt, CPARSER_MAX_PROMPT, "%s(idcard)#", g_cli_prompt);
        return cparser_submode_enter(context->parser, temp, prompt);
    }
}

/* 下面四个接口用来配置file_download防护 */
cparser_result_t cparser_cmd_scp_file_download_protect(cparser_context_t *context)
{
    char prompt[CPARSER_MAX_PROMPT];
    security_policy_t *ring_tmp, *ring_tmp_n;
    int rv;
    char *temp;
    char buf[COMMAND_LEN_MAX];

    transfer_security_policy_name(context);
    temp = (char *)context->cookie[context->parser->root_level];

    if (context == NULL) {
        return CPARSER_NOT_OK;
    }

    if (context->parser->mode != CPARSER_MODE_CONFIG) {
        return CPARSER_OK;
    } else {
        APR_RING_FOREACH_SAFE(ring_tmp, ring_tmp_n, &sec_policy_ring, security_policy_s, ring) {
            if (strncmp(ring_tmp->name, temp, NAME_LEN_MAX) == 0) {
                (ring_tmp->filedown_subply).flag = 1;
                (ring_tmp->filedown_subply).status = ENABLE;
                (ring_tmp->filedown_subply).action = ACTION_PASS;
                (ring_tmp->filedown_subply).log = 0;
                
                rv = convert_sec_subpolicy_set((sec_subpolicy_t*)&(ring_tmp->filedown_subply));
                if (rv != APR_SUCCESS) {
                    cli_printf_info(context, "file-download-protect set failure\n");
                    return CPARSER_NOT_OK;
                }

                sprintf(buf, "file-download-protect");
                admin_log_process(context, buf);
                break;
            }
        }

        context->parser->cur_node = &cparser_node_pe_protect_engine_security_policy_secpname_root_file_download_protect_option_eol;
        snprintf(prompt, CPARSER_MAX_PROMPT, "%s(file-download)#", g_cli_prompt);
        return cparser_submode_enter(context->parser, temp, prompt);
    }
    
    return CPARSER_OK;
}

cparser_result_t cparser_cmd_scp_file_download_protect_action_action_option(cparser_context_t *context,
    char **action_ptr,
    char **option_ptr)
{
    char prompt[CPARSER_MAX_PROMPT];
    security_policy_t *ring_tmp, *ring_tmp_n;
    int rv;
    char *temp;
    char buf[COMMAND_LEN_MAX];

    transfer_security_policy_name(context);
    temp = (char *)context->cookie[context->parser->root_level];

    if (context == NULL) {
        return CPARSER_NOT_OK;
    }

    if (context->parser->mode != CPARSER_MODE_CONFIG) {
        return CPARSER_OK;
    } else {
        APR_RING_FOREACH_SAFE(ring_tmp, ring_tmp_n, &sec_policy_ring, security_policy_s, ring) {
            if (strncmp(ring_tmp->name, temp, NAME_LEN_MAX) == 0) {
                if (option_ptr != NULL) {
                    sec_policy_get_action_option(&(ring_tmp->filedown_subply), action_ptr, option_ptr, buf); 
                } else {
                    sec_policy_get_action(&(ring_tmp->filedown_subply), action_ptr, buf);
                    (ring_tmp->filedown_subply).status = ENABLE;
                }
                
                (ring_tmp->filedown_subply).flag = 1;
                (ring_tmp->filedown_subply).log = 0;
                
                rv = convert_sec_subpolicy_set((sec_subpolicy_t*)&(ring_tmp->filedown_subply));
                if (rv != APR_SUCCESS) {
                    cli_printf_info(context, "file-download-protect set failure\n");
                    return CPARSER_NOT_OK;
                }

                admin_log_process(context, buf);
                break;
            }
        }

        context->parser->cur_node = &cparser_node_pe_protect_engine_security_policy_secpname_root_file_download_protect_option_eol;
        snprintf(prompt, CPARSER_MAX_PROMPT, "%s(file-download)#", g_cli_prompt);
        return cparser_submode_enter(context->parser, temp, prompt);
    }
    
    return CPARSER_OK;
}

cparser_result_t cparser_cmd_scp_file_download_protect_action_action_log_option(cparser_context_t *context,
    char **action_ptr,
    char **option_ptr)
{
    char prompt[CPARSER_MAX_PROMPT];
    security_policy_t *ring_tmp, *ring_tmp_n;
    int rv;
    char *temp;
    char buf[COMMAND_LEN_MAX];

    transfer_security_policy_name(context);
    temp = (char *)context->cookie[context->parser->root_level];

    if (context == NULL) {
        return CPARSER_NOT_OK; 
    }
    
    if (context->parser->mode != CPARSER_MODE_CONFIG) {
        return CPARSER_OK;
    } else {       
        APR_RING_FOREACH_SAFE(ring_tmp, ring_tmp_n, &sec_policy_ring, security_policy_s, ring) {
            if (strncmp(ring_tmp->name, temp, NAME_LEN_MAX) == 0) {
                if (option_ptr != NULL) {
                    sec_policy_get_action_log_option(&(ring_tmp->filedown_subply), action_ptr, option_ptr, buf); 
                } else {
                    sec_policy_get_action_log(&(ring_tmp->filedown_subply), action_ptr, buf);
                    (ring_tmp->filedown_subply).status = ENABLE;
                }
                
                (ring_tmp->filedown_subply).flag = 1;
                
                rv = convert_sec_subpolicy_set((sec_subpolicy_t*)&(ring_tmp->filedown_subply));
                if (rv != APR_SUCCESS) {
                    cli_printf_info(context, "file-download-protect set failure\n");
                    return CPARSER_NOT_OK;
                }

                admin_log_process(context, buf);
                break;
            }
        }

        context->parser->cur_node = &cparser_node_pe_protect_engine_security_policy_secpname_root_file_download_protect_option_eol;
        snprintf(prompt, CPARSER_MAX_PROMPT, "%s(file-download)#", g_cli_prompt);
        return cparser_submode_enter(context->parser, temp, prompt);
    }
    
    return CPARSER_OK;
}

cparser_result_t cparser_cmd_scp_file_download_protect_option(cparser_context_t *context,
    char **option_ptr)
{
    char prompt[CPARSER_MAX_PROMPT];
    security_policy_t *ring_tmp, *ring_tmp_n;
    int rv;
    char *temp;
    char buf[COMMAND_LEN_MAX];

    transfer_security_policy_name(context);
    temp = (char *)context->cookie[context->parser->root_level];
    
    if (context == NULL) {
        return CPARSER_NOT_OK;
    }
    
    if (context->parser->mode != CPARSER_MODE_CONFIG) {        
        APR_RING_FOREACH_SAFE(ring_tmp, ring_tmp_n, &sec_policy_ring, security_policy_s, ring) {
            if (strncmp(ring_tmp->name, temp, NAME_LEN_MAX) == 0) {
                cmd_c2p_file_download(context, &(ring_tmp->filedown_subply));
                break;
            }
        }
    } else { 
        if (option_ptr == NULL || *option_ptr == NULL) {
            return CPARSER_NOT_OK;
        }
        
        APR_RING_FOREACH_SAFE(ring_tmp, ring_tmp_n, &sec_policy_ring, security_policy_s, ring) {
            if (strncmp(ring_tmp->name, temp, NAME_LEN_MAX) == 0) {
                sec_policy_get_option(&(ring_tmp->filedown_subply), option_ptr, buf);
                (ring_tmp->filedown_subply).action = ACTION_PASS;
                (ring_tmp->filedown_subply).log = 0;
                (ring_tmp->filedown_subply).flag = 1;
                
                rv = convert_sec_subpolicy_set((sec_subpolicy_t*)&(ring_tmp->filedown_subply));
                if (rv != APR_SUCCESS) {
                    cli_printf_info(context, "file-download-protect set failure\n");
                    return CPARSER_NOT_OK;
                }

                admin_log_process(context, buf);
                break;
            }
        }

        snprintf(prompt, CPARSER_MAX_PROMPT, "%s(file-download)#", g_cli_prompt);
        return cparser_submode_enter(context->parser, temp, prompt);
    }
    
    return CPARSER_OK; 
}

/* 下面四个接口用来配置file_upload防护 */
cparser_result_t cparser_cmd_scp_file_upload_protect(cparser_context_t *context)
{
    char prompt[CPARSER_MAX_PROMPT];
    security_policy_t *ring_tmp, *ring_tmp_n;
    int rv;
    char *temp;
    char buf[COMMAND_LEN_MAX];

    transfer_security_policy_name(context);
    temp = (char *)context->cookie[context->parser->root_level];

    if (context == NULL) {
        return CPARSER_NOT_OK;
    }

    if (context->parser->mode != CPARSER_MODE_CONFIG) {
        return CPARSER_OK;
    } else {
        APR_RING_FOREACH_SAFE(ring_tmp, ring_tmp_n, &sec_policy_ring, security_policy_s, ring) {
            if (strncmp(ring_tmp->name, temp, NAME_LEN_MAX) == 0) {
                (ring_tmp->fileup_subply).flag = 1;
                (ring_tmp->fileup_subply).status = ENABLE;
                (ring_tmp->fileup_subply).action = ACTION_PASS;
                (ring_tmp->fileup_subply).log = 0;
                
                rv = convert_sec_subpolicy_set((sec_subpolicy_t*)&(ring_tmp->fileup_subply));
                if (rv != APR_SUCCESS) {
                    cli_printf_info(context, "file-upload-protect set failure\n");
                    return CPARSER_NOT_OK;
                }

                sprintf(buf, "file-upload-protect");
                admin_log_process(context, buf);
                break;
            }
        }

        context->parser->cur_node = &cparser_node_pe_protect_engine_security_policy_secpname_root_file_upload_protect_option_eol;
        snprintf(prompt, CPARSER_MAX_PROMPT, "%s(file-upload)#", g_cli_prompt);
        return cparser_submode_enter(context->parser, temp, prompt);
    }
    
    return CPARSER_OK;
}

cparser_result_t cparser_cmd_scp_file_upload_protect_action_action_option(cparser_context_t *context,
    char **action_ptr,
    char **option_ptr)
{
    char prompt[CPARSER_MAX_PROMPT];
    security_policy_t *ring_tmp, *ring_tmp_n;
    int rv;
    char *temp;
    char buf[COMMAND_LEN_MAX];

    transfer_security_policy_name(context);
    temp = (char *)context->cookie[context->parser->root_level];

    if (context == NULL) {
        return CPARSER_NOT_OK;
    }

    if (context->parser->mode != CPARSER_MODE_CONFIG) {
        return CPARSER_OK;
    } else {
        APR_RING_FOREACH_SAFE(ring_tmp, ring_tmp_n, &sec_policy_ring, security_policy_s, ring) {
            if (strncmp(ring_tmp->name, temp, NAME_LEN_MAX) == 0) {
                if (option_ptr != NULL) {
                    sec_policy_get_action_option((generate_subpolicy_t*)&(ring_tmp->fileup_subply), action_ptr, option_ptr, buf); 
                } else {
                    sec_policy_get_action((generate_subpolicy_t*)&(ring_tmp->fileup_subply), action_ptr, buf);
                    (ring_tmp->fileup_subply).status = ENABLE;
                }
                
                (ring_tmp->fileup_subply).flag = 1;
                (ring_tmp->fileup_subply).log = 0;
                
                rv = convert_sec_subpolicy_set((sec_subpolicy_t*)&(ring_tmp->fileup_subply));
                if (rv != APR_SUCCESS) {
                    cli_printf_info(context, "file-upload-protect set failure\n");
                    return CPARSER_NOT_OK;
                }

                admin_log_process(context, buf);
                break;
            }
        }

        context->parser->cur_node = &cparser_node_pe_protect_engine_security_policy_secpname_root_file_upload_protect_option_eol;
        snprintf(prompt, CPARSER_MAX_PROMPT, "%s(file-upload)#", g_cli_prompt);
        return cparser_submode_enter(context->parser, temp, prompt);
    }
    
    return CPARSER_OK;
}

cparser_result_t cparser_cmd_scp_file_upload_protect_action_action_log_option(cparser_context_t *context,
    char **action_ptr,
    char **option_ptr)
{
    char prompt[CPARSER_MAX_PROMPT];
    security_policy_t *ring_tmp, *ring_tmp_n;
    int rv;
    char *temp;
    char buf[COMMAND_LEN_MAX];

    transfer_security_policy_name(context);
    temp = (char *)context->cookie[context->parser->root_level];

    if (context == NULL) {
        return CPARSER_NOT_OK; 
    }
    
    if (context->parser->mode != CPARSER_MODE_CONFIG) {
        return CPARSER_OK;
    } else {       
        APR_RING_FOREACH_SAFE(ring_tmp, ring_tmp_n, &sec_policy_ring, security_policy_s, ring) {
            if (strncmp(ring_tmp->name, temp, NAME_LEN_MAX) == 0) {
                if (option_ptr != NULL) {
                    sec_policy_get_action_log_option((generate_subpolicy_t*)&(ring_tmp->fileup_subply), action_ptr, option_ptr, buf); 
                } else {
                    sec_policy_get_action_log((generate_subpolicy_t*)&(ring_tmp->fileup_subply), action_ptr, buf);
                    (ring_tmp->fileup_subply).status = ENABLE;
                }
                
                (ring_tmp->fileup_subply).flag = 1;
                
                rv = convert_sec_subpolicy_set((sec_subpolicy_t*)&(ring_tmp->fileup_subply));
                if (rv != APR_SUCCESS) {
                    cli_printf_info(context, "file-upload-protect set failure\n");
                    return CPARSER_NOT_OK;
                }

                admin_log_process(context, buf);
                break;
            }
        }

        context->parser->cur_node = &cparser_node_pe_protect_engine_security_policy_secpname_root_file_upload_protect_option_eol;
        snprintf(prompt, CPARSER_MAX_PROMPT, "%s(file-upload)#", g_cli_prompt);
        return cparser_submode_enter(context->parser, temp, prompt);
    }
    
    return CPARSER_OK;
}

cparser_result_t cparser_cmd_scp_file_upload_protect_option(cparser_context_t *context,
    char **option_ptr)
{
    char prompt[CPARSER_MAX_PROMPT];
    security_policy_t *ring_tmp, *ring_tmp_n;
    int rv;
    char *temp;
    char buf[COMMAND_LEN_MAX];

    transfer_security_policy_name(context);
    temp = (char *)context->cookie[context->parser->root_level];
    
    if (context == NULL) {
        return CPARSER_NOT_OK;
    }
    
    if (context->parser->mode != CPARSER_MODE_CONFIG) {        
        APR_RING_FOREACH_SAFE(ring_tmp, ring_tmp_n, &sec_policy_ring, security_policy_s, ring) {
            if (strncmp(ring_tmp->name, temp, NAME_LEN_MAX) == 0) {
                cmd_c2p_file_upload(context, (generate_subpolicy_t*)&(ring_tmp->fileup_subply));
                break;
            }
        }
    } else { 
        if (option_ptr == NULL || *option_ptr == NULL) {
            return CPARSER_NOT_OK;
        }
        
        APR_RING_FOREACH_SAFE(ring_tmp, ring_tmp_n, &sec_policy_ring, security_policy_s, ring) {
            if (strncmp(ring_tmp->name, temp, NAME_LEN_MAX) == 0) {
                sec_policy_get_option((generate_subpolicy_t*)&(ring_tmp->fileup_subply), option_ptr, buf);
                (ring_tmp->fileup_subply).action = ACTION_PASS;
                (ring_tmp->fileup_subply).log = 0;
                (ring_tmp->fileup_subply).flag = 1;
                
                rv = convert_sec_subpolicy_set((sec_subpolicy_t*)&(ring_tmp->fileup_subply));
                if (rv != APR_SUCCESS) {
                    cli_printf_info(context, "file-upload-protect set failure\n");
                    return CPARSER_NOT_OK;
                }

                admin_log_process(context, buf);
                break;
            }
        }

        snprintf(prompt, CPARSER_MAX_PROMPT, "%s(file-upload)#", g_cli_prompt);
        return cparser_submode_enter(context->parser, temp, prompt);
    }
    
    return CPARSER_OK; 
}

/* 下面四个接口用来配置cookie防护 */
cparser_result_t cparser_cmd_scp_cookie_protect(cparser_context_t *context)
{
    char prompt[CPARSER_MAX_PROMPT];
    security_policy_t *ring_tmp, *ring_tmp_n;
    int rv;
    char *temp;
    char buf[COMMAND_LEN_MAX];

    transfer_security_policy_name(context);
    temp = (char *)context->cookie[context->parser->root_level];

    if (context == NULL) {
        return CPARSER_NOT_OK;
    }

    if (context->parser->mode != CPARSER_MODE_CONFIG) {
        return CPARSER_OK;
    } else {
        APR_RING_FOREACH_SAFE(ring_tmp, ring_tmp_n, &sec_policy_ring, security_policy_s, ring) {
            if (strncmp(ring_tmp->name, temp, NAME_LEN_MAX) == 0) {
                (ring_tmp->cookie_subply).flag = 1;
                (ring_tmp->cookie_subply).status = ENABLE;
                (ring_tmp->cookie_subply).action = ACTION_PASS;
                (ring_tmp->cookie_subply).log = 0;
                
                rv = convert_sec_subpolicy_set((sec_subpolicy_t*)&(ring_tmp->cookie_subply));
                if (rv != APR_SUCCESS) {
                    cli_printf_info(context, "cookie-protect set failure\n");
                    return CPARSER_NOT_OK;
                }

                sprintf(buf, "cookie-protect");
                admin_log_process(context, buf);
                break;
            }
        }

        context->parser->cur_node = &cparser_node_pe_protect_engine_security_policy_secpname_root_cookie_protect_option_eol;
        snprintf(prompt, CPARSER_MAX_PROMPT, "%s(cookie)#", g_cli_prompt);
        return cparser_submode_enter(context->parser, temp, prompt);
    }
    
    return CPARSER_OK;
}

cparser_result_t cparser_cmd_scp_cookie_protect_action_action_option(cparser_context_t *context,
    char **action_ptr,
    char **option_ptr)
{
    char prompt[CPARSER_MAX_PROMPT];
    security_policy_t *ring_tmp, *ring_tmp_n;
    int rv;
    char *temp;
    char buf[COMMAND_LEN_MAX];

    transfer_security_policy_name(context);
    temp = (char *)context->cookie[context->parser->root_level];

    if (context == NULL) {
        return CPARSER_NOT_OK;
    }

    if (context->parser->mode != CPARSER_MODE_CONFIG) {
        return CPARSER_OK;
    } else {
        APR_RING_FOREACH_SAFE(ring_tmp, ring_tmp_n, &sec_policy_ring, security_policy_s, ring) {
            if (strncmp(ring_tmp->name, temp, NAME_LEN_MAX) == 0) {
                if (option_ptr != NULL) {
                    sec_policy_get_action_option((generate_subpolicy_t*)&(ring_tmp->cookie_subply), action_ptr, option_ptr, buf); 
                } else {
                    sec_policy_get_action((generate_subpolicy_t*)&(ring_tmp->cookie_subply), action_ptr, buf);
                    (ring_tmp->cookie_subply).status = ENABLE;
                }
                
                (ring_tmp->cookie_subply).flag = 1;
                (ring_tmp->cookie_subply).log = 0;
                
                rv = convert_sec_subpolicy_set((sec_subpolicy_t*)&(ring_tmp->cookie_subply));
                if (rv != APR_SUCCESS) {
                    cli_printf_info(context, "cookie-protect set failure\n");
                    return CPARSER_NOT_OK;
                }

                admin_log_process(context, buf);
                break;
            }
        }

        context->parser->cur_node = &cparser_node_pe_protect_engine_security_policy_secpname_root_cookie_protect_option_eol;
        snprintf(prompt, CPARSER_MAX_PROMPT, "%s(cookie)#", g_cli_prompt);
        return cparser_submode_enter(context->parser, temp, prompt);
    }
    
    return CPARSER_OK;
}

cparser_result_t cparser_cmd_scp_cookie_protect_action_action_log_option(cparser_context_t *context,
    char **action_ptr,
    char **option_ptr)
{
    char prompt[CPARSER_MAX_PROMPT];
    security_policy_t *ring_tmp, *ring_tmp_n;
    int rv;
    char *temp;
    char buf[COMMAND_LEN_MAX];

    transfer_security_policy_name(context);
    temp = (char *)context->cookie[context->parser->root_level];

    if (context == NULL) {
        return CPARSER_NOT_OK; 
    }
    
    if (context->parser->mode != CPARSER_MODE_CONFIG) {
        return CPARSER_OK;
    } else {       
        APR_RING_FOREACH_SAFE(ring_tmp, ring_tmp_n, &sec_policy_ring, security_policy_s, ring) {
            if (strncmp(ring_tmp->name, temp, NAME_LEN_MAX) == 0) {
                if (option_ptr != NULL) {
                    sec_policy_get_action_log_option((generate_subpolicy_t*)&(ring_tmp->cookie_subply), action_ptr, option_ptr, buf); 
                } else {
                    sec_policy_get_action_log((generate_subpolicy_t*)&(ring_tmp->cookie_subply), action_ptr, buf);
                    (ring_tmp->cookie_subply).status = ENABLE;
                }
                
                (ring_tmp->cookie_subply).flag = 1;
                
                rv = convert_sec_subpolicy_set((sec_subpolicy_t*)&(ring_tmp->cookie_subply));
                if (rv != APR_SUCCESS) {
                    cli_printf_info(context, "cookie-protect set failure\n");
                    return CPARSER_NOT_OK;
                }

                admin_log_process(context, buf);
                break;
            }
        }

        context->parser->cur_node = &cparser_node_pe_protect_engine_security_policy_secpname_root_cookie_protect_option_eol;
        snprintf(prompt, CPARSER_MAX_PROMPT, "%s(cookie)#", g_cli_prompt);
        return cparser_submode_enter(context->parser, temp, prompt);
    }
    
    return CPARSER_OK;
}

cparser_result_t cparser_cmd_scp_cookie_protect_option(cparser_context_t *context,
    char **option_ptr)
{
    char prompt[CPARSER_MAX_PROMPT];
    security_policy_t *ring_tmp, *ring_tmp_n;
    int rv;
    char *temp;
    char buf[COMMAND_LEN_MAX];

    transfer_security_policy_name(context);
    temp = (char *)context->cookie[context->parser->root_level];
    
    if (context == NULL) {
        return CPARSER_NOT_OK;
    }
    
    if (context->parser->mode != CPARSER_MODE_CONFIG) {        
        APR_RING_FOREACH_SAFE(ring_tmp, ring_tmp_n, &sec_policy_ring, security_policy_s, ring) {
            if (strncmp(ring_tmp->name, temp, NAME_LEN_MAX) == 0) {
                cmd_c2p_cookie(context, (generate_subpolicy_t*)&(ring_tmp->cookie_subply));
                break;
            }
        }
    } else { 
        if (option_ptr == NULL || *option_ptr == NULL) {
            return CPARSER_NOT_OK;
        }
        
        APR_RING_FOREACH_SAFE(ring_tmp, ring_tmp_n, &sec_policy_ring, security_policy_s, ring) {
            if (strncmp(ring_tmp->name, temp, NAME_LEN_MAX) == 0) {
                sec_policy_get_option((generate_subpolicy_t*)&(ring_tmp->cookie_subply), option_ptr, buf);
                (ring_tmp->cookie_subply).action = ACTION_PASS;
                (ring_tmp->cookie_subply).log = 0;
                (ring_tmp->cookie_subply).flag = 1;
                
                rv = convert_sec_subpolicy_set((sec_subpolicy_t*)&(ring_tmp->cookie_subply));
                if (rv != APR_SUCCESS) {
                    cli_printf_info(context, "cookie-protect set failure\n");
                    return CPARSER_NOT_OK;
                }

                admin_log_process(context, buf);
                break;
            }
        }

        snprintf(prompt, CPARSER_MAX_PROMPT, "%s(cookie)#", g_cli_prompt);
        return cparser_submode_enter(context->parser, temp, prompt);
    }
    
    return CPARSER_OK; 
}

/* 下面四个接口用来配置协议参数防护 */
cparser_result_t cparser_cmd_scp_protocol_param_protect(cparser_context_t *context)
{
    char prompt[CPARSER_MAX_PROMPT];
    security_policy_t *ring_tmp, *ring_tmp_n;
    int rv;
    char *temp;
    char buf[COMMAND_LEN_MAX];

    transfer_security_policy_name(context);
    temp = (char *)context->cookie[context->parser->root_level];

    if (context == NULL) {
        return CPARSER_NOT_OK;
    }

    if (context->parser->mode != CPARSER_MODE_CONFIG) {
        return CPARSER_OK;
    } else {
        APR_RING_FOREACH_SAFE(ring_tmp, ring_tmp_n, &sec_policy_ring, security_policy_s, ring) {
            if (strncmp(ring_tmp->name, temp, NAME_LEN_MAX) == 0) {
                (ring_tmp->protocol_subply).flag = 1;
                (ring_tmp->protocol_subply).status = ENABLE;
                (ring_tmp->protocol_subply).action = ACTION_PASS;
                (ring_tmp->protocol_subply).log = 0;
                
                rv = convert_sec_subpolicy_set((sec_subpolicy_t*)&(ring_tmp->protocol_subply));
                if (rv != APR_SUCCESS) {
                    cli_printf_info(context, "protocol-param-protect set failure\n");
                    return CPARSER_NOT_OK;
                }

                sprintf(buf, "protocol-param-protect");
                admin_log_process(context, buf);
                break;
            }
        }

        context->parser->cur_node = &cparser_node_pe_protect_engine_security_policy_secpname_root_protocol_param_protect_option_eol;
        snprintf(prompt, CPARSER_MAX_PROMPT, "%s(protocol)#", g_cli_prompt);
        return cparser_submode_enter(context->parser, temp, prompt);
    }
    
    return CPARSER_OK;
}

cparser_result_t cparser_cmd_scp_protocol_param_protect_action_action_option(cparser_context_t *context,
    char **action_ptr,
    char **option_ptr)
{
    char prompt[CPARSER_MAX_PROMPT];
    security_policy_t *ring_tmp, *ring_tmp_n;
    int rv;
    char *temp;
    char buf[COMMAND_LEN_MAX];

    transfer_security_policy_name(context);
    temp = (char *)context->cookie[context->parser->root_level];

    if (context == NULL) {
        return CPARSER_NOT_OK;
    }

    if (context->parser->mode != CPARSER_MODE_CONFIG) {
        return CPARSER_OK;
    } else {
        APR_RING_FOREACH_SAFE(ring_tmp, ring_tmp_n, &sec_policy_ring, security_policy_s, ring) {
            if (strncmp(ring_tmp->name, temp, NAME_LEN_MAX) == 0) {
                if (option_ptr != NULL) {
                    sec_policy_get_action_option((generate_subpolicy_t*)&(ring_tmp->protocol_subply), action_ptr, option_ptr, buf); 
                } else {
                    sec_policy_get_action((generate_subpolicy_t*)&(ring_tmp->protocol_subply), action_ptr, buf);
                    (ring_tmp->protocol_subply).status = ENABLE;
                }
                
                (ring_tmp->protocol_subply).flag = 1;
                (ring_tmp->protocol_subply).log = 0;
                
                rv = convert_sec_subpolicy_set((sec_subpolicy_t*)&(ring_tmp->protocol_subply));
                if (rv != APR_SUCCESS) {
                    cli_printf_info(context, "protocol-param-protect set failure\n");
                    return CPARSER_NOT_OK;
                }

                admin_log_process(context, buf);
                break;
            }
        }

        context->parser->cur_node = &cparser_node_pe_protect_engine_security_policy_secpname_root_protocol_param_protect_option_eol;
        snprintf(prompt, CPARSER_MAX_PROMPT, "%s(protocol)#", g_cli_prompt);
        return cparser_submode_enter(context->parser, temp, prompt);
    }
    
    return CPARSER_OK;

}

cparser_result_t cparser_cmd_scp_protocol_param_protect_action_action_log_option(cparser_context_t *context,
    char **action_ptr,
    char **option_ptr)
{
    char prompt[CPARSER_MAX_PROMPT];
    security_policy_t *ring_tmp, *ring_tmp_n;
    int rv;
    char *temp;
    char buf[COMMAND_LEN_MAX];

    transfer_security_policy_name(context);
    temp = (char *)context->cookie[context->parser->root_level];

    if (context == NULL) {
        return CPARSER_NOT_OK; 
    }
    
    if (context->parser->mode != CPARSER_MODE_CONFIG) {
        return CPARSER_OK;
    } else {       
        APR_RING_FOREACH_SAFE(ring_tmp, ring_tmp_n, &sec_policy_ring, security_policy_s, ring) {
            if (strncmp(ring_tmp->name, temp, NAME_LEN_MAX) == 0) {
                if (option_ptr != NULL) {
                    sec_policy_get_action_log_option((generate_subpolicy_t*)&(ring_tmp->protocol_subply), action_ptr, option_ptr, buf); 
                } else {
                    sec_policy_get_action_log((generate_subpolicy_t*)&(ring_tmp->protocol_subply), action_ptr, buf);
                    (ring_tmp->protocol_subply).status = ENABLE;
                }
                
                (ring_tmp->protocol_subply).flag = 1;
                
                rv = convert_sec_subpolicy_set((sec_subpolicy_t*)&(ring_tmp->protocol_subply));
                if (rv != APR_SUCCESS) {
                    cli_printf_info(context, "protocol-param-protect set failure\n");
                    return CPARSER_NOT_OK;
                }

                admin_log_process(context, buf);
                break;
            }
        }

        context->parser->cur_node = &cparser_node_pe_protect_engine_security_policy_secpname_root_protocol_param_protect_option_eol;
        snprintf(prompt, CPARSER_MAX_PROMPT, "%s(protocol)#", g_cli_prompt);
        return cparser_submode_enter(context->parser, temp, prompt);
    }
    
    return CPARSER_OK;


}

cparser_result_t cparser_cmd_scp_protocol_param_protect_option(cparser_context_t *context,
    char **option_ptr)
{
    char prompt[CPARSER_MAX_PROMPT];
    security_policy_t *ring_tmp, *ring_tmp_n;
    int rv;
    char *temp;
    char buf[COMMAND_LEN_MAX];

    transfer_security_policy_name(context);
    temp = (char *)context->cookie[context->parser->root_level];
    
    if (context == NULL) {
        return CPARSER_NOT_OK;
    }
    
    if (context->parser->mode != CPARSER_MODE_CONFIG) {        
        APR_RING_FOREACH_SAFE(ring_tmp, ring_tmp_n, &sec_policy_ring, security_policy_s, ring) {
            if (strncmp(ring_tmp->name, temp, NAME_LEN_MAX) == 0) {
                cmd_c2p_protocol(context, (generate_subpolicy_t*)&(ring_tmp->protocol_subply));
                break;
            }
        }
    } else { 
        if (option_ptr == NULL || *option_ptr == NULL) {
            return CPARSER_NOT_OK;
        }
        
        APR_RING_FOREACH_SAFE(ring_tmp, ring_tmp_n, &sec_policy_ring, security_policy_s, ring) {
            if (strncmp(ring_tmp->name, temp, NAME_LEN_MAX) == 0) {
                sec_policy_get_option((generate_subpolicy_t*)&(ring_tmp->protocol_subply), option_ptr, buf);
                (ring_tmp->protocol_subply).action = ACTION_PASS;
                (ring_tmp->protocol_subply).log = 0;
                (ring_tmp->protocol_subply).flag = 1;
                
                rv = convert_sec_subpolicy_set((sec_subpolicy_t*)&(ring_tmp->protocol_subply));
                if (rv != APR_SUCCESS) {
                    cli_printf_info(context, "protocol-param-protect set failure\n");
                    return CPARSER_NOT_OK;
                }

                admin_log_process(context, buf);
                break;
            }
        }

        snprintf(prompt, CPARSER_MAX_PROMPT, "%s(protocol)#", g_cli_prompt);
        return cparser_submode_enter(context->parser, temp, prompt);
    }
    
    return CPARSER_OK; 

}

/* 下面四个接口用来配置请求方法防护 */
cparser_result_t cparser_cmd_scp_request_method_protect(cparser_context_t *context)
{
    char prompt[CPARSER_MAX_PROMPT];
    security_policy_t *ring_tmp, *ring_tmp_n;
    int rv;
    char *temp;
    char buf[COMMAND_LEN_MAX];

    transfer_security_policy_name(context);
    temp = (char *)context->cookie[context->parser->root_level];

    if (context == NULL) {
        return CPARSER_NOT_OK;
    }

    if (context->parser->mode != CPARSER_MODE_CONFIG) {
        return CPARSER_OK;
    } else {
        APR_RING_FOREACH_SAFE(ring_tmp, ring_tmp_n, &sec_policy_ring, security_policy_s, ring) {
            if (strncmp(ring_tmp->name, temp, NAME_LEN_MAX) == 0) {
                (ring_tmp->request_subply).flag = 1;
                (ring_tmp->request_subply).status = ENABLE;
                (ring_tmp->request_subply).action = ACTION_PASS;
                (ring_tmp->request_subply).log = 0;
                
                rv = convert_sec_subpolicy_set((sec_subpolicy_t*)&(ring_tmp->request_subply));
                if (rv != APR_SUCCESS) {
                    cli_printf_info(context, "request-method-protect set failure\n");
                    return CPARSER_NOT_OK;
                }

                sprintf(buf, "request-method-protect");
                admin_log_process(context, buf);
                break;
            }
        }

        context->parser->cur_node = &cparser_node_pe_protect_engine_security_policy_secpname_root_request_method_protect_option_eol;
        snprintf(prompt, CPARSER_MAX_PROMPT, "%s(method)#", g_cli_prompt);
        return cparser_submode_enter(context->parser, temp, prompt);
    }
    
    return CPARSER_OK;
}

cparser_result_t cparser_cmd_scp_request_method_protect_action_action_option(cparser_context_t *context,
    char **action_ptr,
    char **option_ptr)
{
    char prompt[CPARSER_MAX_PROMPT];
    security_policy_t *ring_tmp, *ring_tmp_n;
    int rv;
    char *temp;
    char buf[COMMAND_LEN_MAX];

    transfer_security_policy_name(context);
    temp = (char *)context->cookie[context->parser->root_level];

    if (context == NULL) {
        return CPARSER_NOT_OK;
    }

    if (context->parser->mode != CPARSER_MODE_CONFIG) {
        return CPARSER_OK;
    } else {
        APR_RING_FOREACH_SAFE(ring_tmp, ring_tmp_n, &sec_policy_ring, security_policy_s, ring) {
            if (strncmp(ring_tmp->name, temp, NAME_LEN_MAX) == 0) {
                if (option_ptr != NULL) {
                    sec_policy_get_action_option(&(ring_tmp->request_subply), action_ptr, option_ptr, buf); 
                } else {
                    sec_policy_get_action(&(ring_tmp->request_subply), action_ptr, buf);
                    (ring_tmp->request_subply).status = ENABLE;
                }
                
                (ring_tmp->request_subply).flag = 1;
                (ring_tmp->request_subply).log = 0;
                
                rv = convert_sec_subpolicy_set((sec_subpolicy_t*)&(ring_tmp->request_subply));
                if (rv != APR_SUCCESS) {
                    cli_printf_info(context, "request-method-protect set failure\n");
                    return CPARSER_NOT_OK;
                }

                admin_log_process(context, buf);
                break;
            }
        }

        context->parser->cur_node = &cparser_node_pe_protect_engine_security_policy_secpname_root_request_method_protect_option_eol;
        snprintf(prompt, CPARSER_MAX_PROMPT, "%s(method)#", g_cli_prompt);
        return cparser_submode_enter(context->parser, temp, prompt);
    }
    
    return CPARSER_OK;
}

cparser_result_t cparser_cmd_scp_request_method_protect_action_action_log_option(cparser_context_t *context,
    char **action_ptr,
    char **option_ptr)
{
    char prompt[CPARSER_MAX_PROMPT];
    security_policy_t *ring_tmp, *ring_tmp_n;
    int rv;
    char *temp;
    char buf[COMMAND_LEN_MAX];

    transfer_security_policy_name(context);
    temp = (char *)context->cookie[context->parser->root_level];

    if (context == NULL) {
        return CPARSER_NOT_OK; 
    }
    
    if (context->parser->mode != CPARSER_MODE_CONFIG) {
        return CPARSER_OK;
    } else {       
        APR_RING_FOREACH_SAFE(ring_tmp, ring_tmp_n, &sec_policy_ring, security_policy_s, ring) {
            if (strncmp(ring_tmp->name, temp, NAME_LEN_MAX) == 0) {
                if (option_ptr != NULL) {
                    sec_policy_get_action_log_option(&(ring_tmp->request_subply), action_ptr, option_ptr, buf); 
                } else {
                    sec_policy_get_action_log(&(ring_tmp->request_subply), action_ptr, buf);
                    (ring_tmp->request_subply).status = ENABLE;
                }
                
                (ring_tmp->request_subply).flag = 1;
                
                rv = convert_sec_subpolicy_set((sec_subpolicy_t*)&(ring_tmp->request_subply));
                if (rv != APR_SUCCESS) {
                    cli_printf_info(context, "request-method-protect set failure\n");
                    return CPARSER_NOT_OK;
                }

                admin_log_process(context, buf);
                break;
            }
        }

        context->parser->cur_node = &cparser_node_pe_protect_engine_security_policy_secpname_root_request_method_protect_option_eol;
        snprintf(prompt, CPARSER_MAX_PROMPT, "%s(method)#", g_cli_prompt);
        return cparser_submode_enter(context->parser, temp, prompt);
    }
    
    return CPARSER_OK;


}

cparser_result_t cparser_cmd_scp_request_method_protect_option(cparser_context_t *context,
    char **option_ptr)
{
    char prompt[CPARSER_MAX_PROMPT];
    security_policy_t *ring_tmp, *ring_tmp_n;
    int rv;
    char *temp;
    char buf[COMMAND_LEN_MAX];

    transfer_security_policy_name(context);
    temp = (char *)context->cookie[context->parser->root_level];
    
    if (context == NULL) {
        return CPARSER_NOT_OK;
    }
    
    if (context->parser->mode != CPARSER_MODE_CONFIG) {        
        APR_RING_FOREACH_SAFE(ring_tmp, ring_tmp_n, &sec_policy_ring, security_policy_s, ring) {
            if (strncmp(ring_tmp->name, temp, NAME_LEN_MAX) == 0) {
                cmd_c2p_request_method(context, &(ring_tmp->request_subply));
                break;
            }
        }
    } else { 
        if (option_ptr == NULL || *option_ptr == NULL) {
            return CPARSER_NOT_OK;
        }
        
        APR_RING_FOREACH_SAFE(ring_tmp, ring_tmp_n, &sec_policy_ring, security_policy_s, ring) {
            if (strncmp(ring_tmp->name, temp, NAME_LEN_MAX) == 0) {
                sec_policy_get_option(&(ring_tmp->request_subply), option_ptr, buf);
                (ring_tmp->request_subply).action = ACTION_PASS;
                (ring_tmp->request_subply).log = 0;
                (ring_tmp->request_subply).flag = 1;
                
                rv = convert_sec_subpolicy_set((sec_subpolicy_t*)&(ring_tmp->request_subply));
                if (rv != APR_SUCCESS) {
                    cli_printf_info(context, "request-method-protect set failure\n");
                    return CPARSER_NOT_OK;
                }

                admin_log_process(context, buf);
                break;
            }
        }

        snprintf(prompt, CPARSER_MAX_PROMPT, "%s(method)#", g_cli_prompt);
        return cparser_submode_enter(context->parser, temp, prompt);
    }
    
    return CPARSER_OK; 

}

/* 下面四个接口用来配置关键字过滤防护 */
cparser_result_t cparser_cmd_scp_keyword_filter(cparser_context_t *context)
{
    char prompt[CPARSER_MAX_PROMPT];
    security_policy_t *ring_tmp, *ring_tmp_n;
    int rv;
    char *temp;
    char buf[COMMAND_LEN_MAX];

    transfer_security_policy_name(context);
    temp = (char *)context->cookie[context->parser->root_level];

    if (context == NULL) {
        return CPARSER_NOT_OK;
    }

    if (context->parser->mode != CPARSER_MODE_CONFIG) {
        return CPARSER_OK;
    } else {
        APR_RING_FOREACH_SAFE(ring_tmp, ring_tmp_n, &sec_policy_ring, security_policy_s, ring) {
            if (strncmp(ring_tmp->name, temp, NAME_LEN_MAX) == 0) {
                (ring_tmp->keyword_subply).flag = 1;
                (ring_tmp->keyword_subply).status = ENABLE;
                (ring_tmp->keyword_subply).action = ACTION_PASS;
                (ring_tmp->keyword_subply).log = 0;
                
                rv = convert_sec_subpolicy_set((sec_subpolicy_t*)&(ring_tmp->keyword_subply));
                if (rv != APR_SUCCESS) {
                    cli_printf_info(context, "keyword-filter set failure\n");
                    return CPARSER_NOT_OK;
                }

                sprintf(buf, "keyword-filter");
                admin_log_process(context, buf);
                break;
            }
        }

        context->parser->cur_node = &cparser_node_pe_protect_engine_security_policy_secpname_root_keyword_filter_option_eol;
        snprintf(prompt, CPARSER_MAX_PROMPT, "%s(keyword-filter)#", g_cli_prompt);
        return cparser_submode_enter(context->parser, temp, prompt);
    }
    
    return CPARSER_OK;
}

cparser_result_t cparser_cmd_scp_keyword_filter_action_action_option(cparser_context_t *context,
    char **action_ptr,
    char **option_ptr)
{
    char prompt[CPARSER_MAX_PROMPT];
    security_policy_t *ring_tmp, *ring_tmp_n;
    int rv;
    char *temp;
    char buf[COMMAND_LEN_MAX];

    transfer_security_policy_name(context);
    temp = (char *)context->cookie[context->parser->root_level];

    if (context == NULL) {
        return CPARSER_NOT_OK;
    }

    if (context->parser->mode != CPARSER_MODE_CONFIG) {
        return CPARSER_OK;
    } else {
        APR_RING_FOREACH_SAFE(ring_tmp, ring_tmp_n, &sec_policy_ring, security_policy_s, ring) {
            if (strncmp(ring_tmp->name, temp, NAME_LEN_MAX) == 0) {
                if (option_ptr != NULL) {
                    sec_policy_get_action_option(&(ring_tmp->keyword_subply), action_ptr, option_ptr, buf); 
                } else {
                    sec_policy_get_action(&(ring_tmp->keyword_subply), action_ptr, buf);
                    (ring_tmp->keyword_subply).status = ENABLE;
                }
                
                (ring_tmp->keyword_subply).flag = 1;
                (ring_tmp->keyword_subply).log = 0;
                
                rv = convert_sec_subpolicy_set((sec_subpolicy_t*)&(ring_tmp->keyword_subply));
                if (rv != APR_SUCCESS) {
                    cli_printf_info(context, "keyword-filter set failure\n");
                    return CPARSER_NOT_OK;
                }

                admin_log_process(context, buf);
                break;
            }
        }

        context->parser->cur_node = &cparser_node_pe_protect_engine_security_policy_secpname_root_keyword_filter_option_eol;
        snprintf(prompt, CPARSER_MAX_PROMPT, "%s(keyword-filter)#", g_cli_prompt);
        return cparser_submode_enter(context->parser, temp, prompt);
    }
    
    return CPARSER_OK;
}

cparser_result_t cparser_cmd_scp_keyword_filter_action_action_log_option(cparser_context_t *context,
    char **action_ptr,
    char **option_ptr)
{
    char prompt[CPARSER_MAX_PROMPT];
    security_policy_t *ring_tmp, *ring_tmp_n;
    int rv;
    char *temp;
    char buf[COMMAND_LEN_MAX];

    transfer_security_policy_name(context);
    temp = (char *)context->cookie[context->parser->root_level];

    if (context == NULL) {
        return CPARSER_NOT_OK; 
    }
    
    if (context->parser->mode != CPARSER_MODE_CONFIG) {
        return CPARSER_OK;
    } else {       
        APR_RING_FOREACH_SAFE(ring_tmp, ring_tmp_n, &sec_policy_ring, security_policy_s, ring) {
            if (strncmp(ring_tmp->name, temp, NAME_LEN_MAX) == 0) {
                if (option_ptr != NULL) {
                    sec_policy_get_action_log_option(&(ring_tmp->keyword_subply), action_ptr, option_ptr, buf); 
                } else {
                    sec_policy_get_action_log(&(ring_tmp->keyword_subply), action_ptr, buf);
                    (ring_tmp->keyword_subply).status = ENABLE;
                }
                
                (ring_tmp->keyword_subply).flag = 1;
                
                rv = convert_sec_subpolicy_set((sec_subpolicy_t*)&(ring_tmp->keyword_subply));
                if (rv != APR_SUCCESS) {
                    cli_printf_info(context, "keyword-filter set failure\n");
                    return CPARSER_NOT_OK;
                }

                admin_log_process(context, buf);
                break;
            }
        }

        context->parser->cur_node = &cparser_node_pe_protect_engine_security_policy_secpname_root_keyword_filter_option_eol;
        snprintf(prompt, CPARSER_MAX_PROMPT, "%s(keyword-filter)#", g_cli_prompt);
        return cparser_submode_enter(context->parser, temp, prompt);
    }
    
    return CPARSER_OK;
}

cparser_result_t cparser_cmd_scp_keyword_filter_option(cparser_context_t *context,
    char **option_ptr)
{
    char prompt[CPARSER_MAX_PROMPT];
    security_policy_t *ring_tmp, *ring_tmp_n;
    int rv;
    char *temp;
    char buf[COMMAND_LEN_MAX];

    transfer_security_policy_name(context);
    temp = (char *)context->cookie[context->parser->root_level];
    
    if (context == NULL) {
        return CPARSER_NOT_OK;
    }
    
    if (context->parser->mode != CPARSER_MODE_CONFIG) {        
        APR_RING_FOREACH_SAFE(ring_tmp, ring_tmp_n, &sec_policy_ring, security_policy_s, ring) {
            if (strncmp(ring_tmp->name, temp, NAME_LEN_MAX) == 0) {
                cmd_c2p_keyword_filter(context, &(ring_tmp->keyword_subply));
                break;
            }
        }
    } else { 
        if (option_ptr == NULL || *option_ptr == NULL) {
            return CPARSER_NOT_OK;
        }
        
        APR_RING_FOREACH_SAFE(ring_tmp, ring_tmp_n, &sec_policy_ring, security_policy_s, ring) {
            if (strncmp(ring_tmp->name, temp, NAME_LEN_MAX) == 0) {
                sec_policy_get_option(&(ring_tmp->keyword_subply), option_ptr, buf);
                (ring_tmp->keyword_subply).action = ACTION_PASS;
                (ring_tmp->keyword_subply).log = 0;
                (ring_tmp->keyword_subply).flag = 1;
                
                rv = convert_sec_subpolicy_set((sec_subpolicy_t*)&(ring_tmp->keyword_subply));
                if (rv != APR_SUCCESS) {
                    cli_printf_info(context, "keyword-filter set failure\n");
                    return CPARSER_NOT_OK;
                }

                admin_log_process(context, buf);
                break;
            }
        }

        snprintf(prompt, CPARSER_MAX_PROMPT, "%s(keyword-filter)#", g_cli_prompt);
        return cparser_submode_enter(context->parser, temp, prompt);
    }
    
    return CPARSER_OK; 
}

/* 下面四个接口用来配置 cc防护 */
cparser_result_t cparser_cmd_scp_cc_protect(cparser_context_t *context)
{
    char prompt[CPARSER_MAX_PROMPT];
    security_policy_t *ring_tmp, *ring_tmp_n;
    int rv;
    char *temp;
    char buf[COMMAND_LEN_MAX];

    transfer_security_policy_name(context);
    temp = (char *)context->cookie[context->parser->root_level];

    if (context == NULL) {
        return CPARSER_NOT_OK;
    }

    if (context->parser->mode != CPARSER_MODE_CONFIG) {
        return CPARSER_OK;
    } else {
        APR_RING_FOREACH_SAFE(ring_tmp, ring_tmp_n, &sec_policy_ring, security_policy_s, ring) {
            if (strncmp(ring_tmp->name, temp, NAME_LEN_MAX) == 0) {
                (ring_tmp->ccprotect_subply).flag = 1;
                (ring_tmp->ccprotect_subply).status = ENABLE;
                (ring_tmp->ccprotect_subply).action = ACTION_PASS;
                (ring_tmp->ccprotect_subply).log = 0;
                
                rv = convert_sec_subpolicy_set((sec_subpolicy_t*)&(ring_tmp->ccprotect_subply));
                if (rv != APR_SUCCESS) {
                    cli_printf_info(context, "cc-protect set failure\n");
                    return CPARSER_NOT_OK;
                }

                sprintf(buf, "cc-protect");
                admin_log_process(context, buf);
                break;
            }
        }

        context->parser->cur_node = &cparser_node_pe_protect_engine_security_policy_secpname_root_cc_protect_option_eol;
        snprintf(prompt, CPARSER_MAX_PROMPT, "%s(cc)#", g_cli_prompt);
        return cparser_submode_enter(context->parser, temp, prompt);
    }
    
    return CPARSER_OK;
}

cparser_result_t cparser_cmd_scp_cc_protect_action_action_option(cparser_context_t *context,
    char **action_ptr,
    char **option_ptr)
{
    char prompt[CPARSER_MAX_PROMPT];
    security_policy_t *ring_tmp, *ring_tmp_n;
    int rv;
    char *temp;
    char buf[COMMAND_LEN_MAX];

    transfer_security_policy_name(context);
    temp = (char *)context->cookie[context->parser->root_level];

    if (context == NULL) {
        return CPARSER_NOT_OK;
    }

    if (context->parser->mode != CPARSER_MODE_CONFIG) {
        return CPARSER_OK;
    } else {
        APR_RING_FOREACH_SAFE(ring_tmp, ring_tmp_n, &sec_policy_ring, security_policy_s, ring) {
            if (strncmp(ring_tmp->name, temp, NAME_LEN_MAX) == 0) {
                if (option_ptr != NULL) {
                    sec_policy_get_action_option((generate_subpolicy_t*)&(ring_tmp->ccprotect_subply), action_ptr, option_ptr, buf); 
                } else {
                    sec_policy_get_action((generate_subpolicy_t*)&(ring_tmp->ccprotect_subply), action_ptr, buf);
                    (ring_tmp->ccprotect_subply).status = ENABLE;
                }
                
                (ring_tmp->ccprotect_subply).flag = 1;
                (ring_tmp->ccprotect_subply).log = 0;
                
                rv = convert_sec_subpolicy_set((sec_subpolicy_t*)&(ring_tmp->ccprotect_subply));
                if (rv != APR_SUCCESS) {
                    cli_printf_info(context, "cc-protect set failure\n");
                    return CPARSER_NOT_OK;
                }

                admin_log_process(context, buf);
                break;
            }
        }

        context->parser->cur_node = &cparser_node_pe_protect_engine_security_policy_secpname_root_cc_protect_option_eol;
        snprintf(prompt, CPARSER_MAX_PROMPT, "%s(cc)#", g_cli_prompt);
        return cparser_submode_enter(context->parser, temp, prompt);
    }
    
    return CPARSER_OK;
}

cparser_result_t cparser_cmd_scp_cc_protect_action_action_log_option(cparser_context_t *context,
    char **action_ptr,
    char **option_ptr)
{
    char prompt[CPARSER_MAX_PROMPT];
    security_policy_t *ring_tmp, *ring_tmp_n;
    int rv;
    char *temp;
    char buf[COMMAND_LEN_MAX];

    transfer_security_policy_name(context);
    temp = (char *)context->cookie[context->parser->root_level];

    if (context == NULL) {
        return CPARSER_NOT_OK; 
    }
    
    if (context->parser->mode != CPARSER_MODE_CONFIG) {
        return CPARSER_OK;
    } else {       
        APR_RING_FOREACH_SAFE(ring_tmp, ring_tmp_n, &sec_policy_ring, security_policy_s, ring) {
            if (strncmp(ring_tmp->name, temp, NAME_LEN_MAX) == 0) {
                if (option_ptr != NULL) {
                    sec_policy_get_action_log_option((generate_subpolicy_t*)&(ring_tmp->ccprotect_subply), action_ptr, option_ptr, buf); 
                } else {
                    sec_policy_get_action_log((generate_subpolicy_t*)&(ring_tmp->ccprotect_subply), action_ptr, buf);
                    (ring_tmp->ccprotect_subply).status = ENABLE;
                }
                
                (ring_tmp->ccprotect_subply).flag = 1;
                
                rv = convert_sec_subpolicy_set((sec_subpolicy_t*)&(ring_tmp->ccprotect_subply));
                if (rv != APR_SUCCESS) {
                    cli_printf_info(context, "cc-protect set failure\n");
                    return CPARSER_NOT_OK;
                }

                admin_log_process(context, buf);
                break;
            }
        }

        context->parser->cur_node = &cparser_node_pe_protect_engine_security_policy_secpname_root_cc_protect_option_eol;
        snprintf(prompt, CPARSER_MAX_PROMPT, "%s(cc)#", g_cli_prompt);
        return cparser_submode_enter(context->parser, temp, prompt);
    }
    
    return CPARSER_OK;

}

cparser_result_t cparser_cmd_scp_cc_protect_option(cparser_context_t *context,
    char **option_ptr)
{
    char prompt[CPARSER_MAX_PROMPT];
    security_policy_t *ring_tmp, *ring_tmp_n;
    int rv;
    char *temp;
    char buf[COMMAND_LEN_MAX];

    transfer_security_policy_name(context);
    temp = (char *)context->cookie[context->parser->root_level];
    
    if (context == NULL) {
        return CPARSER_NOT_OK;
    }
    
    if (context->parser->mode != CPARSER_MODE_CONFIG) {        
        APR_RING_FOREACH_SAFE(ring_tmp, ring_tmp_n, &sec_policy_ring, security_policy_s, ring) {
            if (strncmp(ring_tmp->name, temp, NAME_LEN_MAX) == 0) {
                cmd_c2p_cc(context, (generate_subpolicy_t*)&(ring_tmp->ccprotect_subply));
                break;
            }
        }
    } else { 
        if (option_ptr == NULL || *option_ptr == NULL) {
            return CPARSER_NOT_OK;
        }
        
        APR_RING_FOREACH_SAFE(ring_tmp, ring_tmp_n, &sec_policy_ring, security_policy_s, ring) {
            if (strncmp(ring_tmp->name, temp, NAME_LEN_MAX) == 0) {
                sec_policy_get_option((generate_subpolicy_t*)&(ring_tmp->ccprotect_subply), option_ptr, buf);
                (ring_tmp->ccprotect_subply).action = ACTION_PASS;
                (ring_tmp->ccprotect_subply).log = 0;
                (ring_tmp->ccprotect_subply).flag = 1;
                
                rv = convert_sec_subpolicy_set((sec_subpolicy_t*)&(ring_tmp->ccprotect_subply));
                if (rv != APR_SUCCESS) {
                    cli_printf_info(context, "cc-protect set failure\n");
                    return CPARSER_NOT_OK;
                }

                admin_log_process(context, buf);
                break;
            }
        }

        snprintf(prompt, CPARSER_MAX_PROMPT, "%s(cc)#", g_cli_prompt);
        return cparser_submode_enter(context->parser, temp, prompt);
    }
    
    return CPARSER_OK;
}

/* 该接口用来配置 cc模式下URL页面 */
cparser_result_t cparser_cmd_cc_url_page(cparser_context_t *context)
{
    char *temp_str;
    char prompt[CPARSER_MAX_PROMPT];
    char buf[COMMAND_LEN_MAX];
    security_policy_t *ring_tmp, *ring_tmp_n;

    temp_str = (char *)context->cookie[context->parser->root_level];

    if (context->parser->mode != CPARSER_MODE_CONFIG) { 
        APR_RING_FOREACH_SAFE(ring_tmp, ring_tmp_n, &sec_policy_ring, security_policy_s, ring) {
            if (strncmp(ring_tmp->name, temp_str, NAME_LEN_MAX) == 0) {
                cmd_c2p_url_page(context, ring_tmp);
                break;
            }
        }
    } else {
        APR_RING_FOREACH_SAFE(ring_tmp, ring_tmp_n, &sec_policy_ring, security_policy_s, ring) {
            if (strncmp(ring_tmp->name, temp_str, NAME_LEN_MAX) == 0) {
                ring_tmp->url_page_flag = 1;
                sprintf(buf, "url-page");
                admin_log_process(context, buf);
                snprintf(prompt, CPARSER_MAX_PROMPT, "%s(cc-url)#", g_cli_prompt);
                return cparser_submode_enter(context->parser, temp_str, prompt);
            }
        }
    }

    return CPARSER_OK;
}

/* 该接口用来配置commit命令 */
cparser_result_t cparser_cmd_scp_commit(cparser_context_t *context)
{
    security_policy_t *ring_tmp, *ring_tmp_n;
    int rv;
    char buf[COMMAND_LEN_MAX];
    char *temp_str;

    if (context->parser->mode != CPARSER_MODE_CONFIG) { 
        APR_RING_FOREACH_SAFE(ring_tmp, ring_tmp_n, &sec_policy_ring, security_policy_s, ring) {
            if (strncmp(ring_tmp->name, (char *)context->cookie[context->parser->root_level], NAME_LEN_MAX) == 0) {
                if (ring_tmp->commit_flag) {
                    commit_c2p(context);
                }

                break;
           }
        }
    } else {
        transfer_security_policy_name(context);
        temp_str = (char *)context->cookie[context->parser->root_level];
        APR_RING_FOREACH_SAFE(ring_tmp, ring_tmp_n, &sec_policy_ring, security_policy_s, ring) {
            if (strncmp(ring_tmp->name, temp_str, NAME_LEN_MAX) == 0) {
                rv = ap_secpolicy_deploy(temp_str);
                if (rv != OK) {
                    cli_printf_info(context, "security policy deploy failure\n");
                    ring_tmp->commit_status = 0;
                    return CPARSER_OK;
                }

                sprintf(buf, "commit");
                admin_log_process(context, buf);
                
                ring_tmp->commit_flag = 1;
                ring_tmp->commit_status = 1;
                break;
            }
        }
    }

    return CPARSER_OK;
}

