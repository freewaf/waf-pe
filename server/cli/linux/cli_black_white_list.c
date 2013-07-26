/*
 * $Id: cli_black_white_list.c 2786 2013-07-09 16:42:55 FreeWAF Development Team $
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
#include "cparser.h"
#include "cparser_priv.h"
#include "cparser_token.h"
#include "global_root.h"
#include "cparser_show_tree.h"
#include "cparser_tree.h"
#include "ap_config.h"
#include "httpd.h"
#include "http_main.h"
#include "http_log.h"
#include "mpm_common.h"
#include "cli_common.h"
#include "convert_rule.h"
#include "apr_optional.h"
#include "pe_cli.h"
#include "cli_black_white_list.h"

#define ADDRTYPE_LEN  16

/* 黑名单动态结点show结构 */
typedef struct dyn_blist_show_str_s {
    char *str;
    char *start_time;
    char *end_time;
} dyn_blist_show_str_t;

static apr_pool_t *pbwlist;
static blackwhite_flag_t *bw_flag;
static int commit_status;
APR_DECLARE_OPTIONAL_FN(int, dyn_access_list_show, (int lst, apr_array_header_t **result));

AP_DECLARE(int) blackwhite_list_init(apr_pool_t *p)
{
    int rv;

    /* 分配黑白名单的内存池 */
    rv = apr_pool_create(&pbwlist, p); 
    if (rv) {
        return DECLINED;
    }
    
    apr_pool_tag(pbwlist, "pbwlist");
    bw_flag = apr_pcalloc(pbwlist, sizeof(blackwhite_flag_t));
    if (bw_flag == NULL) {
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, NULL, "malloc failure");
        return DECLINED; 
    }

    BitSet(commit_status, IP_BLACK);
    BitSet(commit_status, IP_WHITE);
    BitSet(commit_status, URL_BLACK);
    BitSet(commit_status, URL_WHITE);
    
    return OK;
}

/**********************************************************************
 * IP黑名单
 **********************************************************************/
/* 进入ip-black-list模式 */
cparser_result_t cparser_cmd_pe_protect_engine_ip_black_list(cparser_context_t *context)
{
    char prompt[CPARSER_MAX_PROMPT];
    char buf[COMMAND_LEN_MAX];

    if (context == NULL) {
        return CPARSER_OK;
    }

    if (context->parser->mode != CPARSER_MODE_CONFIG) { 
        if (bw_flag->ipblack_flag) {
            if (context->parser->mode == CPARSER_MODE_WRITE) {
                assert(context->parser->fp);
                cli_fprintf(context, "protect-engine ip-black-list\n");
            } else {
                cli_printf(context, "!\n");
                cli_printf(context, "protect-engine ip-black-list\n");
            }
            
            context->parser->root_level++;
            context->parser->root[context->parser->root_level] = context->parser->cur_node->children;
            cparser_walk(context->parser, cparser_running_conf_walker, NULL, "ip-black-list");
            context->parser->root_level--;   
            
            return CPARSER_OK;   
        }     
    } else {
        bw_flag->ipblack_flag = 1;
        snprintf(prompt, CPARSER_MAX_PROMPT, "%s(ip-black-list)#", g_cli_prompt);
        
        snprintf(buf, COMMAND_LEN_MAX, "protect-engine ip-black-list");
        admin_log_process(context, buf);
        
        return cparser_submode_enter(context->parser, NULL, prompt);
    }

    return CPARSER_OK;  
}

cparser_result_t cparser_cmd_ipblack_client_ip_address_ipaddr(cparser_context_t *context,
                    uint32_t *ipaddr_ptr)
{
    int rv, i;
    char addr[ADDRTYPE_LEN];
    struct in_addr in;
    apr_pool_t *ptemp;
    char **result;
    apr_array_header_t *array;
    char buf[COMMAND_LEN_MAX];

    if (context == NULL) {
        return CPARSER_OK;
    }
    
    apr_pool_create(&ptemp, pbwlist); 
    apr_pool_tag(ptemp, "ptemp");
    
    if (context->parser->mode != CPARSER_MODE_CONFIG) { 
        array = apr_array_make(ptemp, INIT_ARR_LEN, sizeof(char*));
        if (convert_access_list_show(IP_BLACK, IB_CLIENT_IP, &array) == OK) {
            for (i = 0; i < array->nelts; i++) {
                result = (char **)(array->elts + (array->elt_size * i));

                if (context->parser->mode == CPARSER_MODE_WRITE) {
                    assert(context->parser->fp);
                    cli_fprintf(context, "client ip-address %s\n", *result);
                } else {
                    cli_printf(context, "client ip-address %s\n", *result);
                }
            }
        } 
        
        apr_pool_destroy(ptemp);
        
        return CPARSER_OK;
    } else {
        if (!ipaddr_ptr) {
            return CPARSER_NOT_OK;
        }
        
        in.s_addr = *ipaddr_ptr;
        sprintf(addr, "%d.%d.%d.%d", NIPQUAD(in.s_addr));
        snprintf(buf, COMMAND_LEN_MAX, "client ip-address %s", addr);
        rv = convert_access_list_set(IP_BLACK, IB_CLIENT_IP, addr);
        switch (rv) {
        case CONV_OK:
            admin_log_process(context, buf);
            break;
        case CONV_FAIL:
            cli_printf_info(context, "add ip to ip black list failure\n");
            break;
        case CONV_CONFLICT:
            cli_printf_info(context, "add failure, client ip has existed\n");
            break;
        case CONV_OVERFLOW:
            cli_printf_info(context, "add failure, client ip num overflow\n");
            break;   
        default:
            break;
        }
       
        apr_pool_destroy(ptemp);

        return CPARSER_OK;
    }    
}

static cparser_result_t cfg_ipblacklist_client_ip_no_cmd(cparser_context_t *context, int flag, 
    uint32_t ipaddr_ptr)
{
    int rv;
    char addr[ADDRTYPE_LEN];
    struct in_addr in;
    apr_pool_t *ptemp;
    char buf[COMMAND_LEN_MAX];
    
    apr_pool_create(&ptemp, pbwlist); 
    apr_pool_tag(ptemp, "ptemp");
    
    if (flag == 1) {
        strncpy(addr, KEYWORD_ALL, ADDRTYPE_LEN);
        snprintf(buf, COMMAND_LEN_MAX, "no client all");
    } else {
        in.s_addr = ipaddr_ptr;
        sprintf(addr, "%d.%d.%d.%d", NIPQUAD(in.s_addr));
        snprintf(buf, COMMAND_LEN_MAX, "no client ip-address %s", addr);
    }

    rv = convert_access_list_clear(IP_BLACK, IB_CLIENT_IP, addr);
    switch (rv) {
    case CONV_OK:
        admin_log_process(context, buf);
        break;
    case CONV_FAIL:
        cli_printf_info(context, "clear client ip failure\n");
        break;
    case CONV_NOTEXIST:
        cli_printf_info(context, "clear failure, the data isn't exist\n");
        break;
    default:
        break;
    }
    
    apr_pool_destroy(ptemp);
    return CPARSER_OK;

}

cparser_result_t cparser_cmd_ipblack_no_client_all(cparser_context_t *context)
{
    if (context == NULL) {
        return CPARSER_OK;
    }
    
    if (context->parser->mode != CPARSER_MODE_CONFIG) {        
        return CPARSER_OK;
    } else {
        return cfg_ipblacklist_client_ip_no_cmd(context, 1, 0);
    }    
}

cparser_result_t cparser_cmd_ipblack_no_client_ip_address_ipaddr(cparser_context_t *context,
                    uint32_t *ipaddr_ptr)
{
    if (context == NULL) {
        return CPARSER_OK;
    }
    
    if (context->parser->mode != CPARSER_MODE_CONFIG) {        
        return CPARSER_OK;
    } else {
        if (!ipaddr_ptr) {
            return CPARSER_NOT_OK;
        }
    
        return cfg_ipblacklist_client_ip_no_cmd(context, 0, *ipaddr_ptr);
    }  
}

cparser_result_t cparser_cmd_ipblack_dynamic_timeout_minutes(cparser_context_t *context,
                    uint32_t *minutes_ptr)
{
    int rv, i;
    char addr[ADDRTYPE_LEN];
    apr_pool_t *ptemp;
    char **result;
    apr_array_header_t *array;
    char buf[COMMAND_LEN_MAX];

    if (context == NULL) {
        return CPARSER_OK;
    }

    apr_pool_create(&ptemp, pbwlist); 
    apr_pool_tag(ptemp, "ptemp");
    
    if (context->parser->mode != CPARSER_MODE_CONFIG) {     
        array = apr_array_make(ptemp, INIT_ARR_LEN, sizeof(char*));
        if (convert_access_list_show(IP_BLACK, IB_DYN_TIMEOUT, &array) == OK) {
            for (i = 0; i < array->nelts; i++) {
                result = (char **)(array->elts + (array->elt_size * i));
                if (context->parser->mode == CPARSER_MODE_WRITE) {
                    assert(context->parser->fp);
                    cli_fprintf(context, "dynamic timeout %s\n", *result);
                } else {
                    cli_printf(context,"dynamic timeout %s\n", *result);
                }
            }
        }
      
        apr_pool_destroy(ptemp);

        return CPARSER_OK;
    } else {
        if (!minutes_ptr) {
            return CPARSER_NOT_OK;
        }

        if (*minutes_ptr < 1 || *minutes_ptr > 7200) {
            cli_printf_info(context, "dynamic timeout range is 1 to 7200 minutes\n");
            return CPARSER_NOT_OK;
        }

        snprintf(buf, COMMAND_LEN_MAX, "dynamic timeout %d", *minutes_ptr);
        strncpy(addr, apr_itoa(ptemp, *minutes_ptr), ADDRTYPE_LEN);
        rv = convert_access_list_set(IP_BLACK, IB_DYN_TIMEOUT, addr);
        if (rv != OK) {
            cli_printf_info(context, "set dynamic timeout failure\n");
        } else {
            admin_log_process(context, buf);
        }

        apr_pool_destroy(ptemp);

        return CPARSER_OK;
    }  
}

cparser_result_t cparser_cmd_ipblack_no_dynamic_timeout(cparser_context_t *context)
{
    int rv;
    char addr[ADDRTYPE_LEN];
    apr_pool_t *ptemp;
    char buf[COMMAND_LEN_MAX];

    if (context == NULL) {
        return CPARSER_OK;
    }
    
    if (context->parser->mode != CPARSER_MODE_CONFIG) {        
        return CPARSER_OK;
    } else {
        apr_pool_create(&ptemp, pbwlist); 
        apr_pool_tag(ptemp, "ptemp");

        /* 默认60分钟 */
        snprintf(buf, COMMAND_LEN_MAX, "no dynamic timeout");
        strncpy(addr, apr_itoa(ptemp, DYN_BLIST_DEFAULT_TIMEOUT), ADDRTYPE_LEN);
        rv = convert_access_list_set(IP_BLACK, IB_DYN_TIMEOUT, addr);
        if (rv != OK) {
            cli_printf_info(context, "clear dynamic timeout failure\n");
        } else {
            admin_log_process(context, buf);
        }
        
        apr_pool_destroy(ptemp);
        return CPARSER_OK;
    }  
}

cparser_result_t cparser_cmd_ipblack_dynamic_except_ip_address_ipaddr(cparser_context_t *context,
                    uint32_t *ipaddr_ptr)
{
    int rv, i;
    char addr[ADDRTYPE_LEN];
    struct in_addr in;
    apr_pool_t *ptemp;
    apr_array_header_t *array;
    char **result;
    char buf[COMMAND_LEN_MAX];

    if (context == NULL) {
        return CPARSER_OK;
    }
 
    apr_pool_create(&ptemp, pbwlist); 
    apr_pool_tag(ptemp, "ptemp");
    
    if (context->parser->mode != CPARSER_MODE_CONFIG) {        
        array = apr_array_make(ptemp, INIT_ARR_LEN, sizeof(char*));
        if (convert_access_list_show(IP_BLACK, IB_DYN_EXCEPT, &array) == OK) {
            for (i = 0; i < array->nelts; i++) {
                result = (char **)(array->elts + (array->elt_size * i));
                if (context->parser->mode == CPARSER_MODE_WRITE) {
                    assert(context->parser->fp);
                    cli_fprintf(context, "dynamic except ip-address %s\n", *result);
                } else {
                    cli_printf(context, "dynamic except ip-address %s\n", *result);
                }
            }
        }

        apr_pool_destroy(ptemp);
        return CPARSER_OK;
    } else {
        if (!ipaddr_ptr) {
            return CPARSER_NOT_OK;
        }
    
        in.s_addr = *ipaddr_ptr;
        sprintf(addr, "%d.%d.%d.%d", NIPQUAD(in.s_addr));
        snprintf(buf, COMMAND_LEN_MAX, "dynamic except ip-address %s", addr);
        rv = convert_access_list_set(IP_BLACK, IB_DYN_EXCEPT, addr);
        switch (rv) {
        case CONV_OK:
            admin_log_process(context, buf);
            break;
        case CONV_FAIL:
            cli_printf_info(context, "add dynamic except ip failure\n");
            break;
        case CONV_CONFLICT:
            cli_printf_info(context, "add failure, dynamic except ip has existed\n");
            break;
        case CONV_OVERFLOW:
            cli_printf_info(context, "add failure, client ip num overflow\n");
            break; 
        default:
            break;
        }
        
        apr_pool_destroy(ptemp);
        return CPARSER_OK;
    }
}

static cparser_result_t cfg_ipblacklist_dynamic_except_no_cmd(cparser_context_t *context, 
    int flag, uint32_t ipaddr_ptr)
{
    int rv;
    char addr[ADDRTYPE_LEN];
    struct in_addr in;
    char buf[COMMAND_LEN_MAX];
    
    if (flag == 1) {
        strncpy(addr, KEYWORD_ALL, ADDRTYPE_LEN);
        snprintf(buf, COMMAND_LEN_MAX, "no dynamic except all");
    } else {
        in.s_addr = ipaddr_ptr;
        sprintf(addr, "%d.%d.%d.%d", NIPQUAD(in.s_addr));
        snprintf(buf, COMMAND_LEN_MAX, "no dynamic except ip-address %s", addr);
    }
    
    rv = convert_access_list_clear(IP_BLACK, IB_DYN_EXCEPT, addr);
    switch (rv) {
    case CONV_OK:
        admin_log_process(context, buf);
        break;
    case CONV_FAIL:
        cli_printf_info(context, "clear dynamic except ip failure\n");
        break; 
    case CONV_NOTEXIST:
        cli_printf_info(context, "clear failure, the data isn't exist\n");
        break;
    default:
        break;
    }

    return CPARSER_OK;
}

cparser_result_t cparser_cmd_ipblack_no_dynamic_except_all(cparser_context_t *context)
{
    if (context == NULL) {
        return CPARSER_OK;
    }

    if (context->parser->mode != CPARSER_MODE_CONFIG) {        
        return CPARSER_OK;
    } else {
        return cfg_ipblacklist_dynamic_except_no_cmd(context, 1, 0);
    }    
}

cparser_result_t cparser_cmd_ipblack_no_dynamic_except_ip_address_ipaddr(cparser_context_t *context,
                    uint32_t *ipaddr_ptr)
{
    if (context == NULL) {
        return CPARSER_OK;
    }

    if (context->parser->mode != CPARSER_MODE_CONFIG) {        
        return CPARSER_OK;
    } else {
        if (!ipaddr_ptr) {
            return CPARSER_NOT_OK;
        }
        return cfg_ipblacklist_dynamic_except_no_cmd(context, 0, *ipaddr_ptr);
    }    
}

cparser_result_t cparser_cmd_ipblack_commit(cparser_context_t *context)
{
    int rv;
    apr_pool_t *ptemp;
    apr_array_header_t *client_array, *timeout_array, *except_array;
    char buf[COMMAND_LEN_MAX];

    if (context == NULL) {
        return CPARSER_OK;
    }

    if (context->parser->mode != CPARSER_MODE_CONFIG) {        
        if (bw_flag->ipblack_commit_flag) {
            if (context->parser->mode == CPARSER_MODE_WRITE) {
                assert(context->parser->fp);
                cli_fprintf(context, "commit\n");
            } else {
                cli_printf(context, "commit\n");
            }
            return CPARSER_OK;
        }
    } else {
        rv = ap_access_list_deploy(IP_BLACK);
        if (rv != OK) {
            cli_printf_info(context, "deploy ip black list failure\n");
            BitClr(commit_status, IP_BLACK);
            return CPARSER_NOT_OK;
        } else {
            snprintf(buf, COMMAND_LEN_MAX, "commit");
            admin_log_process(context, buf);
            BitSet(commit_status, IP_BLACK);
        }
    
        apr_pool_create(&ptemp, pbwlist); 
        apr_pool_tag(ptemp, "ptemp");
        
        client_array = apr_array_make(ptemp, INIT_ARR_LEN, sizeof(char*));
        timeout_array = apr_array_make(ptemp, INIT_ARR_LEN, sizeof(char*));
        except_array = apr_array_make(ptemp, INIT_ARR_LEN, sizeof(char*));

        convert_access_list_show(IP_BLACK, IB_CLIENT_IP, &client_array);     
        convert_access_list_show(IP_BLACK, IB_DYN_TIMEOUT, &timeout_array);
        convert_access_list_show(IP_BLACK, IB_DYN_EXCEPT, &except_array);

        if ((client_array->nelts == 0) && (timeout_array->nelts == 0) && (except_array->nelts == 0)) {
            bw_flag->ipblack_commit_flag = 0;
            bw_flag->ipblack_flag = 0; 
            apr_pool_destroy(ptemp);
            return CPARSER_OK;
        }

        bw_flag->ipblack_commit_flag = 1;
        apr_pool_destroy(ptemp);
    }      

    return CPARSER_OK;
}

/**********************************************************************
 * IP白名单
 **********************************************************************/
/* 进入ip-white-list模式 */
cparser_result_t cparser_cmd_pe_protect_engine_ip_white_list(cparser_context_t *context)
{
    char prompt[CPARSER_MAX_PROMPT];
    char buf[COMMAND_LEN_MAX];

    if (context == NULL) {
        return CPARSER_OK;
    }

    if (context->parser->mode != CPARSER_MODE_CONFIG) {  /* 进行c2p操作 */
        if (bw_flag->ipwhite_flag) {
            if (context->parser->mode == CPARSER_MODE_WRITE) {
                assert(context->parser->fp);
                cli_fprintf(context, "protect-engine ip-white-list\n");
            } else {
                cli_printf(context, "!\n");
                cli_printf(context, "protect-engine ip-white-list\n");
            }
            
            context->parser->root_level++;
            context->parser->root[context->parser->root_level] = context->parser->cur_node->children;
            cparser_walk(context->parser, cparser_running_conf_walker, NULL, "ip-white-list");
            context->parser->root_level--;   
        }
        
        return CPARSER_OK;
    } else {
        bw_flag->ipwhite_flag = 1;
        snprintf(prompt, CPARSER_MAX_PROMPT, "%s(ip-white-list)#", g_cli_prompt);
        
        snprintf(buf, COMMAND_LEN_MAX, "protect-engine ip-white-list");
        admin_log_process(context, buf);
        
        return cparser_submode_enter(context->parser, NULL, prompt);
    }
}

cparser_result_t cparser_cmd_ipwhite_client_ip_address_ipaddr(cparser_context_t *context,
                    uint32_t *ipaddr_ptr)
{
    int rv, i;
    struct in_addr in;
    char addr[STR_LEN_MAX];
    apr_pool_t *ptemp;
    apr_array_header_t *array;
    char **result;
    char buf[COMMAND_LEN_MAX];

    if (context == NULL) {
        return CPARSER_OK;
    }
    
    apr_pool_create(&ptemp, pbwlist); 
    apr_pool_tag(ptemp, "ptemp");
    
    if (context->parser->mode != CPARSER_MODE_CONFIG) {  /* 进行c2p操作 */
        array = apr_array_make(ptemp, INIT_ARR_LEN, sizeof(char*));
        if (convert_access_list_show(IP_WHITE, IW_CLIENT_IP, &array) == OK) {
            for (i = 0; i < array->nelts; i++) {
                result = (char **)(array->elts + (array->elt_size * i));
                if (context->parser->mode == CPARSER_MODE_WRITE) {
                    assert(context->parser->fp);
                    cli_fprintf(context, "client ip-address %s\n", *result);
                } else {
                    cli_printf(context, "client ip-address %s\n", *result);
                }
            }
        }
        apr_pool_destroy(ptemp);
        return CPARSER_OK;
    } else {
        if (!ipaddr_ptr) {
            return CPARSER_NOT_OK;
        }
        
        in.s_addr = *ipaddr_ptr;
        sprintf(addr, "%d.%d.%d.%d", NIPQUAD(in.s_addr));
        snprintf(buf, COMMAND_LEN_MAX, "client ip-address %s", addr);

        rv = convert_access_list_set(IP_WHITE, IW_CLIENT_IP, addr);
        switch (rv) {
        case CONV_OK:
            admin_log_process(context, buf);
            break;
        case CONV_FAIL:
            cli_printf_info(context, "add client ip to ip white list failure\n");
            break;
        case CONV_CONFLICT:
            cli_printf_info(context, "add failure, client ip has existed\n");
            break;
        case CONV_OVERFLOW:
            cli_printf_info(context, "add failure, client ip num overflow\n");
            break;   
        default:
            break;
        }
        
        apr_pool_destroy(ptemp);
        return CPARSER_OK;
    }
}

static cparser_result_t cfg_ipwhitelist_client_ip_no_cmd(cparser_context_t *context, int flag,
                         uint32_t ipaddr_ptr)
{
    int rv;
    struct in_addr in;
    char addr[STR_LEN_MAX];
    apr_pool_t *ptemp;
    
    apr_pool_create(&ptemp, pbwlist); 
    apr_pool_tag(ptemp, "ptemp");

    if (flag == 1) {
        strncpy(addr, KEYWORD_ALL, STR_LEN_MAX);
    } else {
        in.s_addr = ipaddr_ptr;
        sprintf(addr, "%d.%d.%d.%d", NIPQUAD(in.s_addr)); 
    }

    rv = convert_access_list_clear(IP_WHITE, IW_CLIENT_IP, addr);
    switch (rv) {
    case CONV_OK:
        break;
    case CONV_FAIL:
        cli_printf_info(context, "clear client ip failure\n");
        break;
    case CONV_NOTEXIST:
        cli_printf_info(context, "clear failure, the data isn't exist\n");
        break;
    default:
        break;
    }

    apr_pool_destroy(ptemp);
    return CPARSER_OK;
}

cparser_result_t cparser_cmd_ipwhite_no_client_all(cparser_context_t *context)
{
    if (context == NULL) {
        return CPARSER_OK;
    }

     if (context->parser->mode != CPARSER_MODE_CONFIG) {        
        return CPARSER_OK;
    } else {
        return cfg_ipwhitelist_client_ip_no_cmd(context, 1, 0);
    }     
}

cparser_result_t cparser_cmd_ipwhite_no_client_ip_address_ipaddr(cparser_context_t *context,
                    uint32_t *ipaddr_ptr)
{
    if (context == NULL) {
        return CPARSER_OK;
    }

    if (context->parser->mode != CPARSER_MODE_CONFIG) {        
        return CPARSER_OK;
    } else {
        if (!ipaddr_ptr) {
            return CPARSER_NOT_OK;
        }
        return cfg_ipwhitelist_client_ip_no_cmd(context, 0, *ipaddr_ptr);
    }      
}

cparser_result_t cparser_cmd_ipwhite_server_ip_address_ipaddr(cparser_context_t *context,
                    uint32_t *ipaddr_ptr)
{
    int rv, i;
    struct in_addr in;
    char addr[STR_LEN_MAX];
    apr_pool_t *ptemp;
    char **result;
    apr_array_header_t *array;
    char buf[COMMAND_LEN_MAX];

    if (context == NULL) {
        return CPARSER_OK;
    }
    
    apr_pool_create(&ptemp, pbwlist); 
    apr_pool_tag(ptemp, "ptemp");
    
    if (context->parser->mode != CPARSER_MODE_CONFIG) {        
        array = apr_array_make(ptemp, INIT_ARR_LEN, sizeof(char*));
        apr_array_clear(array);
        if (convert_access_list_show(IP_WHITE, IW_SERVER_IP, &array) == OK) {
            for (i = 0; i < array->nelts; i++) {
                result = (char **)(array->elts + (array->elt_size * i));
                if (context->parser->mode == CPARSER_MODE_WRITE) {
                    assert(context->parser->fp);
                    cli_fprintf(context, "server ip-address %s\n", *result);
                } else {
                    cli_printf(context, "server ip-address %s\n", *result);
                }
            }        
        }

        apr_pool_destroy(ptemp);
        return CPARSER_OK;
    } else {
        if (!ipaddr_ptr) {
            return CPARSER_NOT_OK;
        }
    
        in.s_addr = *ipaddr_ptr;
        sprintf(addr, "%d.%d.%d.%d", NIPQUAD(in.s_addr)); 
        snprintf(buf, COMMAND_LEN_MAX, "server ip-address %s", addr);
        rv = convert_access_list_set(IP_WHITE, IW_SERVER_IP, addr);
        switch (rv) {
        case CONV_OK:
            admin_log_process(context, buf);
            break;
        case CONV_FAIL:
            cli_printf_info(context, "add server ip to ip white list failure\n");
            break;
        case CONV_CONFLICT:
            cli_printf_info(context, "add failure, server ip has existed\n");
            break;
        case CONV_OVERFLOW:
            cli_printf_info(context, "add failure, server ip num overflow\n");
            break;   
        default:
            break;
        }

        apr_pool_destroy(ptemp);
        return CPARSER_OK;
    }  
}

static cparser_result_t cfg_ipwhitelist_server_ip_no_cmd(cparser_context_t *context, int flag, 
                         uint32_t ipaddr_ptr)
{
    int rv;
    struct in_addr in;
    char addr[STR_LEN_MAX];
    apr_pool_t *ptemp;
    char buf[COMMAND_LEN_MAX];
    
    apr_pool_create(&ptemp, pbwlist); 
    apr_pool_tag(ptemp, "ptemp");
    
    if (flag == 1) {
        strncpy(addr, KEYWORD_ALL, STR_LEN_MAX);
        snprintf(buf, COMMAND_LEN_MAX, "no server all");
    } else {
        in.s_addr = ipaddr_ptr;
        sprintf(addr, "%d.%d.%d.%d", NIPQUAD(in.s_addr));
        snprintf(buf, COMMAND_LEN_MAX, "no server ip-address %s", addr);
    }

    rv = convert_access_list_clear(IP_WHITE, IW_SERVER_IP, addr);
    switch (rv) {
    case CONV_OK:
        admin_log_process(context, buf);
        break;
    case CONV_FAIL:
        cli_printf_info(context, "delete server ip failure\n");
        break;
    case CONV_NOTEXIST:
        cli_printf_info(context, "delete failure, the data isn't exist\n");
        break;
    default:
        break;
    }   

    return CPARSER_OK;
}

cparser_result_t cparser_cmd_ipwhite_no_server_all(cparser_context_t *context)
{
    if (context == NULL) {
        return CPARSER_OK;
    }

    if (context->parser->mode != CPARSER_MODE_CONFIG) {        
        return CPARSER_OK;
    } else {
        return cfg_ipwhitelist_server_ip_no_cmd(context, 1, 0);
    }   
}

cparser_result_t cparser_cmd_ipwhite_no_server_ip_address_ipaddr(cparser_context_t *context,
                    uint32_t *ipaddr_ptr)
{
    if (context == NULL) {
        return CPARSER_OK;
    }

    if (context->parser->mode != CPARSER_MODE_CONFIG) {        
        return CPARSER_OK;
    } else {
        if (!ipaddr_ptr) {
            return CPARSER_NOT_OK;
        }
        return cfg_ipwhitelist_server_ip_no_cmd(context, 0, *ipaddr_ptr);
    }   
}

cparser_result_t cparser_cmd_ipwhite_server_host_plain_text_hostname(cparser_context_t *context,
                    char **hostname_ptr)
{
    int rv, i;
    char addr[STR_LEN_MAX];
    apr_pool_t *ptemp;
    apr_array_header_t *array;
    char **result;
    char buf[COMMAND_LEN_MAX];

    if (context == NULL) {
        return CPARSER_OK;
    }

    if (context->parser->mode != CPARSER_MODE_CONFIG) {     
        apr_pool_create(&ptemp, pbwlist); 
        apr_pool_tag(ptemp, "ptemp");
    
        array = apr_array_make(ptemp, INIT_ARR_LEN, sizeof(char*));
        if (convert_access_list_show(IP_WHITE, IW_SERVER_HOST, &array) == OK) {
            for (i = 0; i < array->nelts; i++) {
                result = (char **)(array->elts + (array->elt_size * i));
                if (context->parser->mode == CPARSER_MODE_WRITE) {
                    assert(context->parser->fp);
                    cli_fprintf(context, "server host plain-text %s\n", *result);
                } else {
                    cli_printf(context, "server host plain-text %s\n", *result);
                }
            }        
        }

        apr_pool_destroy(ptemp);
        return CPARSER_OK;
    } else {
        if (!hostname_ptr || !*hostname_ptr) {
            return CPARSER_NOT_OK;
        }
    
        strncpy(addr, *hostname_ptr, STR_LEN_MAX);
        snprintf(buf, COMMAND_LEN_MAX, "server host plain-text %s", *hostname_ptr);
        rv = convert_access_list_set(IP_WHITE, IW_SERVER_HOST, addr);
        switch (rv) {
        case CONV_OK:
            admin_log_process(context, buf);
            break;
        case CONV_FAIL:
            cli_printf_info(context, "add server host failure\n");
            break;
        case CONV_CONFLICT:
            cli_printf_info(context, "add failure, server host has existed\n");
            break;
        case CONV_OVERFLOW:
            cli_printf_info(context, "add failure, server host num overflow\n");
            break;   
        default:
            break;
        } 
        
        return CPARSER_OK;
    }   
}

static cparser_result_t cfg_ipwhitelist_server_host_no_cmd(cparser_context_t *context, int flag,  
                         char *hostname_ptr)
{
    char addr[STR_LEN_MAX];
    int rv;
    char buf[COMMAND_LEN_MAX];
    
    if (flag == 1) {
        strncpy(addr, KEYWORD_ALL, STR_LEN_MAX);
        snprintf(buf, COMMAND_LEN_MAX, "no server host all");
    } else {
        strncpy(addr, hostname_ptr, STR_LEN_MAX);
        snprintf(buf, COMMAND_LEN_MAX, "no server host plain-text %s", hostname_ptr);
    }

    rv = convert_access_list_clear(IP_WHITE, IW_SERVER_HOST, addr);
    switch (rv) {
    case CONV_OK:
        admin_log_process(context, buf);
        break;
    case CONV_FAIL:
        cli_printf_info(context, "clear server host failure\n");
        break;
    case CONV_NOTEXIST:
        cli_printf_info(context, "clear failure, the data isn't exist\n");
        break;
    default:
        break;
    }

    return CPARSER_OK;
}

cparser_result_t cparser_cmd_ipwhite_no_server_host_all(cparser_context_t *context)
{
    if (context == NULL) {
        return CPARSER_OK;
    }

    if (context->parser->mode != CPARSER_MODE_CONFIG) {        
        return CPARSER_OK;
    } else {
        return cfg_ipwhitelist_server_host_no_cmd(context, 1, NULL);
    }  
}

cparser_result_t cparser_cmd_ipwhite_no_server_host_plain_text_hostname(cparser_context_t *context,
                    char **hostname_ptr)
{
    if (context == NULL) {
        return CPARSER_OK;
    }

    if (context->parser->mode != CPARSER_MODE_CONFIG) {        
        return CPARSER_OK;
    } else {
        if (!hostname_ptr || !*hostname_ptr) {
            return CPARSER_NOT_OK;
        }
    
        return cfg_ipwhitelist_server_host_no_cmd(context, 0, *hostname_ptr);
    }  
}

cparser_result_t cparser_cmd_ipwhite_commit(cparser_context_t *context)
{
    int rv;
    apr_pool_t *ptemp;
    apr_array_header_t *client_array, *server_array, *host_array;
    char buf[COMMAND_LEN_MAX];

    if (context == NULL) {
        return CPARSER_OK;
    }
    
    if (context->parser->mode != CPARSER_MODE_CONFIG) {        
        if (bw_flag->ipwhite_commit_flag) {
            if (context->parser->mode == CPARSER_MODE_WRITE) {
                assert(context->parser->fp);
                cli_fprintf(context, "commit\n");
            } else {
                cli_printf(context, "commit\n");
            }            
        }

        return CPARSER_OK;
    } else {
        rv = ap_access_list_deploy(IP_WHITE);
        snprintf(buf, COMMAND_LEN_MAX, "commit");
        if (rv != OK) {
            cli_printf_info(context, "deploy ip white list failure\n");
            BitClr(commit_status, IP_WHITE);
            return CPARSER_NOT_OK;
        } else {
            admin_log_process(context, buf);
            BitSet(commit_status, IP_WHITE);
        }

        apr_pool_create(&ptemp, pbwlist); 
        apr_pool_tag(ptemp, "ptemp");

        client_array = apr_array_make(ptemp, INIT_ARR_LEN, sizeof(char*));
        server_array = apr_array_make(ptemp, INIT_ARR_LEN, sizeof(char*));
        host_array = apr_array_make(ptemp, INIT_ARR_LEN, sizeof(char*));
        
        convert_access_list_show(IP_WHITE, IW_CLIENT_IP, &client_array);
        convert_access_list_show(IP_WHITE, IW_SERVER_IP, &server_array);
        convert_access_list_show(IP_WHITE, IW_SERVER_HOST, &host_array);

        if ((client_array->nelts == 0) && (server_array->nelts == 0) && (host_array->nelts == 0)) {
            bw_flag->ipwhite_commit_flag = 0;
            bw_flag->ipwhite_flag = 0;
            apr_pool_destroy(ptemp);
            return CPARSER_OK;
        }

        bw_flag->ipwhite_commit_flag = 1;
                
        apr_pool_destroy(ptemp);
        return CPARSER_OK;
    }   
}

/**********************************************************************
 * URL白名单
 **********************************************************************/
/* 进入url-white-list模式 */
cparser_result_t cparser_cmd_pe_protect_engine_url_white_list(cparser_context_t *context)
{
    char prompt[CPARSER_MAX_PROMPT];
    char buf[COMMAND_LEN_MAX];

    if (context == NULL) {
        return CPARSER_OK;
    }
    
    if (context->parser->mode != CPARSER_MODE_CONFIG) {
        if (bw_flag->urlwhite_flag) {
            if (context->parser->mode == CPARSER_MODE_WRITE) {
                assert(context->parser->fp);
                cli_fprintf(context, "protect-engine url-white-list\n");
            } else {
                cli_printf(context, "!\n");
                cli_printf(context, "protect-engine url-white-list\n");
            }    

            context->parser->root_level++;
            context->parser->root[context->parser->root_level] = context->parser->cur_node->children;
            cparser_walk(context->parser, cparser_running_conf_walker, NULL, "url-white-list");
            context->parser->root_level--;   
            
            return CPARSER_OK;   
        }
    } else {
        bw_flag->urlwhite_flag = 1;
        snprintf(prompt, CPARSER_MAX_PROMPT, "%s(url-white-list)#", g_cli_prompt);
        
        snprintf(buf, COMMAND_LEN_MAX, "protect-engine url-white-list");
        admin_log_process(context, buf);
        
        return cparser_submode_enter(context->parser, NULL, prompt);
    }

    return CPARSER_OK;
}

cparser_result_t cparser_cmd_urlwhite_url_options_url_string(cparser_context_t *context,
                    char **options_ptr, char **url_string_ptr)
{
    int i, rv;
    apr_pool_t *ptemp;
    apr_array_header_t *array;
    char **result;
    char str[STR_LEN_MAX];
    char buf[COMMAND_LEN_MAX];

    if (context == NULL) {
        return CPARSER_OK;
    }
      
    if (context->parser->mode != CPARSER_MODE_CONFIG) {
        apr_pool_create(&ptemp, pbwlist); 
        apr_pool_tag(ptemp, "ptemp");
    
        array = apr_array_make(ptemp, INIT_ARR_LEN, sizeof(char*));
        if (convert_access_list_show(URL_WHITE, UW_URL_PLAIN, &array) == OK) {
            for (i = 0; i < array->nelts; i++) {
                result = (char **)(array->elts + (array->elt_size * i));
                if (context->parser->mode == CPARSER_MODE_WRITE) {
                    assert(context->parser->fp);
                    cli_fprintf(context, "url plain-text %s\n", *result);
                } else {
                    cli_printf(context, "url plain-text %s\n", *result);
                }    
            }
        }

        apr_array_clear(array);
        if (convert_access_list_show(URL_WHITE, UW_URL_REGEX, &array) == OK) {
            for (i = 0; i < array->nelts; i++) {
                result = (char **)(array->elts + (array->elt_size * i));
                if (context->parser->mode == CPARSER_MODE_WRITE) {
                    assert(context->parser->fp);
                    cli_fprintf(context, "url regular-exp %s\n", *result);
                } else {
                    cli_printf(context, "url regular-exp %s\n", *result);
                }    
            }
        }
        
        apr_pool_destroy(ptemp);
        return CPARSER_OK;        
    } else {
        if (!options_ptr || !*options_ptr || !url_string_ptr || !*url_string_ptr) {
            return CPARSER_NOT_OK;
        }

        strncpy(str, *url_string_ptr, STR_LEN_MAX);
        if (!strcmp(*options_ptr, "plain-text")) {     
            rv = convert_access_list_set(URL_WHITE, UW_URL_PLAIN, str);
            
        } else {
            rv = convert_access_list_set(URL_WHITE, UW_URL_REGEX, str);
        }

        switch (rv) {
        case CONV_OK:
            snprintf(buf, COMMAND_LEN_MAX, "url %s %s", *options_ptr, *url_string_ptr);
            admin_log_process(context, buf);
            break;
        case CONV_FAIL:
            cli_printf_info(context, "add url to url white list failure\n");
            break;
        case CONV_CONFLICT:
            cli_printf_info(context, "add failure, url has existed\n");
            break;
        case CONV_OVERFLOW:
            cli_printf_info(context, "add failure, url num overflow\n");
            break;   
        default:
            break;
        }
        
        return CPARSER_OK; 
    }
}

static cparser_result_t cfg_urlwhitelist_url_no_cmd(cparser_context_t *context, int flag, 
                         int regular, char *url_string_ptr)
{
    int rv;
    char str[STR_LEN_MAX]; 
    char buf[COMMAND_LEN_MAX];
    
    if (flag == 1) {
        strncpy(str, KEYWORD_ALL, STR_LEN_MAX);
        snprintf(buf, COMMAND_LEN_MAX, "no url all");
        rv = convert_access_list_clear(URL_WHITE, UW_URL_PLAIN, str);/*no url all */
        rv = convert_access_list_clear(URL_WHITE, UW_URL_REGEX, str);
    } else {
        strncpy(str, url_string_ptr, STR_LEN_MAX);
        if (regular) {
           snprintf(buf, COMMAND_LEN_MAX, "no url regular-exp %s", url_string_ptr);
           rv = convert_access_list_clear(URL_WHITE, UW_URL_REGEX, str);
        } else {
           snprintf(buf, COMMAND_LEN_MAX, "no url plain-text %s", url_string_ptr); 
           rv = convert_access_list_clear(URL_WHITE, UW_URL_PLAIN, str);
        }
    }
    
    switch (rv) {
    case CONV_OK:
        admin_log_process(context, buf);
        break;
    case CONV_FAIL:
        cli_printf_info(context, "clear url failure\n");
        break;
    case CONV_NOTEXIST:
        cli_printf_info(context, "clear failure, the data isn't exist\n");
        break;
    default:
        break;
    }   
    
    return CPARSER_OK; 
}

cparser_result_t cparser_cmd_urlwhite_no_url_all(cparser_context_t *context)
{
    if (context == NULL) {
        return CPARSER_OK;
    }

    if (context->parser->mode != CPARSER_MODE_CONFIG) {        
        return CPARSER_OK;
    } else {
        return cfg_urlwhitelist_url_no_cmd(context, 1, 0, 0);
    }   
}

cparser_result_t cparser_cmd_urlwhite_no_url_options_url_string(cparser_context_t *context,
                    char **options_ptr, char **url_string_ptr)
{
    if (context == NULL) {
        return CPARSER_OK;
    }

    if (context->parser->mode != CPARSER_MODE_CONFIG) {        
        return CPARSER_OK;
    } else {
        if (!options_ptr || !*options_ptr || !url_string_ptr || !*url_string_ptr) {
            return CPARSER_NOT_OK;
        }
    
        if (!strcmp(*options_ptr, "plain-text")) {
            return cfg_urlwhitelist_url_no_cmd(context, 0, UW_URL_PLAIN, *url_string_ptr);
        } if (!strcmp(*options_ptr, "regular-exp")) {
            return cfg_urlwhitelist_url_no_cmd(context, 0, UW_URL_REGEX, *url_string_ptr);
        }
    }   

    return CPARSER_OK;
}

cparser_result_t cparser_cmd_urlwhite_commit(cparser_context_t *context)
{
    int rv;
    apr_array_header_t *url_array;
    apr_pool_t *ptemp;
    char buf[COMMAND_LEN_MAX];

    if (context == NULL) {
        return CPARSER_OK;
    }
    
    if (context->parser->mode != CPARSER_MODE_CONFIG) {
        if (bw_flag->urlwhite_commit_flag) {
            if (context->parser->mode == CPARSER_MODE_WRITE) {
                assert(context->parser->fp);
                cli_fprintf(context, "commit\n");
            } else {
                cli_printf(context, "commit\n");
            }    
        }
        return CPARSER_OK;
    } else{
        snprintf(buf, COMMAND_LEN_MAX, "commit");
        rv = ap_access_list_deploy(URL_WHITE);
        if (rv != OK) {
            cli_printf_info(context, "deploy url white list failure\n");
            BitClr(commit_status, URL_WHITE);
            return CPARSER_NOT_OK;
        } else {
            admin_log_process(context, buf);
            BitSet(commit_status, URL_WHITE);
        }

        apr_pool_create(&ptemp, pbwlist); 
        apr_pool_tag(ptemp, "ptemp");
    
        url_array = apr_array_make(ptemp, INIT_ARR_LEN, sizeof(char*));
        convert_access_list_show(URL_WHITE, UW_URL_PLAIN, &url_array);
        convert_access_list_show(URL_WHITE, UW_URL_REGEX, &url_array);
        if (url_array->nelts == 0) {
            bw_flag->urlwhite_flag = 0;
            bw_flag->urlwhite_commit_flag = 0; 
            apr_pool_destroy(ptemp);
            return CPARSER_OK;
        }

        bw_flag->urlwhite_commit_flag = 1;
        apr_pool_destroy(ptemp);
        
        return CPARSER_OK;
    }
}

/**********************************************************************
 * URL黑名单
 **********************************************************************/
/* 进入url-black-list模式 */
cparser_result_t cparser_cmd_pe_protect_engine_url_black_list(cparser_context_t *context)
{ 
    char prompt[CPARSER_MAX_PROMPT];
    char buf[COMMAND_LEN_MAX];
    
    if (context == NULL) {
        return CPARSER_OK;
    }
        
    if (context->parser->mode != CPARSER_MODE_CONFIG) {
        if (bw_flag->urlblack_flag) {
            if (context->parser->mode == CPARSER_MODE_WRITE) {
                assert(context->parser->fp);
                cli_fprintf(context, "protect-engine url-black-list\n");
            } else {
                cli_printf(context,"!\n");
                cli_printf(context,"protect-engine url-black-list\n");
            }    

            context->parser->root_level++;
            context->parser->root[context->parser->root_level] = context->parser->cur_node->children;
            cparser_walk(context->parser, cparser_running_conf_walker, NULL, "url-black-list");
            context->parser->root_level--;   
            
            return CPARSER_OK;   
        }
    } else {
        bw_flag->urlblack_flag = 1;
        snprintf(prompt, CPARSER_MAX_PROMPT, "%s(url-black-list)#", g_cli_prompt);
        snprintf(buf, COMMAND_LEN_MAX, "protect-engine url-black-list");
        admin_log_process(context, buf);
        
        return cparser_submode_enter(context->parser, NULL, prompt);
    }

    return CPARSER_OK;
}

cparser_result_t cparser_cmd_urlblack_url_options_url_string(cparser_context_t *context,
                    char **options_ptr, char **url_string_ptr)
{
    char str[STR_LEN_MAX];
    int rv, i;
    apr_pool_t *ptemp;
    apr_array_header_t *array;
    char **result;
    char buf[COMMAND_LEN_MAX];

    if (context == NULL) {
        return CPARSER_OK;
    }

    if (context->parser->mode != CPARSER_MODE_CONFIG) {
        apr_pool_create(&ptemp, pbwlist); 
        apr_pool_tag(ptemp, "ptemp"); 
        
        array = apr_array_make(ptemp, INIT_ARR_LEN, sizeof(char*));
        if (convert_access_list_show(URL_BLACK, UB_URL_PLAIN, &array) == OK) {
            for (i = 0; i < array->nelts; i++) {
                result = (char **)(array->elts + (array->elt_size * i));
                if (context->parser->mode == CPARSER_MODE_WRITE) {
                    assert(context->parser->fp);
                    cli_fprintf(context, "url plain-text %s\n", *result);
                } else {
                    cli_printf(context, "url plain-text %s\n", *result);
                }    
            }
        }

        apr_array_clear(array);
        if (convert_access_list_show(URL_BLACK, UB_URL_REGEX, &array) == OK) {
            for (i = 0; i < array->nelts; i++) {
                result = (char **)(array->elts + (array->elt_size * i));
                if (context->parser->mode == CPARSER_MODE_WRITE) {
                    assert(context->parser->fp);
                    cli_fprintf(context, "url regular-exp %s\n", *result);
                } else {
                    cli_printf(context, "url regular-exp %s\n", *result);
                }    
            }
        }
        
        apr_pool_destroy(ptemp);
        return CPARSER_OK;
    } else {
        if (!options_ptr || !*options_ptr || !url_string_ptr || !*url_string_ptr) {
            return CPARSER_NOT_OK;
        }

        strncpy(str, *url_string_ptr, STR_LEN_MAX);

        if (!strcmp(*options_ptr, "plain-text")) {
            rv = convert_access_list_set(URL_BLACK, UB_URL_PLAIN, str);
        } else {
            rv = convert_access_list_set(URL_BLACK, UB_URL_REGEX, str);
        }

        switch (rv) {
        case CONV_OK:
            snprintf(buf, COMMAND_LEN_MAX, "url %s %s", *options_ptr, *url_string_ptr);
            admin_log_process(context, buf);
            break;
        case CONV_FAIL:
            cli_printf_info(context, "add url to url black list failure\n");
            break;
        case CONV_CONFLICT:
            cli_printf_info(context, "add failure, url has existed\n");
            break;
        case CONV_OVERFLOW:
            cli_printf_info(context, "add failure, url num overflow\n");
            break;   
        default:
            break;
        }
        
        return CPARSER_OK;
    }
}

static cparser_result_t cfg_urlblacklist_url_no_cmd(cparser_context_t *context, int flag, 
                         int regular, char *url_string_ptr)
{
    char str[STR_LEN_MAX];
    int rv;
    char buf[COMMAND_LEN_MAX];

    if (flag == 1) {
        strncpy(str, KEYWORD_ALL, STR_LEN_MAX);
        snprintf(buf, COMMAND_LEN_MAX, "no url all");
        rv = convert_access_list_clear(URL_BLACK, UB_URL_PLAIN, str);/* 需要确定no url all */
        rv = convert_access_list_clear(URL_BLACK, UB_URL_REGEX, str);
    } else {
        strncpy(str, url_string_ptr, STR_LEN_MAX);
        if (!regular) {
            snprintf(buf, COMMAND_LEN_MAX, "no url plain-text %s", url_string_ptr);
            rv = convert_access_list_clear(URL_BLACK, UB_URL_PLAIN, str);
        } else {
            snprintf(buf, COMMAND_LEN_MAX, "no url regular-exp %s", url_string_ptr);
            rv = convert_access_list_clear(URL_BLACK, UB_URL_REGEX, str);
        }
    }
    
    switch (rv) {
    case CONV_OK:
        admin_log_process(context, buf);
        break;
    case CONV_FAIL:
        cli_printf_info(context, "clear url failure\n");
        break;
    case CONV_NOTEXIST:
        cli_printf_info(context, "clear failure, the data isn't exist\n");
        break;
    default:
        break;
    }

    return CPARSER_OK;
}

cparser_result_t cparser_cmd_urlblack_no_url_all(cparser_context_t *context)
{
    if (context == NULL) {
        return CPARSER_OK;
    }

    if (context->parser->mode != CPARSER_MODE_CONFIG) {        
        return CPARSER_OK;
    } else {
        return cfg_urlblacklist_url_no_cmd(context, 1, 0, 0);
    }  
}

cparser_result_t cparser_cmd_urlblack_no_url_options_url_string(cparser_context_t *context,
                    char **options_ptr, char **url_string_ptr)
{
    if (context == NULL) {
        return CPARSER_OK;
    }

    if (context->parser->mode != CPARSER_MODE_CONFIG) {        
        return CPARSER_OK;
    } else {
        if (!options_ptr || !*options_ptr || !url_string_ptr || !*url_string_ptr) {
            return CPARSER_NOT_OK;
        }
        
        if (!strcmp(*options_ptr, "plain-text")) {
            return cfg_urlblacklist_url_no_cmd(context, 0, 0, *url_string_ptr);
        } if (!strcmp(*options_ptr, "regular-exp")) {
            return cfg_urlblacklist_url_no_cmd(context, 0, 1, *url_string_ptr);
        }
    } 

    return CPARSER_OK;
}

cparser_result_t cparser_cmd_urlblack_dynamic_except_referrer_url_url_string(cparser_context_t *context,
                    char **url_string_ptr)
{
    char str[STR_LEN_MAX];
    int rv, i;
    apr_pool_t *ptemp;
    apr_array_header_t *array;
    char **result;
    char buf[COMMAND_LEN_MAX];

    if (context == NULL) {
        return CPARSER_OK;
    }
    
    if (context->parser->mode != CPARSER_MODE_CONFIG) {
        apr_pool_create(&ptemp, pbwlist); 
        apr_pool_tag(ptemp, "ptemp"); 
        
        array = apr_array_make(ptemp, INIT_ARR_LEN, sizeof(char*));
        if (convert_access_list_show(URL_BLACK, UB_DYN_EXCEPT, &array) == OK) {
            for (i = 0; i < array->nelts; i++) {
                result = (char **)(array->elts + (array->elt_size * i));
                if (context->parser->mode == CPARSER_MODE_WRITE) {
                    assert(context->parser->fp);
                    cli_fprintf(context, "dynamic except referrer-url %s\n", *result);
                } else {
                    cli_printf(context,"dynamic except referrer-url %s\n", *result);
                }    
            }
        }
        apr_pool_destroy(ptemp);
        return CPARSER_OK; 
    } else {
        if (!url_string_ptr || !*url_string_ptr) {
            return CPARSER_NOT_OK;
        }
        
        strncpy(str, *url_string_ptr, STR_LEN_MAX);
        
        rv = convert_access_list_set(URL_BLACK, UB_DYN_EXCEPT, str);
        switch (rv) {
        case CONV_OK:
            snprintf(buf, COMMAND_LEN_MAX, "dynamic except referrer-url %s", *url_string_ptr);
            admin_log_process(context, buf);
            break;
        case CONV_FAIL:
            cli_printf_info(context, "add dynamic except referrer-url failure\n");
            break;
        case CONV_CONFLICT:
            cli_printf_info(context, "add failure, dynamic except referrer-url has existed\n");
            break;
        case CONV_OVERFLOW:
            cli_printf_info(context, "add failure, dynamic except referrer-url num overflow\n");
            break;   
        default:
            break;
        }

        return CPARSER_OK; 
    }
} 

static cparser_result_t cfg_urlwhitelist_dynamic_except_no_cmd(cparser_context_t *context, 
                         int flag, char *url_string_ptr)
{
    char str[STR_LEN_MAX], buf[COMMAND_LEN_MAX];
    int rv;

    if (flag == 1) {
        snprintf(buf, COMMAND_LEN_MAX, "no dynamic except all");
        strncpy(str, KEYWORD_ALL, STR_LEN_MAX);
    } else {
        snprintf(buf, COMMAND_LEN_MAX, "no dynamic except referrer-url %s", url_string_ptr);
        strncpy(str, url_string_ptr, STR_LEN_MAX);
    }

    rv = convert_access_list_clear(URL_BLACK, UB_DYN_EXCEPT, str);
    switch (rv) {
    case CONV_OK:
        admin_log_process(context, buf);
        break;
    case CONV_FAIL:
        cli_printf_info(context, "clear dynamic except referrer-url failure\n");
        break;
    case CONV_NOTEXIST:
        cli_printf_info(context, "clear failure, the data isn't exist\n");
        break;
    default:
        break;
    }   

    return CPARSER_OK;    
}

cparser_result_t cparser_cmd_urlblack_no_dynamic_except_all(cparser_context_t *context)
{
    if (context == NULL) {
        return CPARSER_OK;
    }

    if (context->parser->mode != CPARSER_MODE_CONFIG) {        
        return CPARSER_OK;
    } else {
        return cfg_urlwhitelist_dynamic_except_no_cmd(context, 1, 0);
    }   
}

cparser_result_t cparser_cmd_urlblack_no_dynamic_except_referrer_url_url_string(cparser_context_t *context,
                    char **url_string_ptr)
{
    if (context == NULL) {
        return CPARSER_OK;
    }

    if (context->parser->mode != CPARSER_MODE_CONFIG) {        
        return CPARSER_OK;
    } else {
        if (!url_string_ptr || !*url_string_ptr) {
            return CPARSER_NOT_OK;
        }
        return cfg_urlwhitelist_dynamic_except_no_cmd(context, 0, *url_string_ptr);
    }   
}

cparser_result_t cparser_cmd_urlblack_dynamic_timeout_minutes(cparser_context_t *context,
                    uint32_t *minutes_ptr)
{
    char str[STR_LEN_MAX], buf[COMMAND_LEN_MAX];
    int rv, i;
    apr_pool_t *ptemp;
    apr_array_header_t *array;
    char **result;

    if (context == NULL) {
        return CPARSER_OK;
    }

    apr_pool_create(&ptemp, pbwlist); 
    apr_pool_tag(ptemp, "ptemp"); 
    
    if (context->parser->mode != CPARSER_MODE_CONFIG) {
        array = apr_array_make(ptemp, INIT_ARR_LEN, sizeof(char*));
        if (convert_access_list_show(URL_BLACK, UB_DYN_TIMEOUT, &array) == OK) {
            for (i = 0; i < array->nelts; i++) {
                result = (char **)(array->elts + (array->elt_size * i));
                if (context->parser->mode == CPARSER_MODE_WRITE) {
                    assert(context->parser->fp);
                    cli_fprintf(context, "dynamic timeout %s\n", *result);
                } else {
                    cli_printf(context, "dynamic timeout %s\n", *result);
                }    
            }
        }

        apr_pool_destroy(ptemp);
        return CPARSER_OK;
    } else {
        if (!minutes_ptr) {
            return CPARSER_NOT_OK;
        }

        if (*minutes_ptr < 1 || *minutes_ptr > 7200) {
            cli_printf_info(context, "dynamic timeout range is 1 to 7200 mimutes\n");
            return CPARSER_NOT_OK;
        }
        
        strncpy(str, apr_itoa(ptemp, *minutes_ptr), STR_LEN_MAX);

        rv = convert_access_list_set(URL_BLACK, UB_DYN_TIMEOUT, str);
        if (rv != OK) {
            cli_printf_info(context, "add dynamic timeout failure\n");
            apr_pool_destroy(ptemp);
            return CPARSER_NOT_OK;
        } else {
            snprintf(buf, COMMAND_LEN_MAX, "dynamic timeout %d", *minutes_ptr);
            admin_log_process(context, buf);
        }

        apr_pool_destroy(ptemp);
        return CPARSER_OK;
    }
}

cparser_result_t cparser_cmd_urlblack_no_dynamic_timeout(cparser_context_t *context)
{
    char str[STR_LEN_MAX], buf[COMMAND_LEN_MAX];
    apr_pool_t *ptemp;
    int rv;

    if (context == NULL) {
        return CPARSER_OK;
    }
    
    if (context->parser->mode != CPARSER_MODE_CONFIG) {
        return CPARSER_OK;
    } else {
        apr_pool_create(&ptemp, pbwlist); 
        apr_pool_tag(ptemp, "ptemp"); 
        
        /* 默认值为60分钟 */
        strncpy(str, apr_itoa(ptemp, DYN_BLIST_DEFAULT_TIMEOUT), STR_LEN_MAX);

        rv = convert_access_list_set(URL_BLACK, UB_DYN_TIMEOUT, str);
        if (rv != OK) {
            cli_printf_info(context, "add dynamic timeout failure\n");
            apr_pool_destroy(ptemp);
            return CPARSER_NOT_OK;
        } else {
            snprintf(buf, COMMAND_LEN_MAX, "no dynamic timeout");
            admin_log_process(context, buf);
        }
        
        apr_pool_destroy(ptemp);
        return CPARSER_OK;
    }
}

cparser_result_t cparser_cmd_urlblack_commit(cparser_context_t *context)
{
    int rv;
    apr_pool_t *ptemp;
    apr_array_header_t *url_array, *timeout_array, *except_array;
    char buf[COMMAND_LEN_MAX];

    if (context == NULL) {
        return CPARSER_OK;
    }
   
    if (context->parser->mode != CPARSER_MODE_CONFIG) {
        if (bw_flag->urlblack_commit_flag) {
            if (context->parser->mode == CPARSER_MODE_WRITE) {
                assert(context->parser->fp);
                cli_fprintf(context, "commit\n");
            } else {
                cli_printf(context,"commit\n");
            }  
        }
        return CPARSER_OK;
    } else {
        rv = ap_access_list_deploy(URL_BLACK);
        if (rv != OK) {
            cli_printf_info(context, "deploy url black list failure\n");
            BitClr(commit_status, URL_BLACK);
            return CPARSER_NOT_OK;
        } else {
            snprintf(buf, COMMAND_LEN_MAX, "commit");
            admin_log_process(context, buf);
            BitSet(commit_status, URL_BLACK);            
        }

        apr_pool_create(&ptemp, pbwlist); 
        apr_pool_tag(ptemp, "ptemp");

        url_array = apr_array_make(ptemp, INIT_ARR_LEN, sizeof(char*));
        timeout_array = apr_array_make(ptemp, INIT_ARR_LEN, sizeof(char*));
        except_array = apr_array_make(ptemp, INIT_ARR_LEN, sizeof(char*));

        convert_access_list_show(URL_BLACK, UB_URL_PLAIN, &url_array);
        convert_access_list_show(URL_BLACK, UB_URL_REGEX, &url_array);
        convert_access_list_show(URL_BLACK, UB_DYN_TIMEOUT, &timeout_array);
        convert_access_list_show(URL_BLACK, UB_DYN_EXCEPT, &except_array);

        if ((url_array->nelts == 0) && (timeout_array == 0) && (except_array == 0)) {
            bw_flag->urlblack_commit_flag = 0;
            bw_flag->urlblack_flag = 0;
            apr_pool_destroy(ptemp);
            return CPARSER_OK;
        }
        
        bw_flag->urlblack_commit_flag = 1;  
        apr_pool_destroy(ptemp);
        return CPARSER_OK;
    }
}

/**********************************************************************
 * 清除名单
 **********************************************************************/
/* clear waf ip-black-list */
static cparser_result_t exec_clear_ipblacklist_cmd(cparser_context_t *context, int flag, 
                         uint32_t ipaddr_ptr)
{
    int rv;
    char addr[ADDRTYPE_LEN], buf[COMMAND_LEN_MAX];
    struct in_addr in;
   
    if (flag == 1) {
        strncpy(addr, KEYWORD_ALL, ADDRTYPE_LEN);
        snprintf(buf, COMMAND_LEN_MAX, "clear ip-black-list dynamic all");
    } else {
        in.s_addr = ipaddr_ptr;
        sprintf(addr, "%d.%d.%d.%d", NIPQUAD(in.s_addr));
        snprintf(buf, COMMAND_LEN_MAX, "clear ip-black-list dynamic ip-address %s", addr);
    }

    rv = ap_dyn_blacklist_clear(IP_BLACK, addr);
    if (rv != OK) {
        cli_printf_info(context, "clear failure in ip black list\n");
        return CPARSER_NOT_OK;
    } else {
        admin_log_process(context, buf);
    }

    return CPARSER_OK;
}

/* clear waf url-black-list */
static cparser_result_t exec_clear_urlblacklist_cmd(cparser_context_t *context, int flag, 
                         char *url_string_ptr)
{
    int rv;
    char url[STR_LEN_MAX], buf[COMMAND_LEN_MAX];
    
    if (flag == 1) {
        strncpy(url, KEYWORD_ALL, STR_LEN_MAX);
        snprintf(buf, COMMAND_LEN_MAX, "clear url-black-list dynamic all");
    } else {
        strncpy(url, url_string_ptr, STR_LEN_MAX);
        snprintf(buf, COMMAND_LEN_MAX, "clear url-black-list dynamic referrer-url %s", url_string_ptr);
    }

    rv = ap_dyn_blacklist_clear(URL_BLACK, url);
    if (rv != OK) {
        cli_printf_info(context, "clear failure in url black list\n");
        return CPARSER_NOT_OK;
    } else {
        admin_log_process(context, buf);
    }

    return CPARSER_OK;
}

cparser_result_t cparser_cmd_st_clear_url_black_list_dynamic_all(cparser_context_t *context)
{
    if (context == NULL) {
        return CPARSER_OK;
    }

    if (context->parser->mode != CPARSER_MODE_CONFIG) {        
        return CPARSER_OK;
    } else {
        return exec_clear_urlblacklist_cmd(context, 1, 0);
    }   
}

cparser_result_t cparser_cmd_st_clear_url_black_list_dynamic_referrer_url_url_string(cparser_context_t *context,
                    char **url_string_ptr)
{
    if (context == NULL) {
        return CPARSER_OK;
    }

    if (context->parser->mode != CPARSER_MODE_CONFIG) {        
        return CPARSER_OK;
    } else {
        if (!url_string_ptr || !*url_string_ptr) {
            return CPARSER_NOT_OK;
        }
        return exec_clear_urlblacklist_cmd(context, 0, *url_string_ptr);
    }   
}

cparser_result_t cparser_cmd_st_clear_ip_black_list_dynamic_all(cparser_context_t *context)
{
    if (context == NULL) {
        return CPARSER_OK;
    }

    if (context->parser->mode != CPARSER_MODE_CONFIG) {        
        return CPARSER_OK;
    } else {
        return exec_clear_ipblacklist_cmd(context, 1, 0);
    } 
}

cparser_result_t cparser_cmd_st_clear_ip_black_list_dynamic_ip_address_ipaddr(cparser_context_t *context,
                    uint32_t *ipaddr_ptr)
{
    if (context == NULL) {
        return CPARSER_OK;
    }

    if (context->parser->mode != CPARSER_MODE_CONFIG) {        
        return CPARSER_OK;
    } else {
        if (!ipaddr_ptr) {
            return CPARSER_NOT_OK;
        }
        return exec_clear_ipblacklist_cmd(context, 0, *ipaddr_ptr);
    }   
}

cparser_result_t cparser_cmd_show_protect_engine_ip_white_list(cparser_context_t *context)
{
    int i;
    apr_pool_t *ptemp;
    apr_array_header_t *array;
    char **result;
    char buf[COMMAND_LEN_MAX];

    if (context == NULL) {
        return CPARSER_OK;
    }

    if (context->parser->mode != CPARSER_MODE_CONFIG) {        
        return CPARSER_OK;
    } else {
        apr_pool_create(&ptemp, pbwlist); 
        apr_pool_tag(ptemp, "ptemp");
        
        array = apr_array_make(ptemp, INIT_ARR_LEN, sizeof(char*));
        
        cli_printf_info(context, "-----------------------------------------------------------\n");
        cli_printf_info(context, "Client IP white list as follows:\n");
        cli_printf_info(context, " No.    IP-Address\n");
        if (convert_access_list_show(IP_WHITE, IW_CLIENT_IP, &array) == OK) {
            for (i = 0; i < array->nelts; i++) {
                result = (char **)(array->elts + (array->elt_size * i));
                cli_printf_info(context, " %-3d    %s\n", (i + 1), *result);
            }
        }

        apr_array_clear(array);
        cli_printf_info(context, "Server IP white list as follows:\n");
        cli_printf_info(context, " No.    IP-Address\n");
        if (convert_access_list_show(IP_WHITE, IW_SERVER_IP, &array) == OK) {
            for (i = 0; i < array->nelts; i++) {
                result = (char **)(array->elts + (array->elt_size * i));
                cli_printf_info(context, " %-3d    %s\n", (i + 1), *result);
            }
        }

        apr_array_clear(array);
        cli_printf_info(context, "Server host white list as follows:\n");
        cli_printf_info(context, " No.    Host\n");
        if (convert_access_list_show(IP_WHITE, IW_SERVER_HOST, &array) == OK) {
            for (i = 0; i < array->nelts; i++) {
                result = (char **)(array->elts + (array->elt_size * i));
                cli_printf_info(context, " %-3d    %s\n", (i + 1), *result);
            }
        }

        cli_printf_info(context, "Commit status: %s\n", BitGet(commit_status, IP_WHITE) ? "Succ" : "Fail");
        
        apr_pool_destroy(ptemp);

        snprintf(buf, COMMAND_LEN_MAX, "show protect-engine ip-white-list");
        admin_log_process(context, buf);
        
        return CPARSER_OK;
    }
}

cparser_result_t cparser_cmd_show_protect_engine_ip_black_list(cparser_context_t *context)
{
    int i;
    apr_pool_t *ptemp;
    apr_array_header_t *array;
    char **str;
    dyn_blist_show_str_t **result;
    char buf[COMMAND_LEN_MAX];

    if (context == NULL) {
        return CPARSER_OK;
    }

    if (context->parser->mode != CPARSER_MODE_CONFIG) {        
        return CPARSER_OK;
    } else {
        apr_pool_create(&ptemp, pbwlist); 
        apr_pool_tag(ptemp, "ptemp");
        
        array = apr_array_make(ptemp, INIT_ARR_LEN, sizeof(char*));
        
        apr_array_clear(array);
        cli_printf_info(context, "-----------------------------------------------------------\n");
        cli_printf_info(context, "Client IP black list as follows:\n");
        cli_printf_info(context, " No.    IP-Address\n");
        if (convert_access_list_show(IP_BLACK, IB_CLIENT_IP, &array) == OK) {
            for (i = 0; i < array->nelts; i++) {
                str = (char **)(array->elts + (array->elt_size * i));
                cli_printf_info(context, " %-3d    %s\n", (i + 1), *str);
            }
        }

        apr_array_clear(array);
        cli_printf_info(context, "Dynamic except client IP black list as follows:\n");
        cli_printf_info(context, " No.    IP-Address\n");
        if (convert_access_list_show(IP_BLACK, IB_DYN_EXCEPT, &array) == OK) {
            for (i = 0; i < array->nelts; i++) {
                str = (char **)(array->elts + (array->elt_size * i));
                cli_printf_info(context, " %-3d    %s\n", (i + 1), *str);
            }
        }

        apr_array_clear(array);
        cli_printf_info(context, "Dynamic client ip timeout: ");
        if (convert_access_list_show(IP_BLACK, IB_DYN_TIMEOUT, &array) == OK) {
            if (array->nelts != 0) {
                for (i = 0; i < array->nelts; i++) {
                    str = (char **)(array->elts + (array->elt_size * i));
                    cli_printf_info(context, "%s (Min)\n", *str);
                }                   
            } else {
                cli_printf_info(context, "%d (Min)\n", DYN_BLIST_DEFAULT_TIMEOUT);
            }
        }

        cli_printf_info(context, "Dynamic client ip black list as follows:\n");
        cli_printf_info(context, " No.    Start-Time                  "
            "End-Time                    IP-Address     \n");
        int (*fn) (int lst, apr_array_header_t **result);
        fn = APR_RETRIEVE_OPTIONAL_FN(dyn_access_list_show);
        if (fn) {
            apr_array_clear(array);
            fn(IP_BLACK, &array);
            for (i = 0; i < array->nelts; i++) {
                result = (dyn_blist_show_str_t **)(array->elts + (array->elt_size * i));
                cli_printf_info(context, " %-3d    %-24s    %-24s    %-15s\n", i + 1, 
                    (*result)->start_time, (*result)->end_time, (*result)->str);
            }
        }

        cli_printf_info(context, "Commit status: %s\n", BitGet(commit_status, IP_BLACK) ? "Succ" : "Fail");
        
        apr_pool_destroy(ptemp);
        snprintf(buf, COMMAND_LEN_MAX, "show protect-engine ip-black-list");
        admin_log_process(context, buf);
        return CPARSER_OK;
    }
}

cparser_result_t cparser_cmd_show_protect_engine_url_white_list(cparser_context_t *context)
{
    int i, j;
    apr_pool_t *ptemp;
    apr_array_header_t *array, *array_regex;
    char **result;
    char buf[COMMAND_LEN_MAX];

    if (context == NULL) {
        return CPARSER_OK;
    }

    if (context->parser->mode != CPARSER_MODE_CONFIG) {        
        return CPARSER_OK;
    } else {
        apr_pool_create(&ptemp, pbwlist); 
        apr_pool_tag(ptemp, "ptemp");
              
        array = apr_array_make(ptemp, INIT_ARR_LEN, sizeof(char*));
        array_regex = apr_array_make(ptemp, INIT_ARR_LEN, sizeof(char*));
        
        cli_printf_info(context, "-----------------------------------------------------------\n");
        cli_printf_info(context, "URL white list as follows:\n");
        cli_printf_info(context, " No.    Type           URL\n");
        if (convert_access_list_show(URL_WHITE, UW_URL_PLAIN, &array) == OK 
            && convert_access_list_show(URL_WHITE, UW_URL_REGEX, &array_regex) == OK) {
            for (i = 0; i < array->nelts; i++) {
                result = (char **)(array->elts + (array->elt_size * i));
                cli_printf_info(context, " %-3d    %-11s    %s\n", (i + 1), 
                    "Plain-Text", *result);
            }

            for (j = 0; j < array_regex->nelts; j++) {
                result = (char **)(array_regex->elts + (array_regex->elt_size * j));
                cli_printf_info(context, " %-3d    %-11s    %s\n", (j + i + 1), 
                    "Regular-Exp", *result);
            }
        }
        
        cli_printf_info(context, "Commit status: %s\n", BitGet(commit_status, URL_WHITE) ? "Succ" : "Fail");
        
        apr_pool_destroy(ptemp);

        snprintf(buf, COMMAND_LEN_MAX, "show protect-engine url-white-list");
        admin_log_process(context, buf);
        return CPARSER_OK;
    }
}

cparser_result_t cparser_cmd_show_protect_engine_url_black_list(cparser_context_t *context)
{
    int i, j;
    apr_pool_t *ptemp;
    apr_array_header_t *array, *array_regex;
    dyn_blist_show_str_t **result;
    char **str;
    char buf[COMMAND_LEN_MAX];

    if (context == NULL) {
        return CPARSER_OK;
    }
    
    if (context->parser->mode != CPARSER_MODE_CONFIG) {        
        return CPARSER_OK;
    } else {
        apr_pool_create(&ptemp, pbwlist); 
        apr_pool_tag(ptemp, "ptemp");

        array = apr_array_make(ptemp, INIT_ARR_LEN, sizeof(char*));
        array_regex = apr_array_make(ptemp, INIT_ARR_LEN, sizeof(char*));
        
        cli_printf_info(context, "-----------------------------------------------------------\n");
        cli_printf_info(context, "URL black list as follows:\n");
        cli_printf_info(context, " No.    Type           URL\n"); 
        if (convert_access_list_show(URL_BLACK, UB_URL_PLAIN, &array) == OK
            && convert_access_list_show(URL_BLACK, UB_URL_REGEX, &array_regex) == OK) {      
            for (i = 0; i < array->nelts; i++) {
                str = (char **)(array->elts + (array->elt_size * i));
                cli_printf_info(context, " %-3d    %-11s    %s\n", (i + 1), 
                    "Plain-Text", *str);
            }
            for (j = 0; j < array_regex->nelts; j++) {
                str = (char **)(array_regex->elts + (array_regex->elt_size * j));
                cli_printf_info(context, " %-3d    %-11s    %s\n", (j + i + 1), 
                    "Regular-Exp", *str);
            }
        }

        apr_array_clear(array);
        cli_printf_info(context, "Dynamic except Referrer-URL black list as follows:\n");
        cli_printf_info(context, " No.    URL\n");
        if (convert_access_list_show(URL_BLACK, UB_DYN_EXCEPT, &array) == OK) {
            for (i = 0; i < array->nelts; i++) {
                str = (char **)(array->elts + (array->elt_size * i));
                cli_printf_info(context, " %-3d    %s\n", (i + 1), *str);
            }
        }
        
        apr_array_clear(array);
        cli_printf_info(context, "Dynamic Referrer-URL timeout: ");
        if (convert_access_list_show(URL_BLACK, UB_DYN_TIMEOUT, &array) == OK) {
            if (array->nelts == 0) {
                cli_printf_info(context, "%d (Min)\n", DYN_BLIST_DEFAULT_TIMEOUT);
            } else {
                for (i = 0; i < array->nelts; i++) {
                    str = (char **)(array->elts + (array->elt_size * i));
                    cli_printf_info(context, " %s (Min)\n", *str);
                }
            }
        }

        cli_printf_info(context, "Dynamic Referrer-URL black list as follows:\n");
        cli_printf_info(context, " No.    Start-Time                  "
            "End-Time                    URL\n");
        int (*fn)(int lst, apr_array_header_t **result);
        fn = APR_RETRIEVE_OPTIONAL_FN(dyn_access_list_show);
        if (fn) {
            apr_array_clear(array);
            fn(URL_BLACK, &array);
            for (i = 0; i < array->nelts; i++) {
                result = (dyn_blist_show_str_t **)(array->elts + (array->elt_size * i));
                cli_printf_info(context, " %-3d    %-24s    %-24s    %s\n", (i + 1), 
                    (*result)->start_time, (*result)->end_time, (*result)->str);
            }
        }

        cli_printf_info(context, "Commit status: %s\n", BitGet(commit_status, URL_BLACK) ? "Succ" : "Fail");
        
        apr_pool_destroy(ptemp);

        snprintf(buf, COMMAND_LEN_MAX, "show protect-engine url-black-list");
        admin_log_process(context, buf);
        return CPARSER_OK;
    }
}

