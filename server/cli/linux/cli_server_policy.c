/*
 * $Id: cli_server_policy.c 2786 2013-07-09 16:42:55 FreeWAF Development Team $
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
#include <sys/stat.h>
#include "cparser.h"
#include "cparser_priv.h"
#include "cparser_token.h"
#include "global_root.h"
#include "cparser_show_tree.h"
#include "cparser_tree.h"
#include "ap_config.h"
#include "convert_rule.h"
#include "cli_common.h"
#include "pe_cli.h"

extern cparser_node_t cparser_node_st_configure_root_protect_engine_server_policy_serpname_eol;

static apr_pool_t *pserv = NULL;                /* Pool for server policy stuff */
static apr_hash_t *server_policy_table = NULL;
static char g_servername[NAME_LEN_MAX] = {0};
static char *cache_root_dir;

/**********************************************************
 * CLI无关函数
 **********************************************************/
static apr_status_t reload_server_policy_table(void *baton)
{
    server_policy_table = NULL;
    
    return APR_SUCCESS;
}

static void rebuild_server_policy_table(apr_pool_t *p)
{
    server_policy_table = apr_hash_make(p);

    apr_pool_cleanup_register(p, NULL, reload_server_policy_table, apr_pool_cleanup_null);
}

/**
 * 服务器策略子模块初始化
 */
AP_DECLARE(int) server_policy_init(apr_pool_t *p, apr_pool_t *ptrans)
{
    int rv;

    /* 服务器策略模块使用单独的持久内存池 */
    rv = apr_pool_create(&pserv, p);
    if (rv) {
        return DECLINED;
    }

    rebuild_server_policy_table(pserv);

    cache_root_dir = ap_server_root_relative(pserv, "cache/");

    return OK;
}

static server_policy_t *find_server_policy(const char *name)
{
    server_policy_t *sp;
    char strbuf[STR_LEN_MAX];

    if (!server_policy_table) {
        return NULL;
    }

    strcpy(strbuf, name);
    ap_str_tolower(strbuf);

    sp = NULL;
    sp = apr_hash_get(server_policy_table, strbuf, APR_HASH_KEY_STRING);

    return sp;
}

/**
 * 创建临时的服务器策略，存储在pserv内存池
 * 返回被创建的服务器策略。
 */
static server_policy_t *add_server_policy(cparser_context_t *context, const char *name, int dft)
{
    char *key;
    apr_pool_t *pserver;
    server_policy_t *sp;

    if (!name) {
        return NULL;
    }

    if (!server_policy_table) {
        rebuild_server_policy_table(pserv);
    }

    sp = find_server_policy(name);
    if (sp != NULL) {
        ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, ap_main_server,
                     "found server-policy %s", sp->name);
        return sp;
    }

    if (apr_hash_count(server_policy_table) >= SERVER_PLCY_LIMIT) {
        cli_printf_info(context, "server policy is full, you must remove or replace!\n");
        return NULL;
    }

    /* 创建服务器策略子池，每个服务器策略存储在单独的池子里 */
    apr_pool_create(&pserver, pserv);
    apr_pool_tag(pserver, "pserver");

    sp = (server_policy_t *)apr_pcalloc(pserver, sizeof(server_policy_t));
    sp->pool = pserver;
    sp->pvhost = NULL;
    strcpy(sp->name, name);
    sp->server = NULL;
    sp->is_default = dft;
    sp->work_mode = ap_work_mode;
    sp->opt_flags = 0;
    sp->sec_policy = NULL;
    sp->virt_host = NULL;
    sp->orig_host = NULL;
    sp->commit_status = 0;
    if (sp->work_mode != WORK_OFFLINE) {
        sp->engine = BLOCK_ON;
    } else {
        sp->engine = BLOCK_DET;
    }
    sp->audit_set = 0;
    sp->audit_log = 0;
    sp->atlog_lev = DEFAULT_ATTACK_LEVEL;
    BitSet(sp->audit_log, ACCESS_LOG);
    BitSet(sp->audit_log, ATTACK_LOG);
    sp->cache_root = apr_pstrcat(sp->pool, cache_root_dir, name, NULL);
    sp->argument_separator = ARGUMENT_SEPARATOR_DEFAULT;
    sp->cookie_format = VERSION_0;
    
    /* 保存服务器策略指针到哈希表 */
    key = apr_pstrdup(pserver, name);
    ap_str_tolower(key);
    apr_hash_set(server_policy_table, key, APR_HASH_KEY_STRING, sp);

    return sp;
}

/**
 * 删除服务器策略
 * 找到服务器策略节点，删除哈希表入口并释放内存池。
 */
static int del_server_policy(const char *name)
{
    server_policy_t *sp;
    char strbuf[STR_LEN_MAX];

    if (!name) {
        return DECLINED;
    }

    if (!server_policy_table) {
        return DECLINED;
    }

    strcpy(strbuf, name);
    ap_str_tolower(strbuf);
    sp = apr_hash_get(server_policy_table, strbuf, APR_HASH_KEY_STRING);
    if (sp == NULL) {
        return DONE;
    }

    apr_hash_set(server_policy_table, strbuf, APR_HASH_KEY_STRING, NULL);
    apr_pool_destroy(sp->pool);

    ap_server_policy_remove(name);

    return OK;
}

AP_DECLARE(int) clear_server_policy(void)
{
    int rv;
    char *key;
    apr_ssize_t klen;
    apr_hash_index_t *hi;
    server_policy_t *sp;
    
    if (server_policy_table && (apr_hash_count(server_policy_table) > 0)) {
        for (hi = apr_hash_first(NULL, server_policy_table); hi; hi = apr_hash_next(hi)) {
            apr_hash_this(hi, (void *)&key, &klen, (void *)&sp);
            apr_hash_set(server_policy_table, key, klen, NULL);
            if (sp) {
                apr_pool_destroy(sp->pool);
            }
        }
    }
    
    rv = ap_server_policy_clear();

    return rv;
}

/* 查找服务器策略中的虚拟主机地址 */
static virt_host_t *find_virt_host(struct in_addr addr, char *hostname, int port, int proto,
                      server_policy_t *serplcy, int is_delete)
{
    virt_host_t *vhost;
    char sername[DOMAIN_LEN_MAX];

    if (!serplcy) {
        return NULL;
    }

    if (!serplcy->virt_host) {
        return NULL;
    }

    memset(sername, 0, DOMAIN_LEN_MAX);
    if (hostname) {
        snprintf(sername, DOMAIN_LEN_MAX, "%s", hostname);
    }
    
    for (vhost = serplcy->virt_host->next; vhost; vhost = vhost->next) {
        if (addr.s_addr == vhost->ipaddr.s_addr && !strcmp(vhost->server_name, sername)) {
            if (is_delete) {
                /* 删除虚拟主机的时候，需要按指定的协议去删除 */
                if (proto == vhost->proto) {
                    if ((proto == PROTO_HTTP && port == vhost->phttp)
                        || (proto == PROTO_HTTPS && port == vhost->phttps)) {
                        return vhost;
                    }
                }
            } else {
                /* 增加虚拟主机的时候，不管协议如何，只需要ip和端口号相同，直接修改、覆盖 */
                if (port == vhost->phttp || port == vhost->phttps) {
                    return vhost;
                }
            }
        }
    }

    return NULL;
}

/* 添加服务器策略中的虚拟主机地址 */
static virt_host_t *add_virt_host(server_policy_t *serplcy)
{
    apr_pool_t *pvirt;
    virt_host_t *vhost;

    if (!serplcy) {
        return NULL;
    }

    apr_pool_create(&pvirt, serplcy->pool);
    apr_pool_tag(pvirt, "pvirt");
    vhost = (virt_host_t *)apr_pcalloc(pvirt, sizeof(virt_host_t));
    vhost->pool = pvirt;
    vhost->prev = NULL;
    vhost->next = NULL;
    vhost->ipaddr.s_addr = 0;
    vhost->phttp = 0;
    vhost->phttps = 0;
    vhost->server_name[0] = '\0';

    if (serplcy->virt_host) {
        vhost->next = serplcy->virt_host->next;
        serplcy->virt_host->next = vhost;
        vhost->prev = serplcy->virt_host;
        if (vhost->next) {
            vhost->next->prev = vhost;
        }
    } else {
        /* 第一个节点是链表头 */
        serplcy->virt_host = vhost;
    }

    return vhost;
}

/* 删除服务器策略中的虚拟主机地址 */
static int del_virt_host(cparser_context_t *context, struct in_addr addr, char *hostname, 
               int port, int proto, server_policy_t *serplcy)
{
    virt_host_t *vhost;

    if (!serplcy) {
        return DECLINED;
    }

    vhost = find_virt_host(addr, hostname, port, proto, serplcy, 1);
    if (vhost) {
        vhost->prev->next = vhost->next;
        if (vhost->next) {
            vhost->next->prev = vhost->prev;
        }
        apr_pool_destroy(vhost->pool);
        return OK;
    } else {
        if (proto == PROTO_HTTP) {
            cli_printf_info(context, "The ip-address %d.%d.%d.%d http %d is not exist!\n", 
                NIPQUAD(addr.s_addr), port);
        } else {
            cli_printf_info(context, "The ip-address %d.%d.%d.%d https %d is not exist!\n", 
                NIPQUAD(addr.s_addr), port);
        }
        return DECLINED;
    }
}

/* 删除服务器策略中所有的虚拟主机地址 */
static int clear_virt_host(server_policy_t *serplcy)
{
    virt_host_t *vhost;
    virt_host_t *nvhost;

    if (!serplcy) {
        return DECLINED;
    }

    for (vhost = serplcy->virt_host->next; vhost; vhost = nvhost) {
        nvhost = vhost->next;
        apr_pool_destroy(vhost->pool);
    }
    serplcy->virt_host->next = NULL;

    return OK;
}

/* 检查虚拟主机的IP地址端口是否也被其他服务器策略使用 */
static int check_host_addr(virt_host_t *cur_host, server_policy_t *sp)
{
    int rv;
    virt_host_t *vhost;
    server_policy_t *serplcy;
    apr_hash_index_t *hi;
    
    rv = FALSE;
    if (!cur_host || !sp) {
        return rv;
    }
    
    if (apr_hash_count(server_policy_table) < 1) {
        return rv;
    }

    for (hi = apr_hash_first(NULL, server_policy_table); hi; hi = apr_hash_next(hi)) {
        apr_hash_this(hi, NULL, NULL, (void *)&serplcy);
        if (!serplcy) {
            continue;
        }

        /* 跳过自己所在的服务器策略 */
        if (!strcmp(sp->name, serplcy->name)) {
            continue;
        }

        /* 排除运行模式不同的服务器策略 */
        if (sp->work_mode != serplcy->work_mode) {
            continue;
        }

        if (!serplcy->virt_host) {
            continue;
        }

        for (vhost = serplcy->virt_host->next; vhost; vhost = vhost->next) {
            if (cur_host->ipaddr.s_addr != vhost->ipaddr.s_addr) {
                continue;
            }

            if (strcmp(cur_host->server_name, vhost->server_name) != 0) {
                continue;
            }
            
            if ((cur_host->phttp)  
                && ((cur_host->phttp == vhost->phttp) || (cur_host->phttp == vhost->phttps))) {
                rv = TRUE;
                break;
            }
            if ((cur_host->phttps) 
                && ((cur_host->phttps == vhost->phttps) || (cur_host->phttps == vhost->phttp))) {
                rv = TRUE;
                break;
            }
        }

        if (rv == TRUE) {
            break;
        }
    }

    return rv;
}

/**********************************************************
 * CLI相关函数
 **********************************************************/
/* server-policy模式命令处理函数 */
cparser_result_t cparser_cmd_pe_protect_engine_server_policy_serpname(cparser_context_t *context,
                    char **serpname_ptr)
{
    server_policy_t *cur_serplcy;
    char prompt[CPARSER_MAX_PROMPT], buf[COMMAND_LEN_MAX];
    server_policy_t *sp;
    apr_hash_index_t *hi;

    if (context == NULL) {
        return CPARSER_OK;
    }

    if (context->parser->mode != CPARSER_MODE_CONFIG) {
        if (apr_hash_count(server_policy_table) < 1) {
            return CPARSER_OK;
        }

        for (hi = apr_hash_first(NULL, server_policy_table); hi; hi = apr_hash_next(hi)) {           
            apr_hash_this(hi, NULL, NULL, (void *)&sp);
            if (!sp || (sp->work_mode != ap_work_mode)) {
                continue;
            }

            if (context->parser->mode == CPARSER_MODE_WRITE) {
                assert(context->parser->fp);
                cli_fprintf(context, "protect-engine server-policy %s\n", sp->name);
            } else {
                cli_printf(context, "!\n");
                cli_printf(context, "protect-engine server-policy %s\n", sp->name);
            }
            
            context->parser->root_level++;
            context->parser->root[context->parser->root_level] = context->parser->cur_node->children;
            cparser_walk(context->parser, cparser_running_conf_walker, NULL, sp->name);
            context->parser->cur_node = &cparser_node_st_configure_root_protect_engine_server_policy_serpname_eol;
            context->parser->root_level--; 
        }         

        return CPARSER_OK;
    } else {
        if (!serpname_ptr || !*serpname_ptr) {
            return CPARSER_NOT_OK;
        }

        /* 由于show命令中存在detail关键字，会和服务器策略名冲突，故约定不能创建detail服务器策略 */
        if (strcmp(*serpname_ptr, "detail") == 0) {
            cli_printf_info(context, "can not create detail server policy\n");
            return CPARSER_NOT_OK;
        }

        /* 由于show命令中约定用'--'做为空的意思，故不能创建名为'--' 的服务器策略 */
        if (strcmp(*serpname_ptr, "--") == 0) {
            cli_printf_info(context, "can not create -- server policy\n");
            return CPARSER_NOT_OK;
        }

        memset(g_servername, 0, NAME_LEN_MAX);
        strncpy(g_servername, *serpname_ptr, NAME_LEN_MAX - 1); 
        
        snprintf(prompt, CPARSER_MAX_PROMPT, "%s(server-policy)#", g_cli_prompt);  

        ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, ap_main_server,
                     "add server-policy %s", g_servername);

        if (!strlen(g_servername)) {
            return CPARSER_NOT_OK;
        }

        cur_serplcy = add_server_policy(context, g_servername, FALSE);
        if (!cur_serplcy) {
            cli_printf_info(context, "add server-policy %s failed!\n", g_servername);
            return CPARSER_NOT_OK;
        } else {
            snprintf(buf, COMMAND_LEN_MAX, "protect-engine server-policy %s", *serpname_ptr);
            admin_log_process(context, buf);
        }
        
        /* 只有服务器策略的工作模式符合当前的工作模式才可以 */
        if (cur_serplcy->work_mode == ap_work_mode) {
            if (!cur_serplcy->virt_host) {
                add_virt_host(cur_serplcy);
            }
                           
            return cparser_submode_enter(context->parser, g_servername, prompt);
        } else {
            cli_printf_info(context, "server-policy %s can not work in current work mode!\n", g_servername);
        }

        return CPARSER_OK;
    }   
}

/* 删除服务器策略 */
cparser_result_t cparser_cmd_pe_no_protect_engine_server_policy_serpname(cparser_context_t *context,
                    char **serpname_ptr)
{
    int rv;
    char buf[COMMAND_LEN_MAX];

    if (context == NULL) {
        return CPARSER_OK;
    }

    if (context->parser->mode != CPARSER_MODE_CONFIG) {
        return CPARSER_OK;
    } else {
        if (!serpname_ptr || !*serpname_ptr) {
            return CPARSER_NOT_OK;
        }

        ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, ap_main_server,
                     "delete server-policy %s", *serpname_ptr);

        if (!strlen(*serpname_ptr)) {
            return CPARSER_NOT_OK;
        }       
    
        rv = del_server_policy(*serpname_ptr);
        if (rv == DECLINED) {
            cli_printf_info(context, "can not delete server-policy %s!\n", *serpname_ptr);
        } else if (rv == DONE) {
            snprintf(buf, COMMAND_LEN_MAX, "no protect-engine server-policy %s", *serpname_ptr);
            admin_log_process(context, buf);
            cli_printf_info(context, "server-policy %s has been deleted!\n", *serpname_ptr);
        }

        return CPARSER_OK;
    }
}

/* commit命令处理函数 */
cparser_result_t cparser_cmd_sp_commit(cparser_context_t *context)
{
    int rv;
    char *sername;
    server_policy_t *cur_serplcy;
    char buf[COMMAND_LEN_MAX];

    if (context == NULL) {
        return CPARSER_OK;
    }

    sername = (char *)context->cookie[context->parser->root_level];
    cur_serplcy = find_server_policy(sername);
    if (cur_serplcy == NULL) {
        return CPARSER_NOT_OK;
    }

    if (context->parser->mode != CPARSER_MODE_CONFIG) {
        if (BitGet(cur_serplcy->opt_flags, COMMIT_FLAG)) {
            if (context->parser->mode == CPARSER_MODE_WRITE) {
                assert(context->parser->fp);
                cli_fprintf(context, "commit\n");
            } else {
                cli_printf(context, "commit\n");
            }
        }
        
        return CPARSER_OK;    
    } else {
        ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, ap_main_server,
                     "commit server-policy %s", cur_serplcy->name);
#if 0
        if (cur_serplcy->engine == BLOCK_DET) {
            /* 切换到在线仅检测模式要清除黑白名单 */
            rv = ap_dyn_blacklist_clear(IP_BLACK, "all");
            if (rv != OK) {
                cli_printf_info(context, "clear dynamic ip black list failure!\n");
                return DECLINED;
            }

            rv = ap_dyn_blacklist_clear(URL_BLACK, "all");
            if (rv != OK) {
                cli_printf_info(context, "clear dynamic in url black list failure!\n");
                return DECLINED;
            }
        }
#endif
        rv = ap_server_policy_deploy(cur_serplcy);
        if (rv != OK) {
            cli_printf_info(context, "commit server-policy failed!\n");
            cur_serplcy->commit_status = 0;
            return CPARSER_NOT_OK;
        } else {
            snprintf(buf, COMMAND_LEN_MAX, "commit");
            admin_log_process(context, buf);
            cur_serplcy->commit_status = 1;
        }
        BitSet(cur_serplcy->opt_flags, COMMIT_FLAG);

        return CPARSER_OK;
    }
}

/*deploy security命令处理函数 */
cparser_result_t cparser_cmd_sp_deploy_security_policy_secpname(cparser_context_t *context,
                    char **secpname_ptr)
{
    char *secpolicy;
    char *sername;
    sec_policy_list_t *scpl;
    server_policy_t *cur_serplcy;
    char buf[COMMAND_LEN_MAX];

    if (context == NULL) {
        return CPARSER_OK;
    }

    sername = (char *)context->cookie[context->parser->root_level];
    cur_serplcy = find_server_policy(sername);

    if (context->parser->mode != CPARSER_MODE_CONFIG) {
        if (!cur_serplcy) {
            return CPARSER_NOT_OK;
        }
        
        if (cur_serplcy && cur_serplcy->sec_policy) {
            if (strlen(cur_serplcy->sec_policy->name)) {
                if (context->parser->mode == CPARSER_MODE_WRITE) {
                    assert(context->parser->fp);
                    cli_fprintf(context, "deploy security-policy %s\n", cur_serplcy->sec_policy->name);
                } else {
                    cli_printf(context, "deploy security-policy %s\n", cur_serplcy->sec_policy->name);
                }
            }
        }
        
        return CPARSER_OK;
    } else {
        if (!secpname_ptr || !*secpname_ptr) {
            return CPARSER_NOT_OK;
        }
        
        secpolicy = *secpname_ptr;
        if (!cur_serplcy) {
            cli_printf_info(context, "no server policy for security-policy in current!\n");
            return CPARSER_NOT_OK;
        }
        
        /* 查找安全策略，找不到则返回错误 */
        scpl = ap_secpolicy_list_find(*secpname_ptr);
        if (scpl == NULL) {
            cli_printf_info(context, "can not find sec_policy %s!\n", *secpname_ptr);
            return CPARSER_OK;
        }

        if (!strcmp(secpolicy, DEFAULT_POLICY)) {
            snprintf(buf, COMMAND_LEN_MAX, "deploy security-policy %s", secpolicy);
            admin_log_process(context, buf);
            ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, ap_main_server, "deploy default security-policy");
            if (!cur_serplcy->sec_policy) {
                cur_serplcy->sec_policy = (sec_policy_t *)apr_pcalloc(cur_serplcy->pool,
                                                                      sizeof(sec_policy_t));
            }
            strncpy(cur_serplcy->sec_policy->name, DEFAULT_POLICY, NAME_LEN_MAX);
        } else if (strlen(secpolicy)) {
            snprintf(buf, COMMAND_LEN_MAX, "deploy security-policy %s", secpolicy);
            admin_log_process(context, buf);
            ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, ap_main_server, "deploy security-policy %s", secpolicy);
            if (!cur_serplcy->sec_policy) {
                cur_serplcy->sec_policy = (sec_policy_t *)apr_pcalloc(cur_serplcy->pool,
                                                                      sizeof(sec_policy_t));
            }
            strncpy(cur_serplcy->sec_policy->name, secpolicy, NAME_LEN_MAX);
        } else {
            cli_printf_info(context, "deploy security-policy failed!\n");
        }

        return CPARSER_OK;
    }
}

/* virt命令处理函数 */
static cparser_result_t waf_server_virt_ip_c2p_cmd(cparser_context_t *context)
{
    virt_host_t *vhost;
    server_policy_t *cur_serplcy;
    char ports[STR_LEN_MAX] = {0};
    char strbuf[STR_LEN_MAX] = {0};
    char *sername;

    sername = (char *)context->cookie[context->parser->root_level];
    cur_serplcy = find_server_policy(sername);
    if (!cur_serplcy) {
        return CPARSER_NOT_OK;
    }

    if (cur_serplcy->is_default) {
        return CPARSER_OK;
    }

    if (cur_serplcy->work_mode != WORK_REVERSE) {
        return CPARSER_NOT_OK;
    }

    if (cur_serplcy->virt_host && cur_serplcy->orig_host) {
        vhost = cur_serplcy->virt_host->next;
        if (vhost) {
            if (vhost->phttp) {
                sprintf(ports, "http %d ", vhost->phttp);
            }
            
            if (vhost->phttps) {
                sprintf(strbuf, "https %d ", vhost->phttps);
                strcat(ports, strbuf);
            }
            
            if (cur_serplcy->orig_host->ipaddr.s_addr) {
                sprintf(strbuf, "real-server ip-address %d.%d.%d.%d ",
                        NIPQUAD(cur_serplcy->orig_host->ipaddr.s_addr));
                strcat(ports, strbuf);
            }
            
            if (cur_serplcy->orig_host->proto == PROTO_HTTP) {
                sprintf(strbuf, "http %d ", cur_serplcy->orig_host->port);
                strcat(ports, strbuf);
            } else if (cur_serplcy->orig_host->proto == PROTO_HTTPS) {
                sprintf(strbuf, "https %d", cur_serplcy->orig_host->port);
                strcat(ports, strbuf);
            }

            if (vhost->ipaddr.s_addr) {
                if (context->parser->mode == CPARSER_MODE_WRITE) {
                    assert(context->parser->fp);
                    cli_fprintf(context, "virt-server ip-address %d.%d.%d.%d %s\n", NIPQUAD(vhost->ipaddr.s_addr), ports);
                } else {
                    cli_printf(context, "virt-server ip-address %d.%d.%d.%d %s\n", NIPQUAD(vhost->ipaddr.s_addr), ports);
                }
            }
        }
    }   
   
    return CPARSER_OK;
}

static cparser_result_t waf_server_virt_ip_cmd(cparser_context_t *context, enum req_proto proto,
                            uint32_t vipaddr_ptr, uint32_t vport, 
                            uint32_t ripaddr_ptr, uint32_t rport)
{
    apr_pool_t *porig;
    struct in_addr ipaddr;
    virt_host_t *vhost;
    server_policy_t *cur_serplcy;
    char *sername;
    char buf[COMMAND_LEN_MAX];

    sername = (char *)context->cookie[context->parser->root_level];
    cur_serplcy = find_server_policy(sername);

    if (!cur_serplcy) {
        cli_printf_info(context, "no server policy for virt-server in current!\n");
        return CPARSER_OK;
    }

    if (cur_serplcy->is_default) {
        cli_printf_info(context, "can not configure virt-server in default server policy!\n");
        return CPARSER_OK;
    }

    if (cur_serplcy->work_mode != WORK_REVERSE) {
        cli_printf_info(context, "can not configure virt-server in this work mode!\n");
        return CPARSER_OK;
    }

    /* 反向代理需要创建后端原始服务器配置 */
    if (!cur_serplcy->orig_host) {
        apr_pool_create(&porig, cur_serplcy->pool);
        apr_pool_tag(porig, "porig");
        cur_serplcy->orig_host = (orig_host_t *)apr_pcalloc(porig, sizeof(orig_host_t));
        cur_serplcy->orig_host->pool = porig;
        cur_serplcy->orig_host->ipaddr.s_addr = 0;
        cur_serplcy->orig_host->proto = 0;
        cur_serplcy->orig_host->port = 0;
    }

    /* 添加或替换原来的ip地址 */
    ipaddr.s_addr = vipaddr_ptr;
    if (!vipaddr_ptr) {   
        cli_printf_info(context, "must use a specific virt-server ip-address!\n");
        return CPARSER_NOT_OK;
    }

    if (!ripaddr_ptr) {
        cli_printf_info(context, "must use a specific real-server ip-address!\n");
        return CPARSER_NOT_OK;
    }

    vhost = cur_serplcy->virt_host->next;
    if (!vhost) {
        vhost = add_virt_host(cur_serplcy);
        if (!vhost) {
            cli_printf_info(context, "can not add ip-address!\n");
            return CPARSER_NOT_OK;
        }
    }

    /* 设置虚拟主机和后台服务器的地址端口 */
    vhost->ipaddr.s_addr = ipaddr.s_addr;
    vhost->proto = proto;
    cur_serplcy->orig_host->ipaddr.s_addr = ripaddr_ptr;   
    switch (proto) {
    case PROTO_HTTP:
        vhost->phttp = vport;
        vhost->phttps = 0;
        cur_serplcy->orig_host->port = rport;
        cur_serplcy->orig_host->proto = PROTO_HTTP;
        snprintf(buf, COMMAND_LEN_MAX, "virt-sever ip-address %d.%d.%d.%d http %d real-server ip-address %d.%d.%d.%d http %d", 
            NIPQUAD(vipaddr_ptr), vport,  NIPQUAD(ripaddr_ptr), rport);
        ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, ap_main_server,
                 "virt-server ip-address %d.%d.%d.%d http %d "
                 "real-server ip-address %d.%d.%d.%d http %d",
                 NIPQUAD(vipaddr_ptr), vport,
                 NIPQUAD(ripaddr_ptr), rport);
        break;
    case PROTO_HTTPS:
        vhost->phttp = 0;
        vhost->phttps = vport;
        cur_serplcy->orig_host->port = rport;
        cur_serplcy->orig_host->proto = PROTO_HTTPS;
        snprintf(buf, COMMAND_LEN_MAX, "virt-sever ip-address %d.%d.%d.%d https %d real-server ip-address %d.%d.%d.%d https %d", 
            NIPQUAD(vipaddr_ptr), vport,  NIPQUAD(ripaddr_ptr), rport);
        ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, ap_main_server,
                 "virt-server ip-address %d.%d.%d.%d https %d "
                 "real-server ip-address %d.%d.%d.%d https %d",
                 NIPQUAD(vipaddr_ptr), vport,
                 NIPQUAD(ripaddr_ptr), rport);
        break;
    default:
        break;
    }

    if (check_host_addr(vhost, cur_serplcy) == TRUE) {
        cli_printf_info(context, "ip-address is already in other server policy!\n");
    }

    admin_log_process(context, buf);
    return CPARSER_OK;
}

cparser_result_t cparser_cmd_sp_virt_server_ip_address_virt_ipaddr_http_virt_httpport_real_server_ip_address_real_ipaddr_http_real_httpport(cparser_context_t *context,
                            uint32_t *virt_ipaddr_ptr, uint32_t *virt_httpport_ptr, 
                            uint32_t *real_ipaddr_ptr, uint32_t *real_httpport_ptr)
{
    if (context == NULL) {
        return CPARSER_OK;
    }
    
    if (context->parser->mode != CPARSER_MODE_CONFIG) { 
        return waf_server_virt_ip_c2p_cmd(context);
    } else {
        if (!virt_ipaddr_ptr || !virt_httpport_ptr || !real_ipaddr_ptr || !real_httpport_ptr) {
            return CPARSER_NOT_OK;
        }
        
        if (!PORT_IN_RANGE(*virt_httpport_ptr) || !PORT_IN_RANGE(*real_httpport_ptr)
                || *virt_httpport_ptr == 443 || *real_httpport_ptr == 443) {
            cli_printf_info(context, "Invalid port, the range must be 1~65535, and can not be 443!\n");
            return CPARSER_NOT_OK;
        }
        
        return waf_server_virt_ip_cmd(context, PROTO_HTTP, *virt_ipaddr_ptr, *virt_httpport_ptr, *real_ipaddr_ptr, *real_httpport_ptr);
    }
}

cparser_result_t cparser_cmd_sp_virt_server_ip_address_virt_ipaddr_https_virt_httpsport_real_server_ip_address_real_ipaddr_https_real_httpsport(cparser_context_t *context,
                    uint32_t *virt_ipaddr_ptr, uint32_t *virt_httpsport_ptr, 
                    uint32_t *real_ipaddr_ptr, uint32_t *real_httpsport_ptr)
{
    if (context == NULL) {
        return CPARSER_OK;
    }
    
    if (context->parser->mode != CPARSER_MODE_CONFIG) { 
        return CPARSER_OK;
    } else {
        if (!virt_ipaddr_ptr || !virt_httpsport_ptr || !real_ipaddr_ptr || !real_httpsport_ptr ) {
            return CPARSER_NOT_OK;
        }   
        
        if (!PORT_IN_RANGE(*virt_httpsport_ptr) || !PORT_IN_RANGE(*real_httpsport_ptr)
                || *virt_httpsport_ptr == 80 || *real_httpsport_ptr == 80) {
            cli_printf_info(context, "Invalid port, the range must be 1~65535, and can not be 80!\n");
            return CPARSER_NOT_OK;
        }    
        
        return waf_server_virt_ip_cmd(context, PROTO_HTTPS, *virt_ipaddr_ptr, *virt_httpsport_ptr, *real_ipaddr_ptr, *real_httpsport_ptr);
    }          
}

static cparser_result_t waf_server_virt_ip_no_cmd(cparser_context_t *context, enum req_proto proto, 
                        uint32_t ipaddr_ptr, int port)
{
    server_policy_t *cur_serplcy;
    char *sername;
    struct in_addr addr;
    char buf[COMMAND_LEN_MAX];

    sername = (char *)context->cookie[context->parser->root_level];
    cur_serplcy = find_server_policy(sername);
    if (!cur_serplcy) {
        cli_printf_info(context, "no server policy for virt-server in current!\n");
        return CPARSER_NOT_OK;
    }

    if (cur_serplcy->is_default) {
        cli_printf_info(context, "can not configure virt-server in default server policy!\n");
        return CPARSER_NOT_OK;
    } 

    if (cur_serplcy->work_mode != WORK_REVERSE) {
        cli_printf_info(context, "can not configure virt-server in this work mode!\n");
        return CPARSER_NOT_OK;
    }

    addr.s_addr = ipaddr_ptr;
    if (!find_virt_host(addr, NULL, port, proto, cur_serplcy, 1)) {
        if (proto == PROTO_HTTP) {
            cli_printf_info(context, "The ip-address %d.%d.%d.%d http %d is not exist!\n", 
                NIPQUAD(addr.s_addr), port);
        } else {
            cli_printf_info(context, "The ip-address %d.%d.%d.%d https %d is not exist!\n", 
                NIPQUAD(addr.s_addr), port);
        }
        return CPARSER_NOT_OK;
    }

    if (cur_serplcy->virt_host) {
        clear_virt_host(cur_serplcy);
    }

    if (cur_serplcy->orig_host) {
        apr_pool_destroy(cur_serplcy->orig_host->pool);
        cur_serplcy->orig_host = NULL;
    }

    switch (proto) {
    case PROTO_HTTP:
        snprintf(buf, COMMAND_LEN_MAX, "no virt-sever ip-address %d.%d.%d.%d http %d", 
            NIPQUAD(ipaddr_ptr), port);
        break;
    case PROTO_HTTPS:
        snprintf(buf, COMMAND_LEN_MAX, "no virt-sever ip-address %d.%d.%d.%d https %d",
            NIPQUAD(ipaddr_ptr), port);
    }
    
    admin_log_process(context, buf);
    ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, ap_main_server, "delete virt-server");
    
    return CPARSER_OK;
}

cparser_result_t cparser_cmd_sp_no_virt_server_ip_address_ipaddr_http_port(cparser_context_t *context,
                    uint32_t *ipaddr_ptr, uint32_t *port_ptr)
{
    if (context == NULL) {
        return CPARSER_OK;
    }

    if (context->parser->mode != CPARSER_MODE_CONFIG) { 
        return CPARSER_OK;
    } else {
        if (!ipaddr_ptr || !port_ptr) {
            return CPARSER_NOT_OK;
        }
        
        if (!PORT_IN_RANGE(*port_ptr) || *port_ptr == 443) {
            cli_printf_info(context, "Invalid port, the range must be 1~65535, and can not be 443!\n");
            return CPARSER_NOT_OK;
        }  
        
        return waf_server_virt_ip_no_cmd(context, PROTO_HTTP, *ipaddr_ptr, *port_ptr);
    }  
}

cparser_result_t cparser_cmd_sp_no_virt_server_ip_address_ipaddr_https_port(cparser_context_t *context,
                    uint32_t *ipaddr_ptr, uint32_t *port_ptr)
{
    if (context == NULL) {
        return CPARSER_OK;
    }

    if (context->parser->mode != CPARSER_MODE_CONFIG) { 
        return CPARSER_OK;
    } else {
        if (!ipaddr_ptr || !port_ptr) {
            return CPARSER_NOT_OK;
        }

        if (!PORT_IN_RANGE(*port_ptr) || *port_ptr == 80) {
            cli_printf_info(context, "Invalid port, the range must be 1~65535, and can not be 80!\n");
            return CPARSER_NOT_OK;
        }  
        
        return waf_server_virt_ip_no_cmd(context, PROTO_HTTPS, *ipaddr_ptr, *port_ptr);
    }
}

/* 校验当前的配置参数是否符合默认服务器策略的配置条件 */
static int check_default_config(uint32_t ipaddr_int, char *hostname, uint32_t port)
{
    if (ipaddr_int == 0 && hostname == NULL && port == 0) {
        return 1;
    }

    return 0;
}

static void mark_default_serpolicy(server_policy_t *serplcy, int isdef)
{
    serplcy->is_default = isdef;
}

static server_policy_t *get_default_serpolicy(ap_proxy_mode_t cur_workmode)
{
    server_policy_t *serplcy;
    apr_hash_index_t *hi;
    
    if (apr_hash_count(server_policy_table) < 1) {
        return NULL;
    }
    
    for (hi = apr_hash_first(NULL, server_policy_table); hi; hi = apr_hash_next(hi)) {
        apr_hash_this(hi, NULL, NULL, (void *)&serplcy);
        if (!serplcy) {
            continue;
        }

        /* 排除运行模式不同的服务器策略 */
        if (serplcy->work_mode != cur_workmode) {
            continue;
        }

        if (serplcy->is_default) {
            return serplcy;
        }
    }

    return NULL;    
}

/* real命令处理函数 */
static cparser_result_t waf_server_real_ip_cmd(cparser_context_t *context, uint32_t ipaddr_int, 
                            char *hostname, int proto, uint32_t port)
{
    struct in_addr ipaddr;
    virt_host_t *vhost;
    server_policy_t *cur_serplcy;
    char *sername;
    char buf[COMMAND_LEN_MAX];
    char temp[COMMAND_LEN_MAX];
    int is_default_conf;
    server_policy_t *default_serpolicy;

    sername = (char *)context->cookie[context->parser->root_level];
    cur_serplcy = find_server_policy(sername);
    if (!cur_serplcy) {
        cli_printf_info(context, "no server policy for real-server in current!\n");
        return CPARSER_OK;
    }

    if (cur_serplcy->is_default) {
        cli_printf_info(context, "can not configure other real-server in default server policy!\n");
        return CPARSER_OK;
    }

    if (cur_serplcy->work_mode == WORK_REVERSE) {
        cli_printf_info(context, "can not configure real-server in reverse work mode!\n");
        return CPARSER_OK;
    } 

    /* 校验是否进行默认服务器策略配置 */    
    is_default_conf = check_default_config(ipaddr_int, hostname, port);
    if (is_default_conf) {
        /* 如果已经有其它默认服务器策略，就不能再配置成默认服务器策略了 */
        default_serpolicy = get_default_serpolicy(cur_serplcy->work_mode);
        if (default_serpolicy) {
            cli_printf_info(context, "you has configured a default server policy \"%s\"!\n", 
                default_serpolicy->name);
            return CPARSER_OK;
        }
        
        /* 如果服务器策略已经配置了其它的服务器,也不能再配置成默认服务器策略了 */
        if (cur_serplcy->virt_host->next) {
            cli_printf_info(context, 
                "can not configure default real-server, current server policy has other real-server!\n");
            return CPARSER_OK;
        }   
        
        mark_default_serpolicy(cur_serplcy, 1);
    }

    if (!is_default_conf && !ipaddr_int) {
        /* 无效的ip地址 */
        cli_printf_info(context, "must use a specific real-server ip-address!\n");
        return CPARSER_OK;
    } 
    
    if (!is_default_conf && !PORT_IN_RANGE(port)) {
        /* 无效的端口 */
        cli_printf_info(context, "Invalid port, the range must be 1~65535!\n");
        return CPARSER_NOT_OK;
    }
   
    /* 添加或替换原来的ip地址、端口号 */
    ipaddr.s_addr = ipaddr_int;       
    vhost = find_virt_host(ipaddr, hostname, port, proto, cur_serplcy, 0);
    if (!vhost) {
        vhost = add_virt_host(cur_serplcy);
    }

    if (!vhost) {
        cli_printf_info(context, "can not add ip-address!\n");
        return CPARSER_NOT_OK;
    }

    /* 设置服务器名称和地址端口 */
    if (hostname) {
        strncpy(vhost->server_name, hostname, DOMAIN_LEN_MAX - 1);
        snprintf(buf, COMMAND_LEN_MAX, "real-server ip-address %d.%d.%d.%d host %s", 
            NIPQUAD(ipaddr_int), hostname);
    } else {
        snprintf(buf, COMMAND_LEN_MAX, "real-server ip-address %d.%d.%d.%d", 
            NIPQUAD(ipaddr_int));
    }
    
    vhost->ipaddr.s_addr = ipaddr.s_addr;
    vhost->proto = proto;
    if (proto == PROTO_HTTP) {
        vhost->phttp = port;
        snprintf(temp, COMMAND_LEN_MAX, " http %d", port);
        strcat(buf, temp);
    } else {
        vhost->phttp = 0;
    }
    
    if (proto == PROTO_HTTPS) {
        vhost->phttps = port;
        snprintf(temp, COMMAND_LEN_MAX, " https %d", port);
        strcat(buf, temp);
    } else {
        vhost->phttps = 0;
    }

    if (!is_default_conf && check_host_addr(vhost, cur_serplcy) == TRUE) {
        cli_printf_info(context, "ip-address is already in other server policy!\n");
        del_virt_host(context, ipaddr, hostname, port, proto, cur_serplcy);
        return CPARSER_OK;
    }
    
    if (!is_default_conf) {  
        ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, ap_main_server,
                 "real-server ip-address %d.%d.%d.%d host %s http %d https %d",
                 NIPQUAD(ipaddr_int), hostname , vhost->phttp, vhost->phttps);
    } else {
        ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, ap_main_server, "%s", buf);
    }
    
    admin_log_process(context, buf);   
    return CPARSER_OK;
}

static cparser_result_t waf_server_real_ip_c2p_cmd(cparser_context_t *context)
{
    virt_host_t *vhost;
    server_policy_t *cur_serplcy;
    char ports[STR_LEN_MAX];
    char strbuf[STR_LEN_MAX];
    char *sername;

    sername = (char *)context->cookie[context->parser->root_level];
    cur_serplcy = find_server_policy(sername);

    if (!cur_serplcy) {
        return CPARSER_OK;
    }

    if (cur_serplcy->is_default) {
        vhost = cur_serplcy->virt_host->next;
        if (vhost && vhost->proto == PROTO_HTTP) {
            snprintf(strbuf, STR_LEN_MAX, "real-server ip-address %d.%d.%d.%d http %d\n", 
                NIPQUAD(vhost->ipaddr.s_addr), vhost->phttp);
        } else if (vhost && vhost->proto == PROTO_HTTPS) {
            snprintf(strbuf, STR_LEN_MAX, "real-server ip-address %d.%d.%d.%d https %d\n", 
                NIPQUAD(vhost->ipaddr.s_addr), vhost->phttps);
        } else {
            return CPARSER_NOT_OK;
        }
        
        if (context->parser->mode == CPARSER_MODE_WRITE) {
            cli_fprintf(context, "%s", strbuf);
        } else {
            cli_printf(context, "%s", strbuf);
        }        
        return CPARSER_OK;
    }

    if (cur_serplcy->work_mode == WORK_REVERSE) {
        return CPARSER_OK;
    }

    for (vhost = cur_serplcy->virt_host->next; vhost; vhost = vhost->next) {
        ports[0] = '\0';
        strbuf[0] = '\0';
        
        if (strlen(vhost->server_name)) {
            sprintf(ports, "host %s ", vhost->server_name);
        }
        
        if (vhost->phttp) {
            sprintf(strbuf, "http %d ", vhost->phttp);
            strcat(ports, strbuf);
        }
        
        if (vhost->phttps) {
            sprintf(strbuf, "https %d", vhost->phttps);
            strcat(ports, strbuf);
        }

        if (vhost->ipaddr.s_addr) {
            if (context->parser->mode == CPARSER_MODE_WRITE) {
                assert(context->parser->fp);
                cli_fprintf(context, "real-server ip-address %d.%d.%d.%d %s\n", NIPQUAD(vhost->ipaddr.s_addr), ports);
            } else {
                cli_printf(context, "real-server ip-address %d.%d.%d.%d %s\n", NIPQUAD(vhost->ipaddr.s_addr), ports);
            }
        }
    }

    return CPARSER_OK;
}

cparser_result_t cparser_cmd_sp_real_server_ip_address_ipaddr_host_hostname_http_httpport(cparser_context_t *context,
                    uint32_t *ipaddr_ptr, char **hostname_ptr, uint32_t *httpport_ptr)
{
    if (context == NULL) {
        return CPARSER_OK;
    }

    if (context->parser->mode != CPARSER_MODE_CONFIG) { 
        return CPARSER_OK;
    } else {
        if (!ipaddr_ptr || !hostname_ptr || !*hostname_ptr || !httpport_ptr) {
            return CPARSER_NOT_OK;          
        }

        if (!PORT_IN_RANGE(*httpport_ptr)) {
            cli_printf_info(context, "Invalid port, the range must be 1~65535!\n");
            return CPARSER_NOT_OK;
        }
        
        return waf_server_real_ip_cmd(context, *ipaddr_ptr, *hostname_ptr, PROTO_HTTP, *httpport_ptr);
    }
}

cparser_result_t cparser_cmd_sp_real_server_ip_address_ipaddr_host_hostname_https_httpsport(cparser_context_t *context,
                    uint32_t *ipaddr_ptr, char **hostname_ptr, uint32_t *httpsport_ptr)
{
    if (context == NULL) {
        return CPARSER_OK;
    }

    if (context->parser->mode != CPARSER_MODE_CONFIG) { 
        return CPARSER_OK;
    } else {
        if (!ipaddr_ptr || !hostname_ptr || !*hostname_ptr || !httpsport_ptr) {
            return CPARSER_NOT_OK;
        }
        
        if (!PORT_IN_RANGE(*httpsport_ptr)) {
            cli_printf_info(context, "Invalid port, the range must be 1~65535!\n");
            return CPARSER_NOT_OK;
        }
        
        return waf_server_real_ip_cmd(context, *ipaddr_ptr, *hostname_ptr, PROTO_HTTPS, *httpsport_ptr);
    }
}

cparser_result_t cparser_cmd_sp_real_server_ip_address_ipaddr_http_httpport(cparser_context_t *context,
                    uint32_t *ipaddr_ptr, uint32_t *httpport_ptr)
{
    if (context == NULL) {
        return CPARSER_OK;
    }
    
    if (context->parser->mode != CPARSER_MODE_CONFIG) { 
        return CPARSER_OK;
    } else {
        if (!ipaddr_ptr || !httpport_ptr) {
            return CPARSER_NOT_OK;
        }
       
        return waf_server_real_ip_cmd(context, *ipaddr_ptr, NULL, PROTO_HTTP, *httpport_ptr);
    }
}

cparser_result_t cparser_cmd_sp_real_server_ip_address_ipaddr_https_httpsport(cparser_context_t *context,
                    uint32_t *ipaddr_ptr, uint32_t *httpsport_ptr)
{
    if (context == NULL) {
        return CPARSER_OK;
    }

    if (context->parser->mode != CPARSER_MODE_CONFIG) { 
        return waf_server_real_ip_c2p_cmd(context);
    } else {
        if (!ipaddr_ptr || !httpsport_ptr) {
            return CPARSER_NOT_OK;
        }
 
        return waf_server_real_ip_cmd(context, *ipaddr_ptr, NULL, PROTO_HTTPS, *httpsport_ptr);
    }
}

static cparser_result_t waf_server_real_ip_no_cmd(cparser_context_t *context, enum req_proto proto, 
                        uint32_t ipaddr_int, char *hostname, uint32_t port)
{
    struct in_addr ipaddr;
    server_policy_t *cur_serplcy;
    char *sername;
    char buf[COMMAND_LEN_MAX];
    int is_defconf = 0;
    
    
    sername = (char *)context->cookie[context->parser->root_level];
    cur_serplcy = find_server_policy(sername);
    if (!cur_serplcy) {
        cli_printf_info(context, "no server policy for real-server in current!\n");
        return CPARSER_NOT_OK;
    }
    
    if (cur_serplcy->is_default) {
        is_defconf = check_default_config(ipaddr_int, hostname, port);
        if (!is_defconf) {
            /* 在默认服务器策略下不存在其他的虚拟主机配置 */
            cli_printf_info(context, "no this real-server in default server policy!\n");
            return CPARSER_NOT_OK;
        }
    }
    
    if (!is_defconf && !ipaddr_int) {
        /* 无效的ip地址 */
        cli_printf_info(context, "must use a specific real-server ip-address!\n");
        return CPARSER_OK;
    } 
    
    if (!is_defconf && !PORT_IN_RANGE(port)) {
        /* 无效的端口 */
        cli_printf_info(context, "Invalid port, the range must be 1~65535!\n");
        return CPARSER_NOT_OK;
    }
    
    if (cur_serplcy->work_mode == WORK_REVERSE) {
        cli_printf_info(context, "can not configure real-server in reverse work mode!\n");
        return CPARSER_NOT_OK;
    }

    ipaddr.s_addr = ipaddr_int;
    if (del_virt_host(context, ipaddr, hostname, port, proto, cur_serplcy) != OK) {
        return CPARSER_NOT_OK;
    }

    if (cur_serplcy->is_default) {
        /* 清除默认服务器策略标志 */
        mark_default_serpolicy(cur_serplcy, 0);
    }
    
    ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, ap_main_server, 
        "delete real-server ip-address %d.%d.%d.%d:%d", NIPQUAD(ipaddr_int), port);
    
    switch (proto) {
    case PROTO_HTTP:
        snprintf(buf, COMMAND_LEN_MAX, "no real-server ip-address %d.%d.%d.%d http %d", 
            NIPQUAD(ipaddr_int), port);
        break;
    case PROTO_HTTPS:
        snprintf(buf, COMMAND_LEN_MAX, "no real-server ip-address %d.%d.%d.%d https %d", 
            NIPQUAD(ipaddr_int), port);
        break;
    default:
        break;
    }

    admin_log_process(context, buf);
    return CPARSER_OK; 
}

cparser_result_t cparser_cmd_sp_no_real_server_ip_address_ipaddr_host_hostname_http_httpport(cparser_context_t *context,
                    uint32_t *ipaddr_ptr, char **hostname_ptr, uint32_t *httpport_ptr)
{
    if (context == NULL) {
        return CPARSER_OK;
    }

    if (context->parser->mode != CPARSER_MODE_CONFIG) { 
        return CPARSER_OK;
    } else {
        if (!ipaddr_ptr || !hostname_ptr || !*hostname_ptr || !httpport_ptr) {
            return CPARSER_NOT_OK;            
        }
      
        return waf_server_real_ip_no_cmd(context, PROTO_HTTP, *ipaddr_ptr, *hostname_ptr, *httpport_ptr);
    }
}

cparser_result_t cparser_cmd_sp_no_real_server_ip_address_ipaddr_host_hostname_https_httpport(cparser_context_t *context,
                    uint32_t *ipaddr_ptr, char **hostname_ptr, uint32_t *httpport_ptr)
{
    if (context == NULL) {
        return CPARSER_OK;
    }

    if (context->parser->mode != CPARSER_MODE_CONFIG) { 
        return CPARSER_OK;
    } else {
        if (!ipaddr_ptr || !hostname_ptr || !*hostname_ptr || !httpport_ptr) {
            return CPARSER_NOT_OK;            
        }
      
        return waf_server_real_ip_no_cmd(context, PROTO_HTTPS, *ipaddr_ptr, *hostname_ptr, *httpport_ptr);
    }
}

cparser_result_t cparser_cmd_sp_no_real_server_ip_address_ipaddr_http_httpport(cparser_context_t *context,
                    uint32_t *ipaddr_ptr, uint32_t *httpport_ptr)
{
    if (context == NULL) {
        return CPARSER_OK;
    }

    if (context->parser->mode != CPARSER_MODE_CONFIG) { 
        return CPARSER_OK;
    } else {
        if (!ipaddr_ptr || !httpport_ptr) {
            return CPARSER_NOT_OK;            
        }
    
        return waf_server_real_ip_no_cmd(context, PROTO_HTTP, *ipaddr_ptr, NULL, *httpport_ptr);
    }
}

cparser_result_t cparser_cmd_sp_no_real_server_ip_address_ipaddr_https_httpsport(cparser_context_t *context,
                    uint32_t *ipaddr_ptr, uint32_t *httpsport_ptr)
{
    if (context == NULL) {
        return CPARSER_OK;
    }

    if (context->parser->mode != CPARSER_MODE_CONFIG) { 
        return CPARSER_OK;
    } else {
        if (!ipaddr_ptr || !httpsport_ptr) {
            return CPARSER_NOT_OK;            
        }
      
        return waf_server_real_ip_no_cmd(context, PROTO_HTTPS, *ipaddr_ptr, NULL, *httpsport_ptr);
    }
}

/* 日志 */
cparser_result_t cparser_cmd_sp_access_log_enable(cparser_context_t *context)
{
    server_policy_t *cur_serplcy;
    char *sername;
    char buf[COMMAND_LEN_MAX];
    
    if (context == NULL) {
        return CPARSER_OK;
    }
    
    sername = (char *)context->cookie[context->parser->root_level];
    cur_serplcy = find_server_policy(sername);
    if (!cur_serplcy) {
        cli_printf_info(context, "no server policy for audit_log in current!\n");
        return CPARSER_NOT_OK;
    }

    if (context->parser->mode != CPARSER_MODE_CONFIG) {
        if (!cur_serplcy->audit_set) {
            return CPARSER_NOT_OK;
        }

        if (BitGet(cur_serplcy->audit_set, ACCESS_LOG)) {
            if (BitGet(cur_serplcy->audit_log, ACCESS_LOG)) {
                if (context->parser->mode == CPARSER_MODE_WRITE) {
                    assert(context->parser->fp);
                    cli_fprintf(context, "access-log enable\n");
                } else {
                    cli_printf(context, "access-log enable\n");
                }
            } 
#if 0
            else {
                if (context->parser->mode == CPARSER_MODE_WRITE) {
                    assert(context->parser->fp);
                    cli_fprintf(context, "no access_log enable\n");
                } else {
                    cli_printf(context, "no access_log enable\n");
                }
            }
#endif
        }
        
        return CPARSER_OK;
    } else {
        BitSet(cur_serplcy->audit_log, ACCESS_LOG);
        BitSet(cur_serplcy->audit_set, ACCESS_LOG);
        
        snprintf(buf, COMMAND_LEN_MAX, "access-log enable");
        admin_log_process(context, buf);
        return CPARSER_OK;
    }
}

cparser_result_t cparser_cmd_sp_no_access_log_enable(cparser_context_t *context)
{
    server_policy_t *cur_serplcy;
    char *sername;
    char buf[COMMAND_LEN_MAX];

    if (context == NULL) {
        return CPARSER_OK;
    }
    
    if (context->parser->mode != CPARSER_MODE_CONFIG) {       
        return CPARSER_OK;
    } else {   
        sername = (char *)context->cookie[context->parser->root_level];
        cur_serplcy = find_server_policy(sername);
        if (!cur_serplcy) {
            cli_printf_info(context, "no server policy for audit_log in current!\n");
            return CPARSER_NOT_OK;
        } 
        
        BitClr(cur_serplcy->audit_log, ACCESS_LOG);
        BitSet(cur_serplcy->audit_set, ACCESS_LOG);

        snprintf(buf, COMMAND_LEN_MAX, "no access-log enable");
        admin_log_process(context, buf);
        
        return CPARSER_OK;
    }
}

cparser_result_t cparser_cmd_sp_attack_log_enable(cparser_context_t *context)
{
    server_policy_t *cur_serplcy;
    char *sername;
    char buf[COMMAND_LEN_MAX];

    if (context == NULL) {
        return CPARSER_OK;
    }
    
    if (context->parser->mode != CPARSER_MODE_CONFIG) {
        return CPARSER_OK;
    } else {     
        sername = (char *)context->cookie[context->parser->root_level];
        cur_serplcy = find_server_policy(sername);
        if (!cur_serplcy) {
            cli_printf_info(context, "no server policy for audit_log in current!\n");
            return CPARSER_NOT_OK;
        }
        
        BitSet(cur_serplcy->audit_log, ATTACK_LOG);
        BitSet(cur_serplcy->audit_set, ATTACK_LOG);

        snprintf(buf, COMMAND_LEN_MAX, "attack-log enable");
        admin_log_process(context, buf);
        
        return CPARSER_OK; 
    }
}

cparser_result_t cparser_cmd_sp_attack_log_enable_severity_level(cparser_context_t *context,
                    uint32_t *level_ptr)
{
    server_policy_t *cur_serplcy;
    char *sername;
    char buf[COMMAND_LEN_MAX];

    if (context == NULL) {
        return CPARSER_OK;
    }
    
    sername = (char *)context->cookie[context->parser->root_level];
    cur_serplcy = find_server_policy(sername);
    if (!cur_serplcy) {
        cli_printf_info(context, "no server policy for audit_log in current!\n");
        return CPARSER_NOT_OK;
    }
    
    if (context->parser->mode != CPARSER_MODE_CONFIG) {
        if (BitGet(cur_serplcy->audit_set, ATTACK_LOG)) {
            if (BitGet(cur_serplcy->audit_log, ATTACK_LOG)) {
                if (context->parser->mode == CPARSER_MODE_WRITE) {
                    assert(context->parser->fp);
                    cli_fprintf(context, "attack-log enable severity %d\n", cur_serplcy->atlog_lev);
                } else {
                    cli_printf(context, "attack-log enable severity %d\n", cur_serplcy->atlog_lev);
                }
            } 
#if 0
            else {
                if (context->parser->mode == CPARSER_MODE_WRITE) {
                    assert(context->parser->fp);
                    cli_fprintf(context, "no attack_log enable\n");
                } else {
                    cli_printf(context, "no attack_log enable\n");
                }
            }
#endif
        }
        
        return CPARSER_OK;
    } else {          
        BitSet(cur_serplcy->audit_log, ATTACK_LOG);
        BitSet(cur_serplcy->audit_set, ATTACK_LOG);
        if (level_ptr) {
            if (*level_ptr < 0 || *level_ptr > 7) {
                cli_printf_info(context, "the attack level should be between 0 and 7!\n");
                return CPARSER_NOT_OK; 
            }           
            cur_serplcy->atlog_lev = *level_ptr;
            snprintf(buf, COMMAND_LEN_MAX, "attack-log enable severity %d", *level_ptr);
            admin_log_process(context, buf);
        } else {
            return CPARSER_NOT_OK; 
        }
        return CPARSER_OK; 
    }
}

cparser_result_t cparser_cmd_sp_no_attack_log_enable(cparser_context_t *context)
{
    server_policy_t *cur_serplcy;
    char *sername;
    char buf[COMMAND_LEN_MAX];

    if (context == NULL) {
        return CPARSER_OK;
    }
   
    if (context->parser->mode != CPARSER_MODE_CONFIG) {
        return CPARSER_OK;
    } else {
        sername = (char *)context->cookie[context->parser->root_level];
        cur_serplcy = find_server_policy(sername);
        if (!cur_serplcy) {
            cli_printf_info(context, "no server policy for audit_log in current!\n");
            return CPARSER_NOT_OK;
        } 
        
        BitClr(cur_serplcy->audit_log, ATTACK_LOG);
        BitSet(cur_serplcy->audit_set, ATTACK_LOG);
        cur_serplcy->atlog_lev = 5;

        snprintf(buf, COMMAND_LEN_MAX, "no attack-log enable");
        admin_log_process(context, buf);
        return CPARSER_OK;     
    }
}

/* advance模式命令处理函数 */
cparser_result_t cparser_cmd_sp_advanced_configure(cparser_context_t *context)
{
    server_policy_t *cur_serplcy;
    char *sername;
    char prompt[CPARSER_MAX_PROMPT], buf[COMMAND_LEN_MAX];
    
    if (context == NULL) {
        return CPARSER_OK;
    }

    sername = (char *)context->cookie[context->parser->root_level];
    cur_serplcy = find_server_policy(sername);
    if (!cur_serplcy) {
        return CPARSER_NOT_OK;
    }

    if (context->parser->mode != CPARSER_MODE_CONFIG) {
        if (BitGet(cur_serplcy->opt_flags, ADVANCE_FLAG)) {
            if (context->parser->mode == CPARSER_MODE_WRITE) {
                assert(context->parser->fp);
                cli_fprintf(context, "advanced-configure\n");
            } else {
                cli_printf(context, "advanced-configure\n");
            }
            
            context->parser->root_level++;
            context->parser->root[context->parser->root_level] = context->parser->cur_node->children;
            cparser_walk(context->parser, cparser_running_conf_walker, NULL, sername);
            context->parser->root_level--;
        }
        
        return CPARSER_OK;
    } else {
        BitSet(cur_serplcy->opt_flags, ADVANCE_FLAG);

        snprintf(buf, COMMAND_LEN_MAX, "advanced-configure");
        admin_log_process(context, buf);
        
        snprintf(prompt, CPARSER_MAX_PROMPT, "%s(advanced-configure)#", g_cli_prompt);
        return cparser_submode_enter(context->parser, sername, prompt);       
    }

    return CPARSER_OK;
}

cparser_result_t cparser_cmd_advance_argument_separator_character(cparser_context_t *context,
    char **character_ptr)
{
    char *sername;
    server_policy_t *cur_serplcy;
    char buf[COMMAND_LEN_MAX];

    if (context == NULL) {
        return CPARSER_OK;
    }
    
    sername = (char *)context->cookie[context->parser->root_level];
    cur_serplcy = find_server_policy(sername);
    
    if (context->parser->mode != CPARSER_MODE_CONFIG) {       
        if (!cur_serplcy || !BitGet(cur_serplcy->opt_flags, ARGUMENT_SEPARATOR_FLAG)) {
            return CPARSER_NOT_OK;
        }
        
        if (context->parser->mode == CPARSER_MODE_WRITE) {
            assert(context->parser->fp);
            cli_fprintf(context, "argument-separator %c\n", cur_serplcy->argument_separator);
        } else {
            cli_printf(context, "argument-separator %c\n", cur_serplcy->argument_separator);
        }
        
        return CPARSER_OK;
    } else {
        if (!character_ptr || !*character_ptr) {
            return CPARSER_NOT_OK;
        }
        if (!cur_serplcy) {
            cli_printf_info(context, "no server policy for engine in current!\n");
            return CPARSER_NOT_OK;
        }

        /* 分隔符长度只能为1 */
        if (strlen(*character_ptr) > 1) {
            cli_printf_info(context, "The argument separator length exceed 1!\n");
            return CPARSER_NOT_OK;
        }

        /* 分隔符的有效范围为1-127 */
        if (*(*character_ptr) < 1 || *(*character_ptr) > 127) {
            cli_printf_info(context, "The argument separator must be in the range of 1 to 127!\n");
            return CPARSER_NOT_OK; 
        }
        
        cur_serplcy->argument_separator = *(*character_ptr);
        BitSet(cur_serplcy->opt_flags, ARGUMENT_SEPARATOR_FLAG);

        ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, ap_main_server, 
            "set augument separator %s", *character_ptr);

        snprintf(buf, COMMAND_LEN_MAX, "argument-separator %s", *character_ptr);
        admin_log_process(context, buf);
        
        return CPARSER_OK;
    }   
}

cparser_result_t cparser_cmd_advance_no_argument_separator(cparser_context_t *context)
{
    char *sername;
    server_policy_t *cur_serplcy;
    char buf[COMMAND_LEN_MAX];

    if (context == NULL) {
        return CPARSER_OK;
    }
    
    sername = (char *)context->cookie[context->parser->root_level];
    cur_serplcy = find_server_policy(sername);
    
    if (context->parser->mode != CPARSER_MODE_CONFIG) {       
        return CPARSER_OK;
    } else {
        if (!cur_serplcy) {
            cli_printf_info(context, "no server policy for engine in current!\n");
            return CPARSER_NOT_OK;
        }

        cur_serplcy->argument_separator = ARGUMENT_SEPARATOR_DEFAULT;
        BitSet(cur_serplcy->opt_flags, ARGUMENT_SEPARATOR_FLAG);

        ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, ap_main_server, "no augument separator");

        snprintf(buf, COMMAND_LEN_MAX, "no argument-separator");
        admin_log_process(context, buf);
        
        return CPARSER_OK;
    }      
    return CPARSER_OK;
}

cparser_result_t cparser_cmd_advance_cookie_format_version(cparser_context_t *context,
    char **version_ptr)
{
    char *sername;
    server_policy_t *cur_serplcy;
    char buf[COMMAND_LEN_MAX];

    if (context == NULL) {
        return CPARSER_OK;
    }
    
    sername = (char *)context->cookie[context->parser->root_level];
    cur_serplcy = find_server_policy(sername);
    
    if (context->parser->mode != CPARSER_MODE_CONFIG) {       
        if (!cur_serplcy || !BitGet(cur_serplcy->opt_flags, COOKIE_FORMAT_FLAG)) {
            return CPARSER_NOT_OK;
        }
        
        if (context->parser->mode == CPARSER_MODE_WRITE) {
            assert(context->parser->fp);
            cli_fprintf(context, "cookie-format %s\n", 
                cur_serplcy->cookie_format ? "version-1" : "version-0");
        } else {
            cli_printf(context, "cookie-format %s\n", 
                cur_serplcy->cookie_format ? "version-1" : "version-0");
        }
        
        return CPARSER_OK;
    } else {
        if (!version_ptr || !*version_ptr) {
            return CPARSER_NOT_OK;
        }
        if (!cur_serplcy) {
            cli_printf_info(context, "no server policy for engine in current!\n");
            return CPARSER_NOT_OK;
        }

        if (strcmp(*version_ptr, "version-0") == 0) {
            cur_serplcy->cookie_format = VERSION_0;
        } else if (strcmp(*version_ptr, "version-1") == 0) {
            cur_serplcy->cookie_format = VERSION_1;
        } else {
            cli_printf_info(context, "cookie format error!\n");
            return CPARSER_NOT_OK;
        }
        
        BitSet(cur_serplcy->opt_flags, COOKIE_FORMAT_FLAG);

        ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, ap_main_server, 
            "set cookie format  %s", *version_ptr);

        snprintf(buf, COMMAND_LEN_MAX, "cookie-format %s", *version_ptr);
        admin_log_process(context, buf);
        
        return CPARSER_OK;
    }   
}

cparser_result_t cparser_cmd_advance_no_cookie_format(cparser_context_t *context)
{
    char *sername;
    server_policy_t *cur_serplcy;
    char buf[COMMAND_LEN_MAX];

    if (context == NULL) {
        return CPARSER_OK;
    }
    
    sername = (char *)context->cookie[context->parser->root_level];
    cur_serplcy = find_server_policy(sername);
    
    if (context->parser->mode != CPARSER_MODE_CONFIG) {       
        return CPARSER_OK;
    } else {
        if (!cur_serplcy) {
            cli_printf_info(context, "no server policy for engine in current!\n");
            return CPARSER_NOT_OK;
        }

        cur_serplcy->cookie_format = VERSION_0;
        
        BitSet(cur_serplcy->opt_flags, COOKIE_FORMAT_FLAG);

        ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, ap_main_server, 
            "no cookie format");

        snprintf(buf, COMMAND_LEN_MAX, "no cookie-format");
        admin_log_process(context, buf);
        
        return CPARSER_OK;
    }       
}

/* engine命令处理函数 */
cparser_result_t cparser_cmd_sp_engine_detect_type(cparser_context_t *context,
                    char **detect_type_ptr)
{
    char *sername;
    server_policy_t *cur_serplcy;
    char buf[COMMAND_LEN_MAX];
    
    if (context == NULL) {
        return CPARSER_OK;
    }

    sername = (char *)context->cookie[context->parser->root_level];
    cur_serplcy = find_server_policy(sername);

    if (context->parser->mode != CPARSER_MODE_CONFIG) {
        if (!cur_serplcy || !BitGet(cur_serplcy->opt_flags, ENGINE_FLAG)) {
            return CPARSER_NOT_OK;
        }

        if (cur_serplcy->engine == BLOCK_DET) {
            if (context->parser->mode == CPARSER_MODE_WRITE) {
                assert(context->parser->fp);
                cli_fprintf(context, "engine detect-only\n");
            } else {
                cli_printf(context, "engine detect-only\n");
            }
        } else if (cur_serplcy->engine == BLOCK_ON) {
            if (context->parser->mode == CPARSER_MODE_WRITE) {
                assert(context->parser->fp);
                cli_fprintf(context, "engine detect-block\n");
            } else {
                cli_printf(context, "engine detect-block\n");
            }
        } else if (cur_serplcy->engine == BLOCK_OFF) {
            if (context->parser->mode == CPARSER_MODE_WRITE) {
                assert(context->parser->fp);
                cli_fprintf(context, "engine detect-off\n");
            } else {
                cli_printf(context, "engine detect-off\n");
            }
        }

        return CPARSER_OK;
    } else {
        if (!detect_type_ptr || !*detect_type_ptr) {
            return CPARSER_NOT_OK;
        }
        
        if (!cur_serplcy) {
            cli_printf_info(context, "no server policy for engine in current!\n");
            return CPARSER_NOT_OK;
        }

        if (cur_serplcy->work_mode == WORK_OFFLINE) {
            cli_printf_info(context, "can not configure engine in this work mode!\n");
            return CPARSER_NOT_OK;
        }

        if (!strcmp(*detect_type_ptr, "detect-block")) {           
            cur_serplcy->engine = BLOCK_ON;
            BitSet(cur_serplcy->opt_flags, ENGINE_FLAG);
        } else if (!strcmp(*detect_type_ptr, "detect-only")){       
            cur_serplcy->engine = BLOCK_DET;
            BitSet(cur_serplcy->opt_flags, ENGINE_FLAG);
        }

        ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, ap_main_server, 
            "set server-policy engine %s", *detect_type_ptr);

        snprintf(buf, COMMAND_LEN_MAX, "engine %s", *detect_type_ptr);
        admin_log_process(context, buf);
        
        return CPARSER_OK;
    }
}

cparser_result_t cparser_cmd_sp_no_engine(cparser_context_t *context)
{
    server_policy_t *cur_serplcy;
    char *sername;
    char buf[COMMAND_LEN_MAX];

    if (context == NULL) {
        return CPARSER_OK;
    }

    if (context->parser->mode != CPARSER_MODE_CONFIG) {
        return CPARSER_OK;
    } else {
        sername = (char *)context->cookie[context->parser->root_level];
        cur_serplcy = find_server_policy(sername);
        
        if (!cur_serplcy) {
            cli_printf_info(context, "no server policy for engine in current!\n");
            return CPARSER_NOT_OK;
        }

        if (cur_serplcy->work_mode == WORK_OFFLINE) {
            cli_printf_info(context, "can not configure engine in this work mode!\n");
            return CPARSER_NOT_OK;
        }

        ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, ap_main_server,
                     "set server-policy engine default");
        
        if (cur_serplcy->work_mode != WORK_OFFLINE) {
            cur_serplcy->engine = BLOCK_ON;
        } else {
            cur_serplcy->engine = BLOCK_DET;
        }
        
        BitSet(cur_serplcy->opt_flags, ENGINE_FLAG);

        snprintf(buf, COMMAND_LEN_MAX, "no engine");
        admin_log_process(context, buf);

        return CPARSER_OK;
    }
}

/**********************************************************
 * show命令处理函数
 **********************************************************/
static int show_server_policy_detail(cparser_context_t *context, char *sername)
{
    virt_host_t *vhost;
    server_policy_t *sp;
    apr_hash_index_t *hi;
    int num;
    char ip[32];

    for (hi = apr_hash_first(NULL, server_policy_table); hi; hi = apr_hash_next(hi)) {
        apr_hash_this(hi, NULL, NULL, (void *)&sp);
        if (!sp) {
            continue;
        }

        if (!sername || !strcmp(sp->name, sername)) {
            cli_printf_info(context, "-----------------------------------------------------------------\n");
            cli_printf_info(context, "Server policy name: %s\n", sp->name);
            
            if (sp->engine == BLOCK_DET) {
                cli_printf_info(context, " Engine detect mode:  detect-only\n");
            } else if (sp->engine == BLOCK_ON) {
                cli_printf_info(context, " Engine detect mode:  detect-block\n");
            } else {
                cli_printf_info(context, " Engine detect mode:  detect-off\n");
            }

            if (sp->sec_policy) {
                cli_printf_info(context, " Deploy security policy name: %s\n", sp->sec_policy->name);
            } else {
                cli_printf_info(context, " Deploy security policy name: --\n");
            }
            
            if (sp->work_mode == WORK_REVERSE) {
                if (sp->virt_host) {
                    vhost = sp->virt_host->next;
                } else {
                    vhost = NULL;
                }
                cli_printf_info(context, " Virtual server configuration is as follows:\n");
                cli_printf_info(context, "  Virtual server:\n");
                
                if (vhost && vhost->ipaddr.s_addr) {
                    cli_printf_info(context, "   IP address: %d.%d.%d.%d\n", 
                        NIPQUAD(vhost->ipaddr.s_addr));
                } else {
                    cli_printf_info(context, "   IP address: --\n");
                }
                
                if (vhost && vhost->proto == PROTO_HTTP) {
                    cli_printf_info(context, "   Protocol:   http\n");
                    cli_printf_info(context, "   Port:       %d\n", vhost->phttp);
                } else if (vhost && vhost->proto == PROTO_HTTPS) {
                    cli_printf_info(context, "   Protocol:   https\n");
                    cli_printf_info(context, "   Port:       %d\n", vhost->phttps);
                } else {
                    cli_printf_info(context, "   Protocol:   --\n");
                    cli_printf_info(context, "   Port:       --\n");
                }

                cli_printf_info(context, "  Real server:\n");
                if (sp->orig_host && sp->orig_host->ipaddr.s_addr) {
                    cli_printf_info(context, "   IP address: %d.%d.%d.%d\n", 
                        NIPQUAD(sp->orig_host->ipaddr.s_addr));
                } else {
                    cli_printf_info(context, "   IP address: --\n");
                }
                
                if (sp->orig_host && sp->orig_host->proto == PROTO_HTTP) {
                    cli_printf_info(context, "   Protocol:   http\n");
                    cli_printf_info(context, "   Port:       %d\n", sp->orig_host->port);
                } else if (sp->orig_host && sp->orig_host->proto == PROTO_HTTPS) {
                    cli_printf_info(context, "   Protocol:   https\n");
                    cli_printf_info(context, "   Port:       %d\n", sp->orig_host->port);
                } else {
                    cli_printf_info(context, "   Protocol:   --\n");
                    cli_printf_info(context, "   Port:       --\n");
                }
            } else if (sp->work_mode != WORK_REVERSE) {     
                num = 0;
                cli_printf_info(context, " Real server configuration is as follows:\n");
                cli_printf_info(context, "  No.  IP-Address            Hostname             Protocol    Port\n");
                if (sp->virt_host && sp->virt_host->next) {
                    for (vhost = sp->virt_host->next; vhost; vhost = vhost->next) {
                        snprintf(ip, 32, "%d.%d.%d.%d", NIPQUAD(vhost->ipaddr.s_addr));
                        if (vhost->proto == PROTO_HTTP) {
                            cli_printf_info(context, "  %-3d  %-15s       %-15s      http        %d\n", 
                                ++num, ip, strlen(vhost->server_name) ? vhost->server_name: "--",
                                vhost->phttp);
                        } else if (vhost->proto == PROTO_HTTPS) {
                            cli_printf_info(context, "  %-3d  %-15s       %-15s      https       %d\n",
                                ++num, ip, strlen(vhost->server_name) ? vhost->server_name: "--", 
                                vhost->phttps);
                        }
                    }
                }
            }

            if (BitGet(sp->audit_log, ACCESS_LOG)) {
                 cli_printf_info(context, " Access log:          enable\n");
            } else {
                 cli_printf_info(context, " Access log:          disable\n");
            }
            
            cli_printf_info(context, " Attack log configuration is as follows:\n");
            if (BitGet(sp->audit_log, ATTACK_LOG)) {
                cli_printf_info(context, "  Status:             enable\n");
            } else {
                cli_printf_info(context, "  Status:             disable\n");
            } 
            cli_printf_info(context, "  Severity:           %d\n", sp->atlog_lev);

            cli_printf_info(context, " Advanced configuration is as follows:\n");  
            cli_printf_info(context, "  Argument separator: %c\n", sp->argument_separator);
            cli_printf_info(context, "  Cookie format:      %s\n", 
                sp->cookie_format ? "version-1" : "version-0");
            cli_printf_info(context, " Commit status: %s\n", sp->commit_status ? "Succ" : "Fail");
        }
    }

    return OK;
}

static int show_server_policy(cparser_context_t *context, char *sername)
{
    virt_host_t *vhost;
    server_policy_t *sp;
    apr_hash_index_t *hi;
    int num;
    char ip[32];

    for (hi = apr_hash_first(NULL, server_policy_table); hi; hi = apr_hash_next(hi)) {
        apr_hash_this(hi, NULL, NULL, (void *)&sp);
        if (!sp) {
            continue;
        }

        if (!sername || !strcmp(sp->name, sername)) {
            cli_printf_info(context, "-----------------------------------------------------------------\n");
            cli_printf_info(context, "Server policy name: %s\n", sp->name);
            
            if (BitGet(sp->opt_flags, ENGINE_FLAG)) {               
                if (sp->engine == BLOCK_DET) {
                    cli_printf_info(context, " Engine detect mode: detect-only\n");
                } else if (sp->engine == BLOCK_ON) {
                    cli_printf_info(context, " Engine detect mode: detect-block\n");
                } else {
                    cli_printf_info(context, " Engine detect mode: detect-off\n");
                }
            }
            
            if (sp->sec_policy) {
                cli_printf_info(context, " Deploy security policy name: %s\n", sp->sec_policy->name);
            }
            
            if (((sp->work_mode == WORK_REVERSE) && sp->virt_host) && sp->orig_host) {
                vhost = sp->virt_host->next;
                if (vhost) {
                    cli_printf_info(context, " Virtual server configuration is as follows:\n");
                    cli_printf_info(context, "  Virtual server:\n");
                    
                    if (vhost->ipaddr.s_addr) {
                        cli_printf_info(context, "   IP address: %d.%d.%d.%d\n", 
                            NIPQUAD(vhost->ipaddr.s_addr));
                    }
                    
                    if (vhost->proto == PROTO_HTTP) {
                        cli_printf_info(context, "   Protocol:   http\n");
                        cli_printf_info(context, "   Port:       %d\n", vhost->phttp);
                    } else if (vhost && vhost->proto == PROTO_HTTPS) {
                        cli_printf_info(context, "   Protocol:   https\n");
                        cli_printf_info(context, "   Port:       %d\n", vhost->phttps);
                    }
    
                    cli_printf_info(context, "  Real server:\n");
                    if (sp->orig_host->ipaddr.s_addr) {
                        cli_printf_info(context, "   IP address: %d.%d.%d.%d\n", 
                            NIPQUAD(sp->orig_host->ipaddr.s_addr));
                    }
                    if (sp->orig_host->proto == PROTO_HTTP) {
                        cli_printf_info(context, "   Protocol:   http\n");
                        cli_printf_info(context, "   Port:       %d\n", sp->orig_host->port);
                    } else if (sp->orig_host->proto == PROTO_HTTPS) {
                        cli_printf_info(context, "   Protocol:   https\n");
                        cli_printf_info(context, "   Port:       %d\n", sp->orig_host->port);
                    } 
                }
            } else if ((sp->work_mode != WORK_REVERSE) && sp->virt_host && sp->virt_host->next) {     
                num = 0;
                cli_printf_info(context, " Real server configuration is as follows:\n");
                cli_printf_info(context, "  No.  IP-Address            Hostname             Protocol    Port\n");
                for (vhost = sp->virt_host->next; vhost; vhost = vhost->next) {
                    snprintf(ip, 32, "%d.%d.%d.%d", NIPQUAD(vhost->ipaddr.s_addr));
                    if (vhost->proto == PROTO_HTTP) {
                        cli_printf_info(context, "  %-3d  %-15s       %-15s      http        %d\n", 
                            ++num, ip, strlen(vhost->server_name) ? vhost->server_name: "--",
                            vhost->phttp);
                    } else if (vhost->proto == PROTO_HTTPS) {
                        cli_printf_info(context, "  %-3d  %-15s       %-15s      https       %d\n",
                            ++num, ip, strlen(vhost->server_name) ? vhost->server_name: "--", 
                            vhost->phttps);
                    } else {
                        cli_printf_info(context, "   Protocol configure error!\n");
                        return DECLINED;
                    }
                }
            }

            if (BitGet(sp->audit_set, ACCESS_LOG)) {
                if (BitGet(sp->audit_log, ACCESS_LOG)) {
                     cli_printf_info(context, " Access log: enable\n");
                } else {
                     cli_printf_info(context, " Access log: disable\n");
                }
            }

            if (BitGet(sp->audit_set, ATTACK_LOG)) {
                cli_printf_info(context, " Attack log configuration is as follows:\n");
                if (BitGet(sp->audit_log, ATTACK_LOG)) {
                    cli_printf_info(context, "  Status:    enable\n");
                } else {
                    cli_printf_info(context, "  Status:    disable\n");
                } 
                cli_printf_info(context, "  Severity:  %d\n", sp->atlog_lev);
            }

            if (BitGet(sp->opt_flags, ADVANCE_FLAG)) {
                cli_printf_info(context, " Advanced configuration is as follows:\n");
            }
            
            if (BitGet(sp->opt_flags, ARGUMENT_SEPARATOR_FLAG)) {
                cli_printf_info(context, "  Argument separator: %c\n", sp->argument_separator);
            }

            if (BitGet(sp->opt_flags, COOKIE_FORMAT_FLAG)) {
                cli_printf_info(context, "  Cookie format:      %s\n", 
                    sp->cookie_format ? "version-1" : "version-0");
            }

            cli_printf_info(context, " Commit status: %s\n", sp->commit_status ? "Succ" : "Fail");
        }
    }

    return OK;
} 

cparser_result_t cparser_cmd_show_protect_engine_server_policy(cparser_context_t *context)
{
    char buf[COMMAND_LEN_MAX];
    
    if (context == NULL) {
        return CPARSER_OK;
    }
    
    if (context->parser->mode != CPARSER_MODE_CONFIG) {
        return CPARSER_OK;
    } else {       
        ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, ap_main_server, "show server-policy");

        /* 显示全部服务器策略,仅显示用户配置 */
        show_server_policy(context, NULL);
        snprintf(buf, COMMAND_LEN_MAX, "show protect-engine server-policy");                    
        admin_log_process(context, buf);
        return CPARSER_OK;
    }
}

cparser_result_t cparser_cmd_show_protect_engine_server_policy_detail(cparser_context_t *context)
{
    char buf[COMMAND_LEN_MAX];
        
    if (context == NULL) {
        return CPARSER_OK;
    }

    if (context->parser->mode != CPARSER_MODE_CONFIG) {
        return CPARSER_OK;
    } else {  
        ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, ap_main_server, "show server-policy detail");

        /* 显示全部服务器策略，用户配置、默认配置全部显示 */
        show_server_policy_detail(context, NULL);
        snprintf(buf, COMMAND_LEN_MAX, "show protect-engine server-policy detail");                    
        admin_log_process(context, buf);
        return CPARSER_OK;
    }    
}

cparser_result_t cparser_cmd_show_protect_engine_server_policy_spname(cparser_context_t *context,
    char **spname_ptr)
{
    char buf[COMMAND_LEN_MAX];
    
    if (context == NULL || spname_ptr == NULL || *spname_ptr == NULL) {
        return CPARSER_OK;
    }
    
    if (context->parser->mode != CPARSER_MODE_CONFIG) {
        return CPARSER_OK;
    } else {       
        ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, ap_main_server, "show server-policy %s", *spname_ptr);

        /* 显示指定的服务器策略，仅显示用户配置 */
        show_server_policy(context, *spname_ptr);
        snprintf(buf, COMMAND_LEN_MAX, "show protect-engine server-policy %s", *spname_ptr);                    
        admin_log_process(context, buf);
        return CPARSER_OK;
    }
}

cparser_result_t cparser_cmd_show_protect_engine_server_policy_spname_detail(cparser_context_t *context,
    char **spname_ptr)
{
    char buf[COMMAND_LEN_MAX];
    
    if (context == NULL || spname_ptr == NULL || *spname_ptr == NULL) {
        return CPARSER_OK;
    }

    if (context->parser->mode != CPARSER_MODE_CONFIG) {
        return CPARSER_OK;
    } else { 
        ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, ap_main_server, "show server-policy %s detail", *spname_ptr);

        /* 显示指定的服务器策略， 用户配置、默认配置全部显示 */
        show_server_policy_detail(context, *spname_ptr);
        snprintf(buf, COMMAND_LEN_MAX, "show protect-engine server-policy %s detail", *spname_ptr);                    
        admin_log_process(context, buf);        
        return CPARSER_OK;
    }
}

