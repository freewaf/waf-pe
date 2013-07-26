/*
 * $Id: engine_config.c 2786 2013-07-09 16:42:55 FreeWAF Development Team $
 *
 * (C) 2013-2014 FreeWAF Development Team
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
 
#define CORE_PRIVATE
#include <stdlib.h>
#include <string.h>
#include "apr_network_io.h"
#include "engine_config.h"
#include "convert_rule.h"
#include "http_config.h"
#include "cli_common.h"

#define SHOW_SECURITY_RULE  1      /* 显示安全规则的调试信息开关 */
static apr_pool_t *pcli = NULL;    /* cli内存池 */
static apr_pool_t *pconf = NULL;   /* conf内存池 */

/* 添加监听端口 */
AP_DECLARE(int) ap_listen_ports_alloc(void)
{
    listen_port_t *listen_port;
    const char *errmsg;
    char host[STR_LEN_MAX];

    listen_port = NULL;
    if (ap_listen_ports) {
        listen_port = ap_listen_ports->next;
    } else {
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, NULL, "no listening port");
        return DECLINED;
    }   

    while (listen_port && listen_port->port) {
        if (listen_port->create_mode != ap_work_mode) {
            listen_port = listen_port->next;
            continue;
        }
        
        if (listen_port->ipaddr.s_addr) {   
            sprintf(host, "%d.%d.%d.%d", NIPQUAD(listen_port->ipaddr.s_addr));
        } else {
            sprintf(host, "*");
        }

        if (listen_port->proto == PROTO_HTTP) {
            errmsg = ap_add_listener(ap_main_server, host,
                                     listen_port->port, "http");
            ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, NULL,
                         "add listener host %s port %d http", host, listen_port->port);
        } else if (listen_port->proto == PROTO_HTTPS) {
            errmsg = ap_add_listener(ap_main_server, host,
                                     listen_port->port, "https");
            ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, NULL,
                         "add listener host %s port %d https", host, listen_port->port);
        }
        
        if (errmsg) {
            ap_log_error(APLOG_MARK, APLOG_ERR, 0, NULL,
                         "add listener port %d error: %s",
                         listen_port->port, errmsg);
            return DECLINED;
        }
        listen_port = listen_port->next;
    }

    if (listen_port == ap_listen_ports->next) {
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, NULL,
                     "there is no listen port");
        return DONE;
    }

    return OK;
}

/* 添加桥 */
AP_DECLARE(int) ap_bridge_port_alloc()
{
    bridge_port_t *bridge_port;
    int rv;

    if (ap_work_mode != WORK_BRIDGE && ap_work_mode != WORK_ROUTE) {
        return OK;
    }

    bridge_port = NULL;
    if (ap_bridge_ports) {
        bridge_port = ap_bridge_ports->next;
    } 

    while (bridge_port) {
        if (ap_work_mode == WORK_BRIDGE) {
            /* 检测桥设备 */
            rv = interface_find(bridge_port->br_name);
            if (rv != OK) {
                ap_log_error(APLOG_MARK, APLOG_ERR, 0, NULL, 
                    "bridge %s do not exist!\n", bridge_port->br_name);
                return DECLINED;
            }
            
            /* 调用ebtables设置脚本 */
            if (!bridge_port->deploied && !bridge_port->deleted) {
                rv = create_ebtables_configure(bridge_port->br_name,
                    bridge_port->ser_port, bridge_port->tproxy_port);
                if (rv != 0) {
                    ap_log_error(APLOG_MARK, APLOG_ERR, 0, NULL, "create ebtables fail!");
                    (void)destroy_ebtables_configure(bridge_port->br_name, bridge_port->ser_port,
                        bridge_port->tproxy_port);
                    return DECLINED;
                }
                bridge_port->deploied = 1;
            }
        } else {
            /* 调用iptables设置脚本 */
            if (!bridge_port->deploied && !bridge_port->deleted) {
                rv = create_iptables_configure(bridge_port->ser_port, bridge_port->tproxy_port);
                if (rv != 0) {
                    ap_log_error(APLOG_MARK, APLOG_ERR, 0, NULL, "create iptables fail!\n");
                    (void)destroy_iptables_configure(bridge_port->ser_port, bridge_port->tproxy_port);
                    return DECLINED;
                }
                bridge_port->deploied = 1;
            }
        }

        bridge_port = bridge_port->next;
    }

    return OK;
}

/**********************************************************
 * 黑白名单相关的处理函数
 **********************************************************/
AP_DECLARE(int) ap_access_list_handle(int lst)
{
    apr_status_t rv;
    ap_directive_t *newdir;
    ap_directive_t *current;
    ap_directive_t *conftree;
    apr_array_header_t *acl_config;
    apr_pool_t *ptemp;
    char *cmd_name;
    const char **cmd_args;

    if ((lst < IP_BLACK) || (lst > ALL_LIST)) {
        return DECLINED;
    }

    /* 配置处理过程中的临时数据放在临时内存池里面 */
    apr_pool_create(&ptemp, pconf);
    apr_pool_tag(ptemp, "ptemp");

    /* 读取黑白名单的指令 */
    acl_config  = apr_array_make(ptemp, 1, sizeof(char *));
    rv = convert_access_list_query(lst, &acl_config);
    if (rv != OK) {
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, NULL,
                     "query access list %d error", lst);
        return DECLINED;
    }

    /* 建立一颗临时的配置树 */
    conftree = NULL;
    current = conftree;

    while (1) {
        cmd_args = (const char **)apr_array_pop(acl_config);
        if (!cmd_args) {
            break;
        }
        cmd_name = ap_getword_conf(ptemp, cmd_args);
        newdir = (ap_directive_t *)apr_pcalloc(ptemp, sizeof(ap_directive_t));
        newdir->filename = "access list";
        newdir->line_num = (current == NULL) ? 1 : (current->line_num + 1);
        newdir->directive = apr_pstrdup(ptemp, cmd_name);
        newdir->args = apr_pstrdup(ptemp, *cmd_args);
        current = ap_add_node(&conftree, current, newdir, 0);
        if (conftree == NULL && current != NULL) {
            conftree = current;
        }
    }

    /* 指令下发调试 */
    for (current = conftree; current != NULL; current = current->next) {
        ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, ap_main_server,
                     "%s: line[%d] directive[%s] args[%s]",
                     current->filename, current->line_num,
                     current->directive, current->args);
    }

    /* 处理黑白名单的指令 */
    if (conftree) {
        rv = ap_process_config_tree(ap_main_server, conftree,
                                    pconf, ptemp);
    }

    apr_pool_destroy(ptemp);

    return rv;
}

/**********************************************************
 * 服务器策略相关的处理函数
 **********************************************************/

/**
 * 哈希表统计
 */
static int count_hash(apr_hash_t *h)
{
    apr_hash_index_t *hi;
    char *key;
    apr_ssize_t klen;
    void *val;
    int cnt;

    for (cnt = 0, hi = apr_hash_first(NULL, h); hi; hi = apr_hash_next(hi)) {
        apr_hash_this(hi, (void *)&key, &klen, &val);
        ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, ap_main_server,
                     "hash: key[%s] klen[%u]",
                     key, (apr_uint32_t)klen);
        cnt++;
    }

    return cnt;
}

#if SHOW_SECURITY_RULE
static void conftree_traverse(ap_directive_t *curr_parent)
{
    ap_directive_t *newdir;
    ap_directive_t *nextdir;
    
    for (newdir = curr_parent; newdir != NULL; newdir = newdir->next) {
        ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, ap_main_server,
            "server policy %s: line[%d] directive[%s] args[%s]", newdir->filename, newdir->line_num,
            newdir->directive, newdir->args); 
        nextdir = newdir->first_child;
        if (nextdir != NULL) {
           conftree_traverse(nextdir); 
        }
    }
}
#endif

static int get_command_type(const char *command_name)
{
    if (command_name[0] == '<') {
        if (command_name[1] != '/') {
            return CONTAINER_COMMAND;           
        } else {
            return CLOSED_CONTAINER_COMMAND;
        }
    } else {
        return SINGLE_COMMAND;
    }
}

/* 处理安全策略和规则集的指令 */
static int process_security_rule(server_policy_t *sp, ap_directive_t *current,
            ap_directive_t *conftree, apr_pool_t *ptemp)
{
    apr_status_t rv;
    ap_directive_t *newdir;
    apr_array_header_t *secpolicy_config;
    int i;
    char *cmd_name, *bracket;
    const char *endp;
    int container_num, closed_container_num;
    const char **cmd_args;
    ap_directive_t *curr_parent = conftree;  

    /* 处理安全策略的指令 */
    secpolicy_config  = apr_array_make(ptemp, 1, sizeof(char *));
    rv = convert_sec_policy_query(sp->sec_policy->name, &secpolicy_config);
    if (rv != OK) {
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, NULL,
                     "query security policy %s error", sp->sec_policy->name);
        return DECLINED;
    }

    container_num = 0;
    closed_container_num = 0;
    for (i = 0; i < secpolicy_config->nelts; i ++) {
        cmd_args = (const char **)(secpolicy_config->elts + (secpolicy_config->elt_size * i));
        if (cmd_args) {
            cmd_name = ap_getword_conf(ptemp, cmd_args);
            switch (get_command_type(cmd_name)) {
            case CONTAINER_COMMAND:
                container_num = container_num + 1;
                newdir = (ap_directive_t *)apr_pcalloc(ptemp, sizeof(ap_directive_t));
                newdir->filename = sp->name; /* 使用服务器策略名字作为指令文件名 */
                newdir->line_num = (current == NULL) ? 1 : (current->line_num + 1);
                newdir->directive = apr_pstrdup(ptemp, cmd_name);
                newdir->args = apr_pstrdup(ptemp, *cmd_args);
                endp = ap_strrchr_c(newdir->args, '>');
                if (endp == NULL) {
                    ap_log_error(APLOG_MARK, APLOG_ERR, 0, NULL, "%s directive missing closing '>'", cmd_name);
                    return DECLINED;
                }
              
                current = ap_add_node(&curr_parent, current, newdir, 1);
                break;
                
            case CLOSED_CONTAINER_COMMAND:
                if (curr_parent == NULL) {
                    ap_log_error(APLOG_MARK, APLOG_ERR, 0, NULL, "no appear < container");
                    return DECLINED;
                }
                
                closed_container_num = closed_container_num + 1;      
                bracket = cmd_name + strlen(cmd_name) - 1;
                if (*bracket != '>') {
                    ap_log_error(APLOG_MARK, APLOG_ERR, 0, NULL, "%s directive missing closing '>'", cmd_name);
                    return DECLINED;
                }

                *bracket = '\0';
                if (strcasecmp(cmd_name + 2, curr_parent->directive + 1) != 0) {
                    ap_log_error(APLOG_MARK, APLOG_ERR, 0, NULL, "Expected </%s> but saw %s>", curr_parent->directive + 1, cmd_name + 2);
                    return DECLINED;
                }

                *bracket = '>';
                current = curr_parent;
                curr_parent = curr_parent->parent;
                break;
                
            case SINGLE_COMMAND:
                newdir = (ap_directive_t *)apr_pcalloc(ptemp, sizeof(ap_directive_t));
                newdir->filename = sp->name; /* 使用服务器策略名字作为指令文件名 */
                newdir->line_num = (current == NULL) ? 1 : (current->line_num + 1);
                newdir->directive = apr_pstrdup(ptemp, cmd_name);
                newdir->args = apr_pstrdup(ptemp, *cmd_args);
                current = ap_add_node(&curr_parent, current, newdir, 0);
                break;
                
            default:
                break;
            }
        }
    }

    if (container_num != closed_container_num) {
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, NULL, "< > container number not equal to </ > container number");
        return DECLINED;
    }

    return OK;
}

/* 处理每个服务器策略下的指令 */
static int process_server_policy(server_policy_t *sp,
                                 server_rec *server_conf, apr_pool_t *ptemp)
{
    apr_status_t rv;
    ap_directive_t *newdir;
    ap_directive_t *current;
    ap_directive_t *conftree;
    virt_host_t *vhost;
    int sname_set;
    char strbuf[STR_LEN_MAX];

    /* 每个服务器策略建立一颗临时的配置树 */
    conftree = NULL;
    current = NULL;

    /* 限制了当启用KeepAlive时，每个连接允许的请求数量。*/
    newdir = (ap_directive_t *)apr_pcalloc(ptemp, sizeof(ap_directive_t));
    newdir->filename = sp->name; /* 使用服务器策略名字作为指令文件名 */
    newdir->line_num = (current == NULL) ? 1 : (current->line_num + 1);
    newdir->directive = apr_pstrdup(ptemp, "MaxKeepAliveRequests");
    newdir->args = apr_pstrdup(ptemp, "500");
    current = ap_add_node(&conftree, current, newdir, 0);
    conftree = current;

    if (sp->work_mode == WORK_REVERSE) {
        /* 处理反向代理配置 */
        if (sp->orig_host->proto == PROTO_HTTPS) {
            sprintf(strbuf, "/ https://%d.%d.%d.%d:%d/",
                    NIPQUAD(sp->orig_host->ipaddr.s_addr), sp->orig_host->port);
        } else {
            sprintf(strbuf, "/ http://%d.%d.%d.%d:%d/",
                    NIPQUAD(sp->orig_host->ipaddr.s_addr), sp->orig_host->port);
        }
        ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, ap_main_server,
                     "backend host: %s", strbuf);

        newdir = (ap_directive_t *)apr_pcalloc(ptemp, sizeof(ap_directive_t));
        newdir->filename = sp->name; 
        newdir->line_num = (current == NULL) ? 1 : (current->line_num + 1);
        newdir->directive = apr_pstrdup(ptemp, "ProxyPass");
        newdir->args = apr_pstrdup(ptemp, strbuf);
        current = ap_add_node(&conftree, current, newdir, 0);

        newdir = (ap_directive_t *)apr_pcalloc(ptemp, sizeof(ap_directive_t));
        newdir->filename = sp->name;
        newdir->line_num = (current == NULL) ? 1 : (current->line_num + 1);
        newdir->directive = apr_pstrdup(ptemp, "ProxyPassReverse");
        newdir->args = apr_pstrdup(ptemp, strbuf);
        current = ap_add_node(&conftree, current, newdir, 0);
    } else if ((sp->work_mode == WORK_BRIDGE) || (sp->work_mode == WORK_ROUTE)) {
        /* 处理透明代理配置 */
        newdir = (ap_directive_t *)apr_pcalloc(ptemp, sizeof(ap_directive_t));
        newdir->filename = sp->name; 
        newdir->line_num = (current == NULL) ? 1 : (current->line_num + 1);
        newdir->directive = apr_pstrdup(ptemp, "ProxyTransparent");
        newdir->args = apr_pstrdup(ptemp, "On");
        current = ap_add_node(&conftree, current, newdir, 0);

        if (!sp->is_default) {
            for (sname_set = 0, vhost = sp->virt_host->next; vhost; vhost = vhost->next) {
                if (strlen(vhost->server_name) > 0) {
                    newdir = (ap_directive_t *)apr_pcalloc(ptemp, sizeof(ap_directive_t));
                    newdir->filename = sp->name; 
                    newdir->line_num = (current == NULL) ? 1 : (current->line_num + 1);
                    if (!sname_set) {
                        newdir->directive = apr_pstrdup(ptemp, "ServerName");
                        sname_set = 1;
                    } else {
                        newdir->directive = apr_pstrdup(ptemp, "ServerAlias");
                    }
                    newdir->args = apr_pstrdup(ptemp, vhost->server_name);
                    current = ap_add_node(&conftree, current, newdir, 0);
                }
            }
        }

        newdir = (ap_directive_t *)apr_pcalloc(ptemp, sizeof(ap_directive_t));
        newdir->filename = sp->name; 
        newdir->line_num = (current == NULL) ? 1 : (current->line_num + 1);
        newdir->directive = apr_pstrdup(ptemp, "ProxyPreserveHost");
        newdir->args = apr_pstrdup(ptemp, "On");
        current = ap_add_node(&conftree, current, newdir, 0);
    } else if (sp->work_mode == WORK_OFFLINE) {
        /* 处理离线模式配置 */
        if (!sp->is_default) {
            for (sname_set = 0, vhost = sp->virt_host->next; vhost; vhost = vhost->next) {
                if (strlen(vhost->server_name) > 0) {
                    newdir = (ap_directive_t *)apr_pcalloc(ptemp, sizeof(ap_directive_t));
                    newdir->filename = sp->name; 
                    newdir->line_num = (current == NULL) ? 1 : (current->line_num + 1);
                    if (!sname_set) {
                        newdir->directive = apr_pstrdup(ptemp, "ServerName");
                        sname_set = 1;
                    } else {
                        newdir->directive = apr_pstrdup(ptemp, "ServerAlias");
                    }
                    newdir->args = apr_pstrdup(ptemp, vhost->server_name);
                    current = ap_add_node(&conftree, current, newdir, 0);
                }
            }
        }
    } else {
        ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, ap_main_server,
                     "work mode error");
        return DECLINED;
    }

    /* 配置防护引擎 */
    if (BitGet(sp->opt_flags, ENGINE_FLAG)) {
        switch (sp->engine) {
        case BLOCK_OFF:
            sprintf(strbuf, "Off");
            break;
        case BLOCK_DET:
            sprintf(strbuf, "DetectionOnly");
            break;
        case BLOCK_ON:
            sprintf(strbuf, "On");
            break;
        default:
            sprintf(strbuf, "On");
            break;
        }
        newdir = (ap_directive_t *)apr_pcalloc(ptemp, sizeof(ap_directive_t));
        newdir->filename = sp->name;   
        newdir->line_num = (current == NULL) ? 1 : (current->line_num + 1);
        newdir->directive = apr_pstrdup(ptemp, "SecRuleEngine");
        newdir->args = apr_pstrdup(ptemp, strbuf);
        current = ap_add_node(&conftree, current, newdir, 0);
    }

    /* 配置审核日志 */
    if (BitGet(sp->audit_set, ACCESS_LOG)) {
        if (BitGet(sp->audit_log, ACCESS_LOG)) {
            newdir = (ap_directive_t *)apr_pcalloc(ptemp, sizeof(ap_directive_t));
            newdir->filename = sp->name; 
            newdir->line_num = (current == NULL) ? 1 : (current->line_num + 1);
            newdir->directive = apr_pstrdup(ptemp, "SecAccessLog");
            newdir->args = apr_pstrdup(ptemp, "On");
            current = ap_add_node(&conftree, current, newdir, 0);
        } else {
            newdir = (ap_directive_t *)apr_pcalloc(ptemp, sizeof(ap_directive_t));
            newdir->filename = sp->name; 
            newdir->line_num = (current == NULL) ? 1 : (current->line_num + 1);
            newdir->directive = apr_pstrdup(ptemp, "SecAccessLog");
            newdir->args = apr_pstrdup(ptemp, "Off");
            current = ap_add_node(&conftree, current, newdir, 0);
        }
    }
    if (BitGet(sp->audit_set, ATTACK_LOG)) {
        if (BitGet(sp->audit_log, ATTACK_LOG)) {
            newdir = (ap_directive_t *)apr_pcalloc(ptemp, sizeof(ap_directive_t));
            newdir->filename = sp->name; 
            newdir->line_num = (current == NULL) ? 1 : (current->line_num + 1);
            newdir->directive = apr_pstrdup(ptemp, "SecAttackLog");
            newdir->args = apr_pstrdup(ptemp, "On");
            current = ap_add_node(&conftree, current, newdir, 0);
            if (sp->atlog_lev) {
                sprintf(strbuf, "%d", sp->atlog_lev);
                newdir = (ap_directive_t *)apr_pcalloc(ptemp, sizeof(ap_directive_t));
                newdir->filename = sp->name; /* 使用服务器策略名字作为指令文件名 */
                newdir->line_num = (current == NULL) ? 1 : (current->line_num + 1);
                newdir->directive = apr_pstrdup(ptemp, "SecAttackLogLevel");
                newdir->args = apr_pstrdup(ptemp, strbuf);
                current = ap_add_node(&conftree, current, newdir, 0);
            }
        } else {
            newdir = (ap_directive_t *)apr_pcalloc(ptemp, sizeof(ap_directive_t));
            newdir->filename = sp->name; /* 使用服务器策略名字作为指令文件名 */
            newdir->line_num = (current == NULL) ? 1 : (current->line_num + 1);
            newdir->directive = apr_pstrdup(ptemp, "SecAttackLog");
            newdir->args = apr_pstrdup(ptemp, "Off");
            current = ap_add_node(&conftree, current, newdir, 0);
        }
    }
    
    /* 离线模式不配置缓存模块 */
    if (sp->cache_root && sp->work_mode != WORK_OFFLINE) {
        newdir = (ap_directive_t *)apr_pcalloc(ptemp, sizeof(ap_directive_t));
        newdir->filename = sp->name; /* 使用服务器策略名字作为指令文件名 */
        newdir->line_num = (current == NULL) ? 1 : (current->line_num + 1);
        newdir->directive = apr_pstrdup(ptemp, "CacheEnable");
        newdir->args = apr_pstrdup(ptemp, "disk /");
        current = ap_add_node(&conftree, current, newdir, 0);
        
        newdir = (ap_directive_t *)apr_pcalloc(ptemp, sizeof(ap_directive_t));
        newdir->filename = sp->name; 
        newdir->line_num = (current == NULL) ? 1 : (current->line_num + 1);
        newdir->directive = apr_pstrdup(ptemp, "CacheRoot");
        newdir->args = apr_pstrdup(ptemp, sp->cache_root);
        current = ap_add_node(&conftree, current, newdir, 0);
    } else if (sp->cache_root && sp->work_mode == WORK_OFFLINE) {
        newdir = (ap_directive_t *)apr_pcalloc(ptemp, sizeof(ap_directive_t));
        newdir->filename = sp->name; 
        newdir->line_num = (current == NULL) ? 1 : (current->line_num + 1);
        newdir->directive = apr_pstrdup(ptemp, "CacheDisable");
        newdir->args = apr_pstrdup(ptemp, "/");
        current = ap_add_node(&conftree, current, newdir, 0);
    }

    /* 配置安全策略和规则集 */
    rv = process_security_rule(sp, current, conftree, ptemp);
    if (rv != OK) {
        return DECLINED;
    }

    #if SHOW_SECURITY_RULE
    /* 指令下发调试 */
    conftree_traverse(conftree);
    #endif

    if (conftree) {
        rv = ap_process_config_tree(server_conf, conftree,
                                    sp->pvhost, ptemp);
    }

    return rv;
}

/* 销毁服务器策略下的虚拟主机 */
static int destroy_vhost(server_policy_t *sp)
{
    if (!sp) {
        return DECLINED;
    }
    if (sp->pvhost) {
        apr_pool_destroy(sp->pvhost);
        sp->pvhost = NULL;
    }
    sp->server = NULL;

    return OK;
}

/* 重新构建服务器策略下的虚拟主机，并添加监听端口  */
static int rebuild_vhost(server_policy_t *sp, apr_pool_t *ptemp)
{
    server_rec *s;
    apr_pool_t *pvhost;
    virt_host_t *vhost;
    const char *hostname;
    char *strtmp;
    const char *errmsg;

    if (!sp) {
        return DECLINED;
    } else if (sp->is_default) {
        hostname = apr_pstrdup(ptemp, "_default_:*");
    } else if (sp->virt_host) {
        hostname = NULL;
        for (vhost = sp->virt_host->next; vhost; vhost = vhost->next) {
            if (vhost->phttp) {
                if (!hostname) {
                    hostname = apr_psprintf(ptemp, "%d.%d.%d.%d:%d ",
                                            NIPQUAD(vhost->ipaddr.s_addr),
                                            vhost->phttp);
                } else {
                    strtmp = apr_psprintf(ptemp, "%d.%d.%d.%d:%d ",
                                          NIPQUAD(vhost->ipaddr.s_addr),
                                          vhost->phttp);
                    hostname = apr_pstrcat(ptemp, hostname, strtmp, NULL);
                }
            }
            
            if (vhost->phttps) {
                if (!hostname) {
                    hostname = apr_psprintf(ptemp, "%d.%d.%d.%d:%d ",
                                            NIPQUAD(vhost->ipaddr.s_addr),
                                            vhost->phttps);
                } else {
                    strtmp = apr_psprintf(ptemp, "%d.%d.%d.%d:%d ",
                                          NIPQUAD(vhost->ipaddr.s_addr),
                                          vhost->phttps);
                    hostname = apr_pstrcat(ptemp, hostname, strtmp, NULL);
                }
            }
        }
    } else {
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, NULL,
                     "no virtual host address");
        return DECLINED;
    }

    /* 创建新的虚拟主机 */
    ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, ap_main_server,
                 "create virtual host: %s", hostname);

    apr_pool_create(&pvhost, pconf);
    apr_pool_tag(pvhost, "pvhost");
    sp->pvhost = pvhost;
    errmsg = ap_init_virtual_host(pvhost, hostname, ap_main_server, &s);
    if (errmsg) {
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, NULL,
                     "create virtual host error: %s", errmsg);
        destroy_vhost(sp);
        return DECLINED;
    }

    /* 处理虚拟主机配置 */
    if (process_server_policy(sp, s, ptemp)) {
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, NULL,
                     "process server policy %s error", sp->name);
        destroy_vhost(sp);
        return DECLINED;
    } else {
        sp->server = s;
    }

    return OK;
}

/* 处理所有服务器策略的配置 */
AP_DECLARE(int) ap_server_policy_walk(apr_hash_t *sp_hash)
{
    int total;
    server_policy_t *sp;
    apr_hash_index_t *hi;
    apr_pool_t *ptemp; /* Pool for temporary config stuff, reset often */
    apr_time_t start_time;
    apr_time_t stop_time;

    if (!sp_hash) {
        return DECLINED;
    }

    start_time = apr_time_now();

    /* 配置处理过程中的临时数据放在临时内存池里面 */
    apr_pool_create(&ptemp, pconf);
    apr_pool_tag(ptemp, "ptemp");

    total = count_hash(sp_hash);
    ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, ap_main_server,
                 "server policy hash size: %d", total);

    /* 只部署符合当前运行模式的服务器策略 */
    total = 0;
    for (hi = apr_hash_first(NULL, sp_hash); hi; hi = apr_hash_next(hi)) {
        apr_hash_this(hi, NULL, NULL, (void *)&sp);
        if (!sp && (sp->work_mode != ap_work_mode)) {
            continue;
        }

        if (sp->is_default && (sp->work_mode == WORK_REVERSE)) {
            continue;
        }

        ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, ap_main_server,
                     "server policy (%d): %s", total + 1, sp->name);

        /* 重新构建虚拟主机 */
        if (rebuild_vhost(sp, ptemp)) {
            ap_log_error(APLOG_MARK, APLOG_ERR, 0, NULL,
                         "deploy server policy %s error", sp->name);
            continue;
        }

        sp->server->next = ap_main_server->next;
        ap_main_server->next = sp->server;
        total++;
    }

    apr_pool_destroy(ptemp);

    stop_time = apr_time_now();
    ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, ap_main_server,
                 "cost (%lld) micro-seconds to walk server policy", (long long)(stop_time - start_time));

    if (!total) {
        ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, ap_main_server,
                     "there is no available server policy");
        return DONE;
    }

    return OK;
}

/**********************************************************
 * 离线模式相关的处理函数
 **********************************************************/
/**
 * 离线模式配置终止
 */
AP_DECLARE(void) ap_offline_mode_term(void)
{
    apr_socket_set_offline_mode(0);
    apr_pollset_set_offline_mode(0);
}

/**
 * 离线模式配置初始化
 */
AP_DECLARE(int) ap_offline_configure(void)
{
    int i;
    apr_status_t rv;
    ap_directive_t *newdir;
    ap_directive_t *current;
    ap_directive_t *conftree;
    apr_pool_t *ptemp; /* Pool for temporary config stuff, reset often */
    char strbuf[STR_LEN_MAX];

    if (ap_off_iface == 0) {
        return DONE;
    }
    
    /* 配置处理过程中的临时数据放在临时内存池里面 */
    apr_pool_create(&ptemp, pconf);
    apr_pool_tag(ptemp, "ptemp");
 
    rv = OK;
    
    /* 建立一颗临时的配置树 */
    conftree = NULL;
    current = conftree;

    newdir = (ap_directive_t *)apr_pcalloc(ptemp, sizeof(ap_directive_t));
    newdir->filename = "offline mode";
    newdir->line_num = (current == NULL) ? 1 : (current->line_num + 1);
    newdir->directive = apr_pstrdup(ptemp, "OfflineEngine");
    newdir->args = apr_pstrdup(ptemp, "On");
    current = ap_add_node(&conftree, current, newdir, 0);
    conftree = current;

    /* 设定监听端口 */
    for (i = 0; i < OFFLINE_INTF_NUM; i++) {
        if (BitGet(ap_off_iface, i + 1)) {
            sprintf(strbuf, "eth%d", i);
            newdir = (ap_directive_t *)apr_pcalloc(ptemp, sizeof(ap_directive_t));
            newdir->filename = "offline mode";
            newdir->line_num = (current == NULL) ? 1 : (current->line_num + 1);
            newdir->directive = apr_pstrdup(ptemp, "OfflineEthName");
            newdir->args = apr_pstrdup(ptemp, strbuf);
            current = ap_add_node(&conftree, current, newdir, 0);
        }
    }

    newdir = (ap_directive_t *)apr_pcalloc(ptemp, sizeof(ap_directive_t));
    newdir->filename = "offline mode";
    newdir->line_num = (current == NULL) ? 1 : (current->line_num + 1);
    newdir->directive = apr_pstrdup(ptemp, "OfflineLogLevel");
    newdir->args = apr_pstrdup(ptemp, "fatal");
    current = ap_add_node(&conftree, current, newdir, 0);

    /* 指令下发调试 */
    for (current = conftree; current != NULL; current = current->next) {
        ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, ap_main_server,
                     "%s: line[%d] directive[%s] args[%s]",
                     current->filename, current->line_num,
                     current->directive, current->args);
    }

    if (conftree) {
        rv = ap_process_config_tree(ap_main_server, conftree,
                                    pconf, ptemp);
    }

    apr_pool_destroy(ptemp);

    return rv;
}

/**********************************************************
 * 其他的函数
 **********************************************************/

/* 引擎配置处理模块初始化 */
AP_DECLARE(int) ap_engine_config_init(apr_pool_t *p, apr_pool_t *ptrans)
{
    if (!p || !ptrans) {
        return DECLINED;
    }

    pcli = p;
    pconf = ptrans;

    return OK;
}

