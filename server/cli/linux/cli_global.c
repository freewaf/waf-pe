/*
 * $Id: cli_global.c 2786 2013-07-09 16:42:55 FreeWAF Development Team $
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
#include <unistd.h>
#include <net/if.h>
#include <netinet/in.h>
#include <arpa/inet.h> 
#include "cparser.h"
#include "cparser_priv.h"
#include "cparser_token.h"
#include "global_root.h"
#include "cparser_show_tree.h"
#include "cparser_tree.h"
#include "ap_config.h"
#include "ap_listen.h"
#include "cli_common.h"
#include "convert_rule.h"
#include "engine_config.h"
#include "pe_cli.h"

#define  INNER_HTTP           3129
#define  INNER_HTTPS          3128
#define  ANY_IP               "0.0.0.0"

static apr_pool_t *pcli = NULL;              /* Pool for cli config stuff */
static char *abs_tproxy_shell_path = NULL;

ap_proxy_mode_t ap_work_mode;
int work_mode_opt_flags[WORK_NUM];
encode_type_t encode_type;
int encode_type_flag = 0;
int ap_off_iface;
listen_port_t *ap_listen_ports = NULL;        /* 监听端口存储 */
bridge_port_t *ap_bridge_ports = NULL;        /* 网桥和路由模式，桥和服务器端口信息存储 */

/***********************************************************/
/* 端口监听的相关操作                                      */
/***********************************************************/
static int get_listen_port_num(ap_proxy_mode_t curmode)
{
    int num = 0;
    listen_port_t *listen_port;
    
    if (ap_listen_ports) {
        listen_port = ap_listen_ports->next;
        while (listen_port) {
            if (listen_port->create_mode == curmode) {
                num++;
            }
            listen_port = listen_port->next;
        } 
    }

    return num;
}

static listen_port_t *find_listen_port(struct in_addr ipaddr, apr_port_t port, ap_proxy_mode_t curmode)
{
    listen_port_t *listen_port;

    listen_port = NULL;
    if (ap_listen_ports) {
        listen_port = ap_listen_ports->next;
    } else {
        return NULL;
    }

    while (listen_port) {
        if ((listen_port->create_mode == curmode) 
            && (listen_port->ipaddr.s_addr == ipaddr.s_addr) && (listen_port->port == port)) {
            break;
        }
        listen_port = listen_port->next;
    }

    return listen_port;
}

static listen_port_t *add_listen_port(void)
{
    apr_pool_t *plisten;
    listen_port_t *listen_port;

    apr_pool_create(&plisten, pcli);
    apr_pool_tag(plisten, "plisten");
    listen_port = (listen_port_t *)apr_pcalloc(plisten, sizeof(listen_port_t));
    listen_port->pool = plisten;
    listen_port->prev = NULL;
    listen_port->next = NULL;
    listen_port->ipaddr.s_addr = 0;
    listen_port->proto = 0;
    listen_port->port = 0;

    if (ap_listen_ports) {
        listen_port->next = ap_listen_ports->next;
        ap_listen_ports->next = listen_port;
        listen_port->prev = ap_listen_ports;
        if (listen_port->next) {
            listen_port->next->prev = listen_port;
        }
    } else {
        /* 第一个节点是链表头 */
        ap_listen_ports = listen_port;
    }

    return listen_port;
}

static int del_listen_port(struct in_addr ipaddr, apr_port_t port, ap_proxy_mode_t cur_mode)
{
    listen_port_t *listen_port;

    listen_port = find_listen_port(ipaddr, port, cur_mode);
    if (listen_port) {
        listen_port->prev->next = listen_port->next;
        if (listen_port->next) {
            listen_port->next->prev = listen_port->prev;
        }
        apr_pool_destroy(listen_port->pool);
    }
    
    return OK;
}

/* 清除除new-mode模式以外的其它监听端口 */
static int clear_listen_port(ap_proxy_mode_t new_mode)
{
    listen_port_t *listen_port, *listen_port_tmp;

    listen_port = NULL;
    if (ap_listen_ports) {
        listen_port = ap_listen_ports->next;
    } else {
        return DECLINED;
    }

    while (listen_port) {
        if (listen_port->create_mode != new_mode) {
            listen_port->prev->next = listen_port->next;
            if (listen_port->next) {
                listen_port->next->prev = listen_port->prev;
            }
            listen_port_tmp = listen_port->next;
            apr_pool_destroy(listen_port->pool);  
            listen_port = listen_port_tmp;
        } else {
            listen_port = listen_port->next;
        }
    }

    return OK;
}

/* 端口监听 */
static int create_listen_port(cparser_context_t *context, uint32_t ipaddr_ptr, uint32_t port,
             int proto, ap_proxy_mode_t cur_mode)
{
    struct in_addr ipaddr;
    listen_port_t *listen_port;

    ipaddr.s_addr = ipaddr_ptr;

    if (proto == PROTO_HTTP) {
        port = port > 0 ? port : DEFAULT_HTTP_PORT;
    } else if (proto == PROTO_HTTPS) {
        port = port > 0 ? port : DEFAULT_HTTPS_PORT;
    }

    ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, ap_main_server,
                 "add listener ip[%d.%d.%d.%d] proto[%d] port[%d]",
                 NIPQUAD(ipaddr.s_addr), proto, port);

    listen_port = find_listen_port(ipaddr, port, cur_mode);
    if (!listen_port) {
        listen_port = add_listen_port();
        if (!listen_port) {
            if (context) {
                cli_printf_info(context, "add listener[%d.%d.%d.%d:%d] failure!\n",
                       NIPQUAD(ipaddr.s_addr), port);
            } else {
                ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, NULL, "add listener[%d.%d.%d.%d:%d] failure!",
                       NIPQUAD(ipaddr.s_addr), port);
            }
            return DECLINED;
        }
    } else {
        if (context) {
            cli_printf_info(context, "listener[%d.%d.%d.%d:%d] have been added!\n",
                   NIPQUAD(ipaddr.s_addr), port);
        } else {
            ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, NULL, "listener[%d.%d.%d.%d:%d] have been added!",
                   NIPQUAD(ipaddr.s_addr), port);
        }
        return DECLINED;
    }
     
    listen_port->ipaddr.s_addr = ipaddr.s_addr;
    listen_port->proto = proto;
    listen_port->port = port;
    listen_port->create_mode = cur_mode;
    
    return OK;
}

/* 取消端口监听 */
static int destroy_listen_port(cparser_context_t *context, uint32_t ipaddr_ptr, uint32_t port, 
            int proto, ap_proxy_mode_t cur_mode)
{
    int rv;
    struct in_addr ipaddr;
   
    ipaddr.s_addr = ipaddr_ptr;
    if (proto == PROTO_HTTP) {
        port = port > 0 ? port : DEFAULT_HTTP_PORT;
    } else if (proto == PROTO_HTTPS) {
        port = port > 0 ? port : DEFAULT_HTTPS_PORT;
    }

    ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, ap_main_server,
                 "delete listen ip[%d.%d.%d.%d] proto[%d] port[%d]",
                 NIPQUAD(ipaddr.s_addr), proto, port);

    rv = del_listen_port(ipaddr, port, cur_mode);
    if (rv != OK) {
        if (context) {
            cli_printf_info(context, "delete listener[%d.%d.%d.%d:%d] failure!\n",
                   NIPQUAD(ipaddr.s_addr), port);
        } else {
            printf("delete listener[%d.%d.%d.%d:%d] failure!\n",
                   NIPQUAD(ipaddr.s_addr), port);
        }
        return DECLINED;
    }

    return OK;
}

/* 透明模式下，内置端口监听 */
static int listen_inner_port(cparser_context_t *context, ap_proxy_mode_t work_mode)
{
    struct in_addr ipaddr;
    cparser_result_t rv;

    ipaddr.s_addr = inet_addr(ANY_IP);

    /* 添加内置3129端口,用于接收HTTP流量 */
    rv = create_listen_port(context, ipaddr.s_addr, INNER_HTTP, PROTO_HTTP, work_mode);
    if (rv != OK) {
        return DECLINED;
    }

    /* 添加内置3128端口,用于接收HTTPS流量 */
    rv = create_listen_port(context, ipaddr.s_addr, INNER_HTTPS, PROTO_HTTPS, work_mode);
    if (rv != OK) {
        (void)destroy_listen_port(context, ipaddr.s_addr, INNER_HTTP, PROTO_HTTP, work_mode);
        return DECLINED;
    }

    BitSet(work_mode_opt_flags[work_mode], MODE_FLAG);
    return OK;   
}

/****************************************************/
/* 透明端口和桥的相关操作                           */
/*****************************************************/
static bridge_port_t *find_bridge_port(char *br_name, apr_port_t ser_port)
{
    bridge_port_t *bridge_port;

    bridge_port = NULL;
    if (ap_bridge_ports) {
        bridge_port = ap_bridge_ports->next;
    } else {
        return NULL;
    }

    while (bridge_port) {
        /* 网桥模式有桥 */
        if (br_name) {
            if (!strcmp(bridge_port->br_name, br_name) && (bridge_port->ser_port == ser_port)) { 
                break;
            }
        }

        /* 路由模式没有桥 */
        if (!br_name) {
            if (!strlen(bridge_port->br_name) && (bridge_port->ser_port == ser_port)) { 
                break;
            }
        }
        
        bridge_port = bridge_port->next;
    }

    return bridge_port;
}

static bridge_port_t *add_bridge_port(void)
{
    apr_pool_t *pbridge;
    bridge_port_t *bridge_port;

    apr_pool_create(&pbridge, pcli);
    apr_pool_tag(pbridge, "pbridge");
    bridge_port = (bridge_port_t *)apr_pcalloc(pbridge, sizeof(bridge_port_t));
    bridge_port->pool = pbridge;
    bridge_port->prev = NULL;
    bridge_port->next = NULL;
    bridge_port->proto = 0;
    bridge_port->ser_port = 0;
    bridge_port->br_name[0] = '\0';

    if (ap_bridge_ports) {
        bridge_port->next = ap_bridge_ports->next;
        ap_bridge_ports->next = bridge_port;
        bridge_port->prev = ap_bridge_ports;
        if (bridge_port->next) {
            bridge_port->next->prev = bridge_port;
        }
    } else {
        /* 第一个节点是链表头 */
        ap_bridge_ports = bridge_port;
    }

    return bridge_port;
}

static int del_bridge_port(char *br_name, apr_port_t ser_port, int proto)
{
    bridge_port_t *bridge_port;

    bridge_port = find_bridge_port(br_name, ser_port);
    if (bridge_port && bridge_port->proto == proto) {
        bridge_port->prev->next = bridge_port->next;
        if (bridge_port->next) {
            bridge_port->next->prev = bridge_port->prev;
        }
        apr_pool_destroy(bridge_port->pool);

        return OK;
    } else {
        return DECLINED;
    }
}

static int clear_bridge_port(ap_proxy_mode_t new_mode)
{
    bridge_port_t *bridge_port, *bridge_port_tmp;

    bridge_port = NULL;
    if (ap_bridge_ports) {
        bridge_port = ap_bridge_ports->next;
    } else {
        return DECLINED;
    }

    while (bridge_port) {
        if (bridge_port->create_mode != new_mode || bridge_port->deleted) {
            bridge_port->prev->next = bridge_port->next;
            if (bridge_port->next) {
                bridge_port->next->prev = bridge_port->prev;
            }
            bridge_port_tmp = bridge_port->next;
            apr_pool_destroy(bridge_port->pool);
            bridge_port = bridge_port_tmp;
        } else {
            bridge_port = bridge_port->next;
        }
    }

    return OK;
}

static int create_bridge_port(cparser_context_t *context, char *br_name, apr_port_t ser_port, 
    apr_port_t tproxy_port, int proto, ap_proxy_mode_t work_mode)
{
    bridge_port_t *bridge_port;

    if (br_name) {
        if (strlen(br_name) >= NAME_LEN_MAX) {
            cli_printf_info(context, "the bridge name exceed max number(%d)!\n", NAME_LEN_MAX);
            return DECLINED;
        }
        ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, ap_main_server,
                     "tproxy add bridge %s server port[%d] proto[%d]",
                     br_name, ser_port, proto);
    } else {
        ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, ap_main_server,
                     "tproxy add server port[%d] proto[%d]",
                     ser_port, proto);
    }

    bridge_port = find_bridge_port(br_name, ser_port);
    if (!bridge_port) {
        bridge_port = add_bridge_port();
        if (!bridge_port) {
            if (br_name) {
                cli_printf_info(context, "tproxy add bridge %s server port[%d] failure!\n", br_name, ser_port);
            } else {
                cli_printf_info(context, "tproxy add server port[%d] failure!\n", ser_port);
            }
            return DECLINED;
        }
    } else {    
        if (!bridge_port->deleted) {
            if (br_name) {
                cli_printf_info(context, "tproxy bridge %s server port[%d] have been added!\n", br_name, ser_port);
            } else {
                cli_printf_info(context, "tproxy server port[%d] have been added!\n", ser_port);
            }
            return DECLINED;
        }
    }

    if (br_name) {
        strcpy(bridge_port->br_name, br_name);
    }

    bridge_port->proto = proto;
    bridge_port->ser_port = ser_port;
    bridge_port->tproxy_port = tproxy_port;
    bridge_port->create_mode = work_mode;
    bridge_port->deploied = 0;
    bridge_port->deleted = 0;

    return OK;
}

/* 取消端口监听 */
static int destroy_bridge_port(cparser_context_t *context, char *br_name, apr_port_t ser_port, int proto)
{
    int rv;
    char strbuf[STR_LEN_MAX];
    bridge_port_t *bridge_port;
    
    if (br_name) {
        ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, ap_main_server,
                 "delete tproxy bridge %s server port[%d] proto[%d]", br_name, ser_port, proto);
    } else {
        ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, ap_main_server,
             "delete tproxy server port[%d] proto[%d]", ser_port, proto);
    }

    if (proto == PROTO_HTTP) {
        sprintf(strbuf, "%s", "http");
    } else {
        sprintf(strbuf, "%s", "https");
    }
#if 0
    rv = del_bridge_port(br_name, ser_port, proto);
    if (rv != OK) {
        if (br_name) {
            cli_printf_info(context, "tproxy bridge %s %s server port[%d] do not exist!\n", 
                br_name, strbuf, ser_port);
        } else {
            cli_printf_info(context, "tproxy server port[%d] do not exist!\n", ser_port);         
        }
        return DECLINED;
    }
    
    return OK;
#else
    /* 删除时先把标识位置1，待commit的时候才真正从链表上摘除 */
    bridge_port = find_bridge_port(br_name, ser_port);
    if (bridge_port && bridge_port->proto == proto) {
        bridge_port->deleted = 1;
        return OK;
    } else {
        if (br_name) {
            cli_printf_info(context, "tproxy bridge %s %s server port[%d] do not exist!\n", 
                br_name, strbuf, ser_port);
        } else {
            cli_printf_info(context, "tproxy server port[%d] do not exist!\n", ser_port);         
        }
        return DECLINED;
    }
#endif
}

/*****************************************************/
/* iptables和ebtables脚本相关操作                    */
/*****************************************************/
int create_iptables_configure(int ser_port, int tproxy_port)
{
    char *argv[MAX_ARGV_NUM] = { NULL };
    apr_pool_t *ptemp;
    int rv;
    int i;

    /* 分配子池 */
    apr_pool_create(&ptemp, pcli);
    apr_pool_tag(ptemp, "ptemp");

    i = 0;
    argv[i++] = apr_psprintf(ptemp, "%s", abs_tproxy_shell_path);
    argv[i++] = apr_psprintf(ptemp, "route");
    argv[i++] = apr_psprintf(ptemp, "a");
    argv[i++] = apr_psprintf(ptemp, "add");
    argv[i++] = apr_psprintf(ptemp, "dport");
    argv[i++] = apr_psprintf(ptemp, "%d", ser_port);
    argv[i++] = apr_psprintf(ptemp, "tport");
    argv[i++] = apr_psprintf(ptemp, "%d", tproxy_port);

    rv = ap_exec_shell(abs_tproxy_shell_path, argv);
    
    ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, NULL, 
        "exec iptables shell:route a add dport %d tport %d", ser_port, tproxy_port);    
    apr_pool_destroy(ptemp);
    
    return rv;
}

int destroy_iptables_configure(int ser_port, int tproxy_port)
{
    char *argv[MAX_ARGV_NUM] = { NULL };
    apr_pool_t *ptemp;
    int rv;
    int i;

    /* 分配子池 */
    apr_pool_create(&ptemp, pcli);
    apr_pool_tag(ptemp, "ptemp");

    i = 0;
    argv[i++] = apr_psprintf(ptemp, "%s", abs_tproxy_shell_path);
    argv[i++] = apr_psprintf(ptemp, "route");
    argv[i++] = apr_psprintf(ptemp, "a");
    argv[i++] = apr_psprintf(ptemp, "del");
    argv[i++] = apr_psprintf(ptemp, "dport");
    argv[i++] = apr_psprintf(ptemp, "%d", ser_port);
    argv[i++] = apr_psprintf(ptemp, "tport");
    argv[i++] = apr_psprintf(ptemp, "%d", tproxy_port);

    rv = ap_exec_shell(abs_tproxy_shell_path, argv);

    ap_log_perror(APLOG_MARK, APLOG_DEBUG, 0, ptemp, 
        "exec iptables shell:route a del dport %d tport %d, rv = %d", ser_port, tproxy_port, rv);
    apr_pool_destroy(ptemp);
    
    return rv;
}

int create_ebtables_configure(char *br, int ser_port, int tproxy_port)
{
    char *argv[MAX_ARGV_NUM] = { NULL };
    apr_pool_t *ptemp;
    int rv;
    int i;

    /* 分配子池 */
    apr_pool_create(&ptemp, pcli);
    apr_pool_tag(ptemp, "ptemp");

    i = 0;
    argv[i++] = apr_psprintf(ptemp, "%s", abs_tproxy_shell_path);
    argv[i++] = apr_psprintf(ptemp, "bridge");
    argv[i++] = apr_psprintf(ptemp, "%s", br);
    argv[i++] = apr_psprintf(ptemp, "add");
    argv[i++] = apr_psprintf(ptemp, "dport");
    argv[i++] = apr_psprintf(ptemp, "%d", ser_port);
    argv[i++] = apr_psprintf(ptemp, "tport");
    argv[i++] = apr_psprintf(ptemp, "%d", tproxy_port);

    rv = ap_exec_shell(abs_tproxy_shell_path, argv);
    
    ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, NULL, 
        "exec ebtables shell:%s bridge %s add dport %d tport %d, rv = %d", abs_tproxy_shell_path, br, ser_port, tproxy_port, rv);
    apr_pool_destroy(ptemp);
    
    return rv;
}

int destroy_ebtables_configure(char *br, int ser_port, int tproxy_port)
{
    char *argv[MAX_ARGV_NUM] = { NULL };
    apr_pool_t *ptemp;
    int rv;
    int i;

    /* 分配子池 */
    apr_pool_create(&ptemp, pcli);
    apr_pool_tag(ptemp, "ptemp");

    i = 0;
    argv[i++] = apr_psprintf(ptemp, "%s", abs_tproxy_shell_path);
    argv[i++] = apr_psprintf(ptemp, "bridge");
    argv[i++] = apr_psprintf(ptemp, "%s", br);
    argv[i++] = apr_psprintf(ptemp, "del");
    argv[i++] = apr_psprintf(ptemp, "dport");
    argv[i++] = apr_psprintf(ptemp, "%d", ser_port);
    argv[i++] = apr_psprintf(ptemp, "tport");
    argv[i++] = apr_psprintf(ptemp, "%d", tproxy_port);

    rv = ap_exec_shell(abs_tproxy_shell_path, argv);
    
    ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, NULL, 
        "exec ebtables shell:bridge %s del dport %d tport %d", br, ser_port, tproxy_port);    
    apr_pool_destroy(ptemp);
    
    return rv;
}

static int clear_tproxy_configure()
{
    bridge_port_t *bridge_port;
    
    if (ap_bridge_ports) {
        bridge_port = ap_bridge_ports->next;
    } else {
        return OK;
    }
    
    while (bridge_port) {
        if (ap_work_mode == WORK_BRIDGE && bridge_port->create_mode == ap_work_mode) {
            if (bridge_port->deploied) {
                (void)destroy_ebtables_configure(bridge_port->br_name, bridge_port->ser_port, 
                    bridge_port->tproxy_port);
                bridge_port->deploied = 0;
            }
        }

        if (ap_work_mode == WORK_ROUTE && bridge_port->create_mode == ap_work_mode) {
            if (bridge_port->deploied) {
                (void)destroy_iptables_configure(bridge_port->ser_port, bridge_port->tproxy_port);
                bridge_port->deploied = 0;
            }
        }
        
        bridge_port = bridge_port->next;
    }

    return OK;
}

/* 清除非当前工作模式操作标记 */
static void clear_work_mode_opt_flag(ap_proxy_mode_t new_mode)
{
    ap_proxy_mode_t mode;

    for(mode = 0; mode < WORK_NUM; mode++) {
        if (mode != new_mode) {
            BitClr(work_mode_opt_flags[mode], MODE_FLAG);
        }
    }
}

/**********************************************************/
/* 模式操作相关                                           */
/**********************************************************/
/* 模式切换准备工作 */
AP_DECLARE(int) workemode_change_prepare(cparser_context_t *context, ap_proxy_mode_t new_mode)
{
    int rv;
    
    if (context == NULL || new_mode >= WORK_NUM) {
        return DECLINED;
    }
    
    /* 清除该监听端口链表上其它的模式结点 */
    rv = clear_listen_port(new_mode);
    if (rv != OK) {
        cli_printf_info(context, "clear listener port failure!\n");
        return DECLINED;
    }
    
    /* 清除桥模式下配置的ebtables，或者路由模式下配置的iptables */
    if (ap_work_mode == WORK_BRIDGE || ap_work_mode == WORK_ROUTE) {
        rv = clear_tproxy_configure();
        if (rv != OK) {
            cli_printf_info(context, "clear tproxy configure failure!\n");
            return DECLINED;
        }
    }
    
    /* 清除桥端口链表上的其它模式的结点 */
    rv = clear_bridge_port(new_mode);
    if (rv != OK) {
        cli_printf_info(context, "clear bridge port failure!\n");
        return DECLINED;
    }
    
    if (ap_work_mode != new_mode) {
        /* 清除IP动态黑名单 */
        rv = ap_dyn_blacklist_clear(IP_BLACK, "all");
        if (rv != OK) {
            cli_printf_info(context, "clear dynamic ip black list failure!\n");
            return DECLINED;
        }
        /* 清除URL动态黑名单 */
        rv = ap_dyn_blacklist_clear(URL_BLACK, "all");
        if (rv != OK) {
            cli_printf_info(context, "clear dynamic in url black list failure!\n");
            return DECLINED;
        }

        /* 清除服务器策略 */
        rv = clear_server_policy();
        if (rv != OK) {
            cli_printf_info(context, "clear server policy failure!\n");
            return DECLINED;
        }

        /* 由桥模式切到其它模式，清除桥模式下配置的桥 */
        if (ap_work_mode == WORK_BRIDGE && new_mode != WORK_BRIDGE) {
            rv = clear_bridge();
            if (rv != OK) {
                cli_printf_info(context, "clear bridge failure!\n");
                return DECLINED;
            }
        }  

        /* 由其它模式切到桥模式或者路由模式 */
        if ((ap_work_mode != WORK_BRIDGE && new_mode == WORK_BRIDGE) 
                || (ap_work_mode !=  WORK_ROUTE && new_mode == WORK_ROUTE)) {
            /* 监听透明内置端口，3129和3128 */
            rv = listen_inner_port(context, new_mode);
            if (rv != OK) {
                cli_printf_info(context, "add inner listen port failure!\n");
                return DECLINED;
            }
        }
      
        /* 关闭所有的监听端口 */
        ap_close_listeners();
            
        if (new_mode != WORK_OFFLINE) {
            /* 离线接口清除 */
            ap_off_iface = 0;   
            if (ap_work_mode == WORK_OFFLINE) {
                /* 终止离线接口 */
                ap_offline_mode_term();
            }
        }
    }

    /* 清除其它模式的操作标记 */
    clear_work_mode_opt_flag(new_mode);
    
    ap_work_mode = new_mode;
    return OK;
}

/**********************************************************/
/* 全局配置初始化                                         */
/**********************************************************/
AP_DECLARE(int) global_init(apr_pool_t *p)
{
    listen_port_t *listen_port;
    bridge_port_t *bridge_port;
    cparser_result_t rv;
    char *path;

    pcli = p;

    /* 初始化监听端口列表，添加头节点 */
    listen_port = add_listen_port();
    if (!listen_port) {
        return DECLINED;
    }

    /* 初始化透明桥和端口列表，添加头节点 */
    bridge_port = add_bridge_port();
    if (!bridge_port) {
        return DECLINED;
    }
    
    /* 脚本放置在apache根目录的bin目录下(~/bin/tproxy.sh) */
    path = ap_server_root_relative(pcli, "bin");
    abs_tproxy_shell_path = apr_pstrcat(pcli, path, "/tproxy.sh", NULL);

    /* 设定默认工作模式 */
    ap_work_mode = WORK_DEFAULT;
    
    if (ap_work_mode == WORK_BRIDGE || ap_work_mode == WORK_ROUTE) {       
        rv = listen_inner_port(NULL, ap_work_mode);
        if (rv != OK) {
            return DECLINED;
        }
    }

#if 0
    /* 默认为网桥代理模式，需要添加默认的配置 */
    if (ap_work_mode == WORK_BRIDGE) {  
        /* 默认网桥名为br0，服务器端口为80 */
        rv = create_ebtables_configure("br0", DEFAULT_HTTP_PORT, INNER_HTTP);
        if (rv != OK) {
            printf("Default bridge configure failed. Maybe there is no bridge br0.\n");
            destroy_ebtables_configure("br0", DEFAULT_HTTP_PORT, INNER_HTTP);
            return DECLINED;
        }
        
        rv = create_bridge_port("br0", DEFAULT_HTTP_PORT, INNER_HTTP, PROTO_HTTP);
        if (rv != OK) {
            destroy_ebtables_configure("br0", DEFAULT_HTTP_PORT, INNER_HTTP);
            return DECLINED;
        }        
    }
#endif

    /* 初始化离线监听网口 */
    ap_off_iface = 0;

    /* 初始化汉字编码 */
    encode_type = UTF_8;
    
    return OK;
}

/**********************************************************/
/* 模式配置                                               */
/**********************************************************/
static cparser_result_t cfg_waf_work_mode_c2p_cmd(cparser_context_t *context, ap_proxy_mode_t work_mode)
{
    char strbuf[STR_LEN_MAX] = {0};

    switch (work_mode) {
    case WORK_BRIDGE:
        sprintf(strbuf, "online bridge-proxy");
        break;
    case WORK_ROUTE:
        sprintf(strbuf, "online route-proxy");
        break;
    case WORK_REVERSE:
        sprintf(strbuf, "online reverse-proxy");
        break;
    case WORK_OFFLINE:
        sprintf(strbuf, "offline");
        break;
    default:
        return CPARSER_NOT_OK;
    }

    if (context->parser->mode == CPARSER_MODE_WRITE) {
        assert(context->parser->fp);
        cli_fprintf(context, "protect-engine work-mode %s\n", strbuf);
    } else {
        cli_printf(context, "!\n");
        cli_printf(context, "protect-engine work-mode %s\n", strbuf);
    }

    return CPARSER_OK;
}

/* 网桥代理配置相关 */
cparser_result_t cparser_cmd_pe_protect_engine_work_mode_online_bridge_proxy(cparser_context_t *context)
{
    char buf[COMMAND_LEN_MAX];
    char prompt[CPARSER_MAX_PROMPT];
    
    if (context == NULL) {
        return CPARSER_OK;
    }

    if (context->parser->mode != CPARSER_MODE_CONFIG) {            
        if (BitGet(work_mode_opt_flags[WORK_BRIDGE], MODE_FLAG)) {
            cfg_waf_work_mode_c2p_cmd(context, WORK_BRIDGE);
        }

        context->parser->root_level++;
        context->parser->root[context->parser->root_level] = context->parser->cur_node->children;
        cparser_walk(context->parser, cparser_running_conf_walker, NULL, "bridge_proxy");
        context->parser->root_level--;  
        
        return CPARSER_OK;
    } else { 
        snprintf(prompt, CPARSER_MAX_PROMPT, "%s(bridge-proxy)#", g_cli_prompt);
        snprintf(buf, COMMAND_LEN_MAX, "protect-engine work-mode online bridge-proxy");
        admin_log_process(context, buf);
        BitSet(work_mode_opt_flags[WORK_BRIDGE], MODE_FLAG);
        
        return cparser_submode_enter(context->parser, NULL, prompt);
    }       
}

static cparser_result_t cfg_waf_bridge_proxy_c2p_cmd(cparser_context_t *context, int proto)
{
    bridge_port_t *bridge_port;
    char strbuf[STR_LEN_MAX];

    if (ap_bridge_ports) {
        bridge_port = ap_bridge_ports->next;
    } else {
        return CPARSER_OK;
    }
     
    if (proto == PROTO_HTTP) {
        sprintf(strbuf, "http");
    } else {
        sprintf(strbuf, "https");
    }

    while (bridge_port) {
        if (bridge_port->proto == proto && bridge_port->create_mode == WORK_BRIDGE) {
            if (context->parser->mode == CPARSER_MODE_WRITE) {
                assert(context->parser->fp);
                cli_fprintf(context, "bridge %s %s %d\n", 
                    bridge_port->br_name, strbuf, bridge_port->ser_port);
            } else {
                cli_printf(context, "bridge %s %s %d\n", 
                    bridge_port->br_name, strbuf, bridge_port->ser_port);
            }
        }
        bridge_port = bridge_port->next;
    }

    return CPARSER_OK;
}

cparser_result_t cparser_cmd_bridge_proxy_bridge_bridge_name_http_httpport(cparser_context_t *context,
                   char **bridge_name_ptr, uint32_t *httpport_ptr)
{
    int rv;
    char buf[COMMAND_LEN_MAX];
    
    if (context == NULL) {
        return CPARSER_OK;
    }
  
    if (context->parser->mode != CPARSER_MODE_CONFIG) { 
        return cfg_waf_bridge_proxy_c2p_cmd(context, PROTO_HTTP);
    } else {
        if (!bridge_name_ptr || !*bridge_name_ptr || !httpport_ptr) {
            return CPARSER_NOT_OK;
        }

        if (!PORT_IN_RANGE(*httpport_ptr)) {
            cli_printf_info(context, "Invalid port, the range must be 1~65535!\n");    
            return CPARSER_NOT_OK;
        }
        
        /* 检测桥设备 */

#if 0
        rv = interface_find(*bridge_name_ptr);
        if (rv != OK) {
            cli_printf_info(context, "bridge %s do not exist!\n", *bridge_name_ptr);
            return CPARSER_NOT_OK;
        }
#else
        rv = bridge_check(*bridge_name_ptr);
        if (rv != OK) {
            cli_printf_info(context, 
                "No %s , or must have two or more members!\n", *bridge_name_ptr);
            return CPARSER_NOT_OK;
        }
#endif        
        /* 创建桥和端口，网桥代理模式必须要配置桥名字 */
        rv = create_bridge_port(context, *bridge_name_ptr, *httpport_ptr, 
            INNER_HTTP, PROTO_HTTP, WORK_BRIDGE);
        if (rv != OK) {
            return CPARSER_NOT_OK;
        }
        snprintf(buf, COMMAND_LEN_MAX, "bridge %s http %d", *bridge_name_ptr, *httpport_ptr);
        admin_log_process(context, buf);
        
        return CPARSER_OK;
    }     
}

cparser_result_t cparser_cmd_bridge_proxy_bridge_bridge_name_https_httpsport(cparser_context_t *context,
                   char **bridge_name_ptr, uint32_t *httpsport_ptr)
{
    int rv;
    char buf[COMMAND_LEN_MAX];
    
    if (context == NULL) {
        return CPARSER_OK;
    }
    
    if (context->parser->mode != CPARSER_MODE_CONFIG) {      
        return cfg_waf_bridge_proxy_c2p_cmd(context, PROTO_HTTPS);
    } else {        
        if (!bridge_name_ptr || !*bridge_name_ptr || !httpsport_ptr) {
            return CPARSER_NOT_OK;
        }

        if (!PORT_IN_RANGE(*httpsport_ptr)) {
            cli_printf_info(context, "Invalid port, the range must be 1~65535!\n");    
            return CPARSER_NOT_OK;
        }
        
        /* 检测桥设备 */
#if 0
        rv = interface_find(*bridge_name_ptr);
        if (rv != OK) {
            cli_printf_info(context, "bridge %s do no exist!\n", *bridge_name_ptr);
            return CPARSER_NOT_OK;
        }
#else        
        rv = bridge_check(*bridge_name_ptr);
        if (rv != OK) {
            cli_printf_info(context, 
                "No %s , or must have two or more members!\n", *bridge_name_ptr);
            return CPARSER_NOT_OK;
        }
#endif      
        /* 创建桥和端口，网桥代理模式必须要配置桥名字 */
        rv = create_bridge_port(context, *bridge_name_ptr, *httpsport_ptr, 
            INNER_HTTPS, PROTO_HTTPS, WORK_BRIDGE);
        if (rv != OK) {
            return CPARSER_OK;
        }
        snprintf(buf, COMMAND_LEN_MAX, "bridge %s https %d", *bridge_name_ptr, *httpsport_ptr);
        admin_log_process(context, buf);
        
        return CPARSER_OK;
    }     
}

cparser_result_t cparser_cmd_bridge_proxy_no_bridge_bridge_name_http_httpport(cparser_context_t *context,
                   char **bridge_name_ptr, uint32_t *httpport_ptr)
{
    int rv;
    char buf[COMMAND_LEN_MAX];
    
    if (context == NULL) {
        return CPARSER_OK;
    }
    
    if (context->parser->mode != CPARSER_MODE_CONFIG) {       
        return CPARSER_OK;
    } else {    
        if (!bridge_name_ptr || !*bridge_name_ptr) {
            return CPARSER_NOT_OK;
        }

        if (!PORT_IN_RANGE(*httpport_ptr)) {
            cli_printf_info(context, "Invalid port, the range must be 1~65535!\n");    
            return CPARSER_NOT_OK;
        }
        
        /* 检测桥设备 */
        rv = interface_find(*bridge_name_ptr);
        if (rv != OK) {
            cli_printf_info(context, "bridge %s do no exist!\n", *bridge_name_ptr);
            return CPARSER_NOT_OK;
        }
        
        (void)destroy_bridge_port(context, *bridge_name_ptr, *httpport_ptr, PROTO_HTTP);
        
        snprintf(buf, COMMAND_LEN_MAX, "no bridge %s http %d", *bridge_name_ptr, *httpport_ptr);
        admin_log_process(context, buf);    
        return CPARSER_OK;
    }        
}

cparser_result_t cparser_cmd_bridge_proxy_no_bridge_bridge_name_https_httpsport(cparser_context_t *context,
                   char **bridge_name_ptr, uint32_t *httpsport_ptr)
{
    int rv;
    char buf[COMMAND_LEN_MAX];
    
    if (context == NULL) {
        return CPARSER_OK;
    }
    
    if (context->parser->mode != CPARSER_MODE_CONFIG) {       
        return CPARSER_OK;
    } else {
        if (!bridge_name_ptr || !*bridge_name_ptr) {
            return CPARSER_NOT_OK;
        }

        if (!PORT_IN_RANGE(*httpsport_ptr)) {
            cli_printf_info(context, "Invalid port, the range must be 1~65535!\n");    
            return CPARSER_NOT_OK;
        }
        
        /* 检测桥设备 */
        rv = interface_find(*bridge_name_ptr);
        if (rv != OK) {
            cli_printf_info(context, "bridge %s do no exist!\n", *bridge_name_ptr);
            return CPARSER_NOT_OK;
        }

        (void)destroy_bridge_port(context, *bridge_name_ptr, *httpsport_ptr, PROTO_HTTPS);

        snprintf(buf, COMMAND_LEN_MAX, "no bridge %s https %d", *bridge_name_ptr, *httpsport_ptr);
        admin_log_process(context, buf);
        
        return CPARSER_OK;
    }       
}

cparser_result_t cparser_cmd_bridge_proxy_commit(cparser_context_t *context)
{
    int rv;
    char buf[COMMAND_LEN_MAX];
    
    if (context == NULL) {
        return CPARSER_OK;
    } 

    if (context->parser->mode != CPARSER_MODE_CONFIG) { 
        if (ap_work_mode == WORK_BRIDGE) {
            if (context->parser->mode == CPARSER_MODE_WRITE) {
                assert(context->parser->fp);
                cli_fprintf(context, "commit\n");
            } else {
                cli_printf(context, "commit\n");
            }
        }
        return CPARSER_OK;
    } else {
        ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, ap_main_server, "set work-mode online bridge-proxy");       
        rv = ap_config_update(context, WORK_BRIDGE, 1, CLI_REST);
        if (rv != OK) {
            cli_printf_info(context, "update work mode failure!\n");
            return CPARSER_NOT_OK;
        }

        snprintf(buf, COMMAND_LEN_MAX, "commit");
        admin_log_process(context, buf);
        
        return CPARSER_OK;
    }     
}

/* 路由代理配置相关 */
cparser_result_t cparser_cmd_pe_protect_engine_work_mode_online_route_proxy(cparser_context_t *context)
{
    char buf[COMMAND_LEN_MAX];
    char prompt[CPARSER_MAX_PROMPT];
    
    if (context == NULL) {
        return CPARSER_OK;
    }

    if (context->parser->mode != CPARSER_MODE_CONFIG) { 
        if (BitGet(work_mode_opt_flags[WORK_ROUTE], MODE_FLAG)) {
            cfg_waf_work_mode_c2p_cmd(context, WORK_ROUTE);
        }
        
        context->parser->root_level++;
        context->parser->root[context->parser->root_level] = context->parser->cur_node->children;
        cparser_walk(context->parser, cparser_running_conf_walker, NULL, "route_proxy");
        context->parser->root_level--; 
        
        return CPARSER_OK;
    } else { 
        snprintf(prompt, CPARSER_MAX_PROMPT, "%s(route-proxy)#", g_cli_prompt);        
        snprintf(buf, COMMAND_LEN_MAX, "protect-engine work-mode online route-proxy");
        admin_log_process(context, buf);        
        BitSet(work_mode_opt_flags[WORK_ROUTE], MODE_FLAG);
        return cparser_submode_enter(context->parser, NULL, prompt);
    }      
}

static cparser_result_t cfg_waf_route_proxy_c2p_cmd(cparser_context_t *context, int proto)
{
    bridge_port_t *bridge_port;
    char strbuf[STR_LEN_MAX] = {0};

    if (ap_bridge_ports) {
        bridge_port = ap_bridge_ports->next;
    } else {
        return CPARSER_OK;
    }
   
    if (proto == PROTO_HTTP) {
        sprintf(strbuf, "http");
    } else {
        sprintf(strbuf, "https");
    }
    
    while (bridge_port) {
        if (bridge_port->proto == proto && bridge_port->create_mode == WORK_ROUTE) {
            if (context->parser->mode == CPARSER_MODE_WRITE) {
                assert(context->parser->fp);
                cli_fprintf(context, "%s %d\n", 
                    strbuf, bridge_port->ser_port);
            } else {
                cli_printf(context, "%s %d\n", 
                    strbuf, bridge_port->ser_port);
            }
        }
        bridge_port = bridge_port->next;
    }

    return CPARSER_OK;
}

cparser_result_t cparser_cmd_route_proxy_http_httpport(cparser_context_t *context, uint32_t *httpport_ptr)
{
    int rv;
    char buf[COMMAND_LEN_MAX];
    
    if (context == NULL) {
        return CPARSER_OK;
    }
    
    if (context->parser->mode != CPARSER_MODE_CONFIG) {  
        return cfg_waf_route_proxy_c2p_cmd(context, PROTO_HTTP);
    } else {      
        if (!httpport_ptr) {
            return CPARSER_NOT_OK;
        }

        if (!PORT_IN_RANGE(*httpport_ptr)) {
            cli_printf_info(context, "Invalid port, the range must be 1~65535!\n");    
            return CPARSER_NOT_OK;
        }
        
        /* 创建端口，路由代理模式不能配置桥名字 */
        rv = create_bridge_port(context, NULL, *httpport_ptr, INNER_HTTP, PROTO_HTTP, WORK_ROUTE);
        if (rv != OK) {
            cli_printf_info(context, "add port fail!\n");
            return CPARSER_NOT_OK;
        }

        snprintf(buf, COMMAND_LEN_MAX, "http %d", *httpport_ptr);
        admin_log_process(context, buf);
        return CPARSER_OK;
    }
}

cparser_result_t cparser_cmd_route_proxy_https_httpsport(cparser_context_t *context, 
                   uint32_t *httpsport_ptr)
{
    int rv;
    char buf[COMMAND_LEN_MAX];
    
    if (context == NULL) {
        return CPARSER_OK;
    }
       
    if (context->parser->mode != CPARSER_MODE_CONFIG) { 
        return cfg_waf_route_proxy_c2p_cmd(context, PROTO_HTTPS);
    } else {
        if (!httpsport_ptr) {
            return CPARSER_NOT_OK;
        }

        if (!PORT_IN_RANGE(*httpsport_ptr)) {
            cli_printf_info(context, 
                "Invalid port , the range must be 1~65535!\n");    
            return CPARSER_NOT_OK;
        }
        
        /* 创建端口，路由代理模式不能配置桥名字 */
        rv = create_bridge_port(context, NULL, *httpsport_ptr, INNER_HTTPS, PROTO_HTTPS, WORK_ROUTE);
        if (rv != OK) {
            return CPARSER_NOT_OK;
        }
        
        snprintf(buf, COMMAND_LEN_MAX, "https %d", *httpsport_ptr);
        admin_log_process(context, buf);
        return CPARSER_OK;
    } 
}

cparser_result_t cparser_cmd_route_proxy_no_http_httpport(cparser_context_t *context, 
                   uint32_t *httpport_ptr)
{
    char buf[COMMAND_LEN_MAX];
    
    if (context == NULL) {
        return CPARSER_OK;
    }

    if (context->parser->mode != CPARSER_MODE_CONFIG) {    
        return CPARSER_OK;
    } else {
        if (!httpport_ptr) {
            return CPARSER_NOT_OK;
        }

        if (!PORT_IN_RANGE(*httpport_ptr)) {
            cli_printf_info(context, "Invalid port, the range must be 1~65535!\n");    
            return CPARSER_NOT_OK;
        }
        
        (void)destroy_bridge_port(context, NULL, *httpport_ptr, PROTO_HTTP);
        snprintf(buf, COMMAND_LEN_MAX, "no http %d", *httpport_ptr);
        admin_log_process(context, buf);
        return CPARSER_OK;
    }   

}

cparser_result_t cparser_cmd_route_proxy_no_https_httpsport(cparser_context_t *context,
                   uint32_t *httpsport_ptr)
{
    char buf[COMMAND_LEN_MAX];
    
    if (context == NULL) {
        return CPARSER_OK;
    }
    
    if (context->parser->mode != CPARSER_MODE_CONFIG) {         
        return CPARSER_OK;
    } else {
        if (!httpsport_ptr) {
            return CPARSER_NOT_OK;
        }

        if (!PORT_IN_RANGE(*httpsport_ptr)) {
            cli_printf_info(context, "Invalid port, the range must be 1~65535!\n");    
            return CPARSER_NOT_OK;
        }
        
        (void)destroy_bridge_port(context, NULL, *httpsport_ptr, PROTO_HTTPS);
        snprintf(buf, COMMAND_LEN_MAX, "no https %d", *httpsport_ptr);
        admin_log_process(context, buf);
        return CPARSER_OK;
    } 
}

cparser_result_t cparser_cmd_route_proxy_commit(cparser_context_t *context)
{
    int rv;
    char buf[COMMAND_LEN_MAX];
    
    if (context == NULL) {
        return CPARSER_OK;
    } 
    
    if (context->parser->mode != CPARSER_MODE_CONFIG) { 
        if (ap_work_mode == WORK_ROUTE) {
            if (context->parser->mode == CPARSER_MODE_WRITE) {
                assert(context->parser->fp);
                cli_fprintf(context, "commit\n");
            } else {
                cli_printf(context, "commit\n");
            }
        }
        return CPARSER_OK;
    } else {
        ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, ap_main_server, "set work-mode online route-proxy");
        rv = ap_config_update(context, WORK_ROUTE, 1, CLI_REST);
        if (rv != OK) {
            cli_printf_info(context, "update work mode failure!\n");
            return CPARSER_NOT_OK;
        }

        snprintf(buf, COMMAND_LEN_MAX, "commit");
        admin_log_process(context, buf);

        return CPARSER_OK;
    }     
}

/* 反向代理配置相关 */
cparser_result_t cparser_cmd_pe_protect_engine_work_mode_online_reverse_proxy(cparser_context_t *context)
{
    char buf[COMMAND_LEN_MAX];
    char prompt[CPARSER_MAX_PROMPT];
    
    if (context == NULL) {
        return CPARSER_OK;
    }

    if (context->parser->mode != CPARSER_MODE_CONFIG) { 
        if (BitGet(work_mode_opt_flags[WORK_REVERSE], MODE_FLAG)) {
            cfg_waf_work_mode_c2p_cmd(context, WORK_REVERSE);
        }
        
        context->parser->root_level++;
        context->parser->root[context->parser->root_level] = context->parser->cur_node->children;
        cparser_walk(context->parser, cparser_running_conf_walker, NULL, "reverse_proxy");
        context->parser->root_level--;  
        
        return CPARSER_OK;
    } else { 
        snprintf(prompt, CPARSER_MAX_PROMPT, "%s(reverse-proxy)#", g_cli_prompt);        
        snprintf(buf, COMMAND_LEN_MAX, "protect-engine work-mode online reverse-proxy");
        admin_log_process(context, buf);
        BitSet(work_mode_opt_flags[WORK_REVERSE], MODE_FLAG);
        return cparser_submode_enter(context->parser, NULL, prompt);
    }  
}

static cparser_result_t cfg_waf_reverse_proxy_c2p_cmd(cparser_context_t *context, int proto)
{
    listen_port_t *listen_port;
    char strbuf[STR_LEN_MAX];

    if (ap_listen_ports) {
        listen_port = ap_listen_ports->next;
    } else {
        return CPARSER_OK;
    }

    if (proto == PROTO_HTTP) {
        sprintf(strbuf, "http");
    } else {
        sprintf(strbuf, "https");
    }
        
    while (listen_port) {
        if (listen_port->proto == proto && listen_port->create_mode == WORK_REVERSE) {
            if (context->parser->mode == CPARSER_MODE_WRITE) {
                assert(context->parser->fp);
                cli_fprintf(context, "ip-address %d.%d.%d.%d %s %d\n", 
                    NIPQUAD(listen_port->ipaddr.s_addr), strbuf, listen_port->port);
            } else {
                cli_printf(context, "ip-address %d.%d.%d.%d %s %d\n", 
                    NIPQUAD(listen_port->ipaddr.s_addr), strbuf, listen_port->port);
            }
        }
        listen_port = listen_port->next;
    }

    return CPARSER_OK;
}

cparser_result_t cparser_cmd_reverse_proxy_ip_address_ipaddr_http_httpport(cparser_context_t *context,
                   uint32_t *ipaddr_ptr, uint32_t *httpport_ptr)
{
    int rv;
    listen_port_t *listen_port;
    struct in_addr ipaddr;
    char buf[COMMAND_LEN_MAX];
    
    if (context == NULL) {
        return CPARSER_NOT_OK;
    }

    if (context->parser->mode != CPARSER_MODE_CONFIG) { 
        return cfg_waf_reverse_proxy_c2p_cmd(context, PROTO_HTTP);
    } else {
        if (!ipaddr_ptr || !httpport_ptr) {
            return CPARSER_NOT_OK;
        }
        
        if (*ipaddr_ptr == 0) {
            cli_printf_info(context, "Invalid ip address [%d.%d.%d.%d]!\n", NIPQUAD(*ipaddr_ptr));
            return CPARSER_NOT_OK;
        }
            
        if (!PORT_IN_RANGE(*httpport_ptr)) {
            cli_printf_info(context, "Invalid port, the range must be 1~65535!\n");    
            return CPARSER_NOT_OK;
        }
        
        ipaddr.s_addr = *ipaddr_ptr;
        listen_port = find_listen_port(ipaddr, *httpport_ptr, WORK_REVERSE);
        if (listen_port) {   
            cli_printf_info(context, "the ip address [%d.%d.%d.%d:%d] have been added!\n", 
                NIPQUAD(*ipaddr_ptr), *httpport_ptr);
            return DECLINED;
        }
        
        rv = create_listen_port(context, *ipaddr_ptr, *httpport_ptr, PROTO_HTTP, WORK_REVERSE);
        if (rv != OK) {
            return CPARSER_NOT_OK;
        }

        snprintf(buf, COMMAND_LEN_MAX, "ip-address %d.%d.%d.%d http %d",
            NIPQUAD(*ipaddr_ptr), *httpport_ptr);
        admin_log_process(context, buf);
        return CPARSER_OK;
    }     
}

cparser_result_t cparser_cmd_reverse_proxy_ip_address_ipaddr_https_httpsport(cparser_context_t *context,
                   uint32_t *ipaddr_ptr, uint32_t *httpsport_ptr)
{
    int rv;
    listen_port_t *listen_port;
    struct in_addr ipaddr;
    char buf[COMMAND_LEN_MAX];
    
    if (context == NULL) {
        return CPARSER_OK;
    }
       
    if (context->parser->mode != CPARSER_MODE_CONFIG) { 
        return cfg_waf_reverse_proxy_c2p_cmd(context, PROTO_HTTPS);
    } else {
        if (!ipaddr_ptr || !httpsport_ptr) {
            return CPARSER_NOT_OK;
        }

        if (*ipaddr_ptr == 0) {
            cli_printf_info(context, "Invalid ip address [%d.%d.%d.%d]!\n", NIPQUAD(*ipaddr_ptr));
            return CPARSER_NOT_OK;
        }
        
        if (!PORT_IN_RANGE(*httpsport_ptr)) {
            cli_printf_info(context, "Invalid port, the range must be 1~65535!\n");    
            return CPARSER_NOT_OK;
        }
        
        ipaddr.s_addr = *ipaddr_ptr;
        listen_port = find_listen_port(ipaddr, *httpsport_ptr, WORK_REVERSE);
        if (listen_port) {   
            cli_printf_info(context, "the ip address [%d.%d.%d.%d:%d] have been added!\n", 
                NIPQUAD(*ipaddr_ptr), *httpsport_ptr);
            return DECLINED;
        }

        rv = create_listen_port(context, *ipaddr_ptr, *httpsport_ptr, PROTO_HTTPS, WORK_REVERSE);
        if (rv != OK) {
            return CPARSER_NOT_OK;
        }

        snprintf(buf, COMMAND_LEN_MAX, "ip-address %d.%d.%d.%d https %d",
            NIPQUAD(*ipaddr_ptr), *httpsport_ptr);
        admin_log_process(context, buf);
        return CPARSER_OK;
    }    
}

cparser_result_t cparser_cmd_reverse_proxy_no_ip_address_ipaddr_http_httpport(cparser_context_t *context,
                   uint32_t *ipaddr_ptr, uint32_t *httpport_ptr)
{
    int rv;
    listen_port_t *listen_port;
    struct in_addr ipaddr;
    char buf[COMMAND_LEN_MAX];
    
    if (context == NULL) {
        return CPARSER_OK;
    }

    if (context->parser->mode != CPARSER_MODE_CONFIG) { 
        return CPARSER_OK;
    } else { 
        if (!ipaddr_ptr || !httpport_ptr) {
            return CPARSER_NOT_OK;
        }

        if (*ipaddr_ptr == 0) {
            cli_printf_info(context, "Invalid ip address [%d.%d.%d.%d]!\n", NIPQUAD(*ipaddr_ptr));
            return CPARSER_NOT_OK;
        }
        
        if (!PORT_IN_RANGE(*httpport_ptr)) {
            cli_printf_info(context, "Invalid port, the range must be 1~65535!\n");    
            return CPARSER_NOT_OK;
        }
        
        ipaddr.s_addr = *ipaddr_ptr;
        listen_port = find_listen_port(ipaddr, *httpport_ptr, WORK_REVERSE); 
        if (!listen_port || listen_port->proto != PROTO_HTTP) {   
            cli_printf_info(context, "the ip address [%d.%d.%d.%d] http %d have not been added!\n", 
                NIPQUAD(*ipaddr_ptr), *httpport_ptr);
            return DECLINED;
        }        
        
        rv = destroy_listen_port(context, *ipaddr_ptr, *httpport_ptr, PROTO_HTTP, WORK_REVERSE);
        if (rv != OK) {
            return CPARSER_NOT_OK;
        }
        
        snprintf(buf, COMMAND_LEN_MAX, "no ip-address %d.%d.%d.%d http %d",
            NIPQUAD(*ipaddr_ptr), *httpport_ptr);
        admin_log_process(context, buf);
        return CPARSER_OK;
    }    
}

cparser_result_t cparser_cmd_reverse_proxy_no_ip_address_ipaddr_https_httpsport(cparser_context_t *context,
                   uint32_t *ipaddr_ptr, uint32_t *httpsport_ptr)
{
   int rv;
    listen_port_t *listen_port;
    struct in_addr ipaddr;
    char buf[COMMAND_LEN_MAX];
        
    if (context == NULL) {
        return CPARSER_OK;
    }
    
    if (context->parser->mode != CPARSER_MODE_CONFIG) {        
        return CPARSER_OK;
    } else {
        if (!ipaddr_ptr || !httpsport_ptr) {
            return CPARSER_NOT_OK;
        }

        if (*ipaddr_ptr == 0) {
            cli_printf_info(context, "Invalid ip address [%d.%d.%d.%d]!\n", NIPQUAD(*ipaddr_ptr));
            return CPARSER_NOT_OK;
        }
        
        if (!PORT_IN_RANGE(*httpsport_ptr)) {
            cli_printf_info(context, "Invalid port, the range must be 1~65535!\n");    
            return CPARSER_NOT_OK;
        }
        
        ipaddr.s_addr = *ipaddr_ptr;
        listen_port = find_listen_port(ipaddr, *httpsport_ptr, WORK_REVERSE);
        if (!listen_port || listen_port->proto != PROTO_HTTPS) {   
            cli_printf_info(context, "the ip address [%d.%d.%d.%d] https %d have not been added!\n", 
                NIPQUAD(*ipaddr_ptr), *httpsport_ptr);
            return DECLINED;
        }
        
        rv = destroy_listen_port(context, *ipaddr_ptr, *httpsport_ptr, PROTO_HTTPS, WORK_REVERSE);
        if (rv != OK) {
            return CPARSER_NOT_OK;
        }

        snprintf(buf, COMMAND_LEN_MAX, "no ip-address %d.%d.%d.%d https %d",
            NIPQUAD(*ipaddr_ptr), *httpsport_ptr);
        admin_log_process(context, buf); 
        return CPARSER_OK;
    }    
}

cparser_result_t cparser_cmd_reverse_proxy_commit(cparser_context_t *context)
{
    int rv;
    char buf[COMMAND_LEN_MAX];
    
    if (context == NULL) {
        return CPARSER_OK;
    } 
    
    if (context->parser->mode != CPARSER_MODE_CONFIG) { 
        if (ap_work_mode == WORK_REVERSE) {
            if (context->parser->mode == CPARSER_MODE_WRITE) {
                assert(context->parser->fp);
                cli_fprintf(context, "commit\n");
            } else {
                cli_printf(context, "commit\n");
            }
        }
        return CPARSER_OK;
    } else {
        ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, ap_main_server, "set work-mode online reverse-proxy");
        rv = ap_config_update(context, WORK_REVERSE, 1, CLI_REST);
        if (rv != OK) {
            cli_printf_info(context, "update work mode failure!\n");
            return CPARSER_NOT_OK;
        }

        snprintf(buf, COMMAND_LEN_MAX, "commit");
        admin_log_process(context, buf);

        return CPARSER_OK;
    }     
}

/* 离线代理配置相关 */
cparser_result_t cparser_cmd_pe_protect_engine_work_mode_offline(cparser_context_t *context)
{
    char buf[COMMAND_LEN_MAX];
    char prompt[CPARSER_MAX_PROMPT];
    
    if (context == NULL) {
        return CPARSER_OK;
    }

    if (context->parser->mode != CPARSER_MODE_CONFIG) { 
        if (BitGet(work_mode_opt_flags[WORK_OFFLINE], MODE_FLAG)) {
            cfg_waf_work_mode_c2p_cmd(context, WORK_OFFLINE);
        }
        
        context->parser->root_level++;
        context->parser->root[context->parser->root_level] = context->parser->cur_node->children;
        cparser_walk(context->parser, cparser_running_conf_walker, NULL, "offline");
        context->parser->root_level--;  
        
        return CPARSER_OK;
    } else { 
        snprintf(prompt, CPARSER_MAX_PROMPT, "%s(offline)#", g_cli_prompt);       
        snprintf(buf, COMMAND_LEN_MAX, "protect-engine work-mode offline");
        admin_log_process(context, buf);
        BitSet(work_mode_opt_flags[WORK_OFFLINE], MODE_FLAG);
        return cparser_submode_enter(context->parser, NULL, prompt);
    }          
}

static cparser_result_t cfg_waf_offline_interface_c2p_cmd(cparser_context_t *context)
{
    int i;

    for (i = 0; i < OFFLINE_INTF_NUM; i++) {
        if (BitGet(ap_off_iface, i + 1)) {
            if (context->parser->mode == CPARSER_MODE_WRITE) {
                assert(context->parser->fp);
                cli_fprintf(context, "interface eth%d\n", i);
            } else {
                cli_printf(context, "interface eth%d\n", i);
            }
        }
    }

    return CPARSER_OK;
}

static int get_offline_interface_num()
{
    int i;
    int intf_num = 0;

    /* 统计已配置的网卡数量 */
    for (i = 0; i < OFFLINE_INTF_NUM; i++) {
        if (BitGet(ap_off_iface, i + 1)) {
            intf_num++;
        }
    }    

    return intf_num;
}

/* 配置离线接口和IP地址模式 */
cparser_result_t cparser_cmd_offline_interface_interface_name(cparser_context_t *context,
                    char **interface_name_ptr)
{
    int rv;
    char intf;
    char *p;
    char buf[COMMAND_LEN_MAX];
    
    if (context == NULL) {
        return CPARSER_NOT_OK;
    }

    if (context->parser->mode != CPARSER_MODE_CONFIG) { 
        return cfg_waf_offline_interface_c2p_cmd(context);
    } else {    
        if (!interface_name_ptr || !*interface_name_ptr) {
            return CPARSER_OK;
        }
        
        if (get_offline_interface_num() >= OFFLINE_INTF_MAX) {
            cli_printf_info(context, "The interface number can't exceed %d\n", OFFLINE_INTF_MAX);
            return CPARSER_NOT_OK;
        }
        
        rv = ap_query_interface_exist(*interface_name_ptr);
        if (rv != 0) {
            cli_printf_info(context, "the interface do not exist.\n");
            return CPARSER_NOT_OK;
        }

        p = *interface_name_ptr + strlen("eth");
        intf = atoi(p);
        
        if ((intf < 0) || (intf >= OFFLINE_INTF_NUM)) {
            cli_printf_info(context, "interface-type interface-number invalid!\n");
            return CPARSER_NOT_OK;
        }

        BitSet(ap_off_iface, intf + 1);
        
        snprintf(buf, COMMAND_LEN_MAX, "interface %s", *interface_name_ptr);
        admin_log_process(context, buf);
        
        return CPARSER_OK;
    }
}

cparser_result_t cparser_cmd_offline_no_interface_interface_name(cparser_context_t *context,
                    char **interface_name_ptr)
{
    int rv;
    char intf;
    char *p;
    char buf[COMMAND_LEN_MAX];
    
    if (context == NULL) {
        return CPARSER_NOT_OK;
    }
   
    if (context->parser->mode != CPARSER_MODE_CONFIG) {    
        return CPARSER_OK;
    } else {
        if (!interface_name_ptr || !*interface_name_ptr) {
            return CPARSER_OK;
        }

        rv = ap_query_interface_exist(*interface_name_ptr);
        if (rv != OK) {
            cli_printf_info(context, "the interface %s do not exist!\n", *interface_name_ptr);
            return CPARSER_NOT_OK;
        }

        p = *interface_name_ptr + strlen("eth");
        intf = atoi(p);
        
        if ((intf < 0) || (intf > OFFLINE_INTF_NUM)) {
            cli_printf_info(context, "interface-type interface-number invalid!\n");
            return CPARSER_NOT_OK;
        }

        BitClr(ap_off_iface, intf + 1);
        
        snprintf(buf, COMMAND_LEN_MAX, "no interface %s", *interface_name_ptr);
        admin_log_process(context, buf);
        
        return CPARSER_OK;
    }
}

static cparser_result_t cfg_waf_offline_listen_c2p_cmd(cparser_context_t *context, int proto)
{
    listen_port_t *listen_port;
    char strbuf[STR_LEN_MAX];

    if (ap_listen_ports) {
        listen_port = ap_listen_ports->next;
    } else {
        return CPARSER_OK;
    }

    if (proto == PROTO_HTTP) {
        sprintf(strbuf, "http");
    } else {
        sprintf(strbuf, "https");
    }
        
    while (listen_port) {
        if (listen_port->proto == proto && listen_port->create_mode  == WORK_OFFLINE) {
            if (context->parser->mode == CPARSER_MODE_WRITE) {
                assert(context->parser->fp);
                cli_fprintf(context, "ip-address %d.%d.%d.%d %s %d\n", 
                    NIPQUAD(listen_port->ipaddr.s_addr), strbuf, listen_port->port);
            } else {
                cli_printf(context, "ip-address %d.%d.%d.%d %s %d\n", 
                    NIPQUAD(listen_port->ipaddr.s_addr), strbuf, listen_port->port);
            }
        }
        listen_port = listen_port->next;
    }

    return CPARSER_OK;
}


cparser_result_t cparser_cmd_offline_ip_address_ipaddr_http_httpport(cparser_context_t *context,
                    uint32_t *ipaddr_ptr, uint32_t *httpport_ptr)
{
    int rv;
    listen_port_t *listen_port;
    struct in_addr ipaddr;
    char buf[COMMAND_LEN_MAX];
    
    if (context == NULL) {
        return CPARSER_NOT_OK;
    }

    if (context->parser->mode != CPARSER_MODE_CONFIG) { 
        return cfg_waf_offline_listen_c2p_cmd(context, PROTO_HTTP);
    } else {
        if (!ipaddr_ptr || !httpport_ptr) {
            return CPARSER_NOT_OK;
        }

        if (*ipaddr_ptr == 0) {
            cli_printf_info(context, "Invalid ip address [%d.%d.%d.%d]!\n", NIPQUAD(*ipaddr_ptr));
            return CPARSER_NOT_OK;
        }
        
        if (!PORT_IN_RANGE(*httpport_ptr)) {
            cli_printf_info(context, "Invalid port, the range must be 1~65535!\n");    
            return CPARSER_NOT_OK;
        }
        
        ipaddr.s_addr = *ipaddr_ptr;
        listen_port = find_listen_port(ipaddr, *httpport_ptr, WORK_OFFLINE);
        if (listen_port) {   
            cli_printf_info(context, "the ip address [%d.%d.%d.%d:%d] have been added!\n", 
                NIPQUAD(*ipaddr_ptr), *httpport_ptr);
            return DECLINED;
        }
                
        rv = create_listen_port(context, *ipaddr_ptr, *httpport_ptr, PROTO_HTTP, WORK_OFFLINE);
        if (rv != OK) {
            return CPARSER_NOT_OK;
        }
        
        snprintf(buf, COMMAND_LEN_MAX, "ip-address %d.%d.%d.%d http %d", 
            NIPQUAD(*ipaddr_ptr), *httpport_ptr);
        admin_log_process(context, buf);
        
        return CPARSER_OK;
    }
}

cparser_result_t cparser_cmd_offline_no_ip_address_ipaddr_http_httpport(cparser_context_t *context,
                    uint32_t *ipaddr_ptr, uint32_t *httpport_ptr)
{
    int rv;
    listen_port_t *listen_port;
    struct in_addr ipaddr;
    char buf[COMMAND_LEN_MAX];
    
    if (context == NULL) {
        return CPARSER_OK;
    }

    if (context->parser->mode != CPARSER_MODE_CONFIG) { 
        return CPARSER_OK;
    } else {
        if (!ipaddr_ptr || !httpport_ptr) {
            return CPARSER_NOT_OK;
        }

        if (*ipaddr_ptr == 0) {
            cli_printf_info(context, "Invalid ip address [%d.%d.%d.%d]!\n", NIPQUAD(*ipaddr_ptr));
            return CPARSER_NOT_OK;
        }
        
        if (!PORT_IN_RANGE(*httpport_ptr)) {
            cli_printf_info(context, "Invalid port, the range must be 1~65535!\n");    
            return CPARSER_NOT_OK;
        }
        
        ipaddr.s_addr = *ipaddr_ptr;
        listen_port = find_listen_port(ipaddr, *httpport_ptr, WORK_OFFLINE);
        if (!listen_port || listen_port->proto != PROTO_HTTP) {   
            cli_printf_info(context, "the ip address [%d.%d.%d.%d] http %d have not been added!\n", 
                NIPQUAD(*ipaddr_ptr), *httpport_ptr);
            return DECLINED;
        }

        rv = destroy_listen_port(context, *ipaddr_ptr, *httpport_ptr, PROTO_HTTP, WORK_OFFLINE);
        if (rv != OK) {
            return CPARSER_NOT_OK;
        }

        snprintf(buf, COMMAND_LEN_MAX, "no ip-address %d.%d.%d.%d http %d", 
            NIPQUAD(*ipaddr_ptr), *httpport_ptr);
        admin_log_process(context, buf);
        
        return CPARSER_OK;
    }    
}

cparser_result_t cparser_cmd_offline_ip_address_ipaddr_https_httpsport(cparser_context_t *context,
                    uint32_t *ipaddr_ptr, uint32_t *httpsport_ptr)
{
    int rv;
    listen_port_t *listen_port;
    struct in_addr ipaddr;
    char buf[COMMAND_LEN_MAX];
    
    if (context == NULL) {
        return CPARSER_OK;
    }
       
    if (context->parser->mode != CPARSER_MODE_CONFIG) { 
        return cfg_waf_offline_listen_c2p_cmd(context, PROTO_HTTPS);
    } else {
        if (!ipaddr_ptr || !httpsport_ptr) {
            return CPARSER_NOT_OK;
        }

        if (*ipaddr_ptr == 0) {
            cli_printf_info(context, "Invalid ip address [%d.%d.%d.%d]!\n", NIPQUAD(*ipaddr_ptr));
            return CPARSER_NOT_OK;
        }
        
        if (!PORT_IN_RANGE(*httpsport_ptr)) {
            cli_printf_info(context, "Invalid port, the range must be 1~65535!\n");    
            return CPARSER_NOT_OK;
        }
        
        ipaddr.s_addr = *ipaddr_ptr;
        listen_port = find_listen_port(ipaddr, *httpsport_ptr, WORK_OFFLINE);
        if (listen_port) {   
            cli_printf_info(context, "the ip address [%d.%d.%d.%d:%d] have been added!\n", 
                NIPQUAD(*ipaddr_ptr), *httpsport_ptr);
            return DECLINED;
        }
               
        rv = create_listen_port(context, *ipaddr_ptr, *httpsport_ptr, PROTO_HTTPS, WORK_OFFLINE);
        if (rv != OK) {
            return CPARSER_NOT_OK;
        }

        snprintf(buf, COMMAND_LEN_MAX, "ip-address %d.%d.%d.%d https %d", 
            NIPQUAD(*ipaddr_ptr), *httpsport_ptr);
        admin_log_process(context, buf);
        
        return CPARSER_OK;
    }    
}

cparser_result_t cparser_cmd_offline_no_ip_address_ipaddr_https_httpsport(cparser_context_t *context,
                    uint32_t *ipaddr_ptr, uint32_t *httpsport_ptr)
{
    int rv;
    listen_port_t *listen_port;
    struct in_addr ipaddr;
    char buf[COMMAND_LEN_MAX];
    
    if (context == NULL) {
        return CPARSER_OK;
    }
    
    if (context->parser->mode != CPARSER_MODE_CONFIG) {        
        return CPARSER_OK;
    } else {
        if (!ipaddr_ptr || !httpsport_ptr) {
            return CPARSER_NOT_OK;
        }

        if (*ipaddr_ptr == 0) {
            cli_printf_info(context, "Invalid ip address [%d.%d.%d.%d]!\n", NIPQUAD(*ipaddr_ptr));
            return CPARSER_NOT_OK;
        }
        
        if (!PORT_IN_RANGE(*httpsport_ptr)) {
            cli_printf_info(context, "Invalid port, the range must be 1~65535!\n");    
            return CPARSER_NOT_OK;
        }
        
        ipaddr.s_addr = *ipaddr_ptr;
        listen_port = find_listen_port(ipaddr, *httpsport_ptr, WORK_OFFLINE);
        if (!listen_port || listen_port->proto != PROTO_HTTPS) {   
            cli_printf_info(context, "the ip address [%d.%d.%d.%d] https %d have not been added!\n", 
                NIPQUAD(*ipaddr_ptr), *httpsport_ptr);
            return DECLINED;
        }
        
        rv = destroy_listen_port(context, *ipaddr_ptr, *httpsport_ptr, PROTO_HTTPS, WORK_OFFLINE);
        if (rv != OK) {
            return CPARSER_NOT_OK;
        }
               
        snprintf(buf, COMMAND_LEN_MAX, "no ip-address %d.%d.%d.%d https %d", 
            NIPQUAD(*ipaddr_ptr), *httpsport_ptr);
        admin_log_process(context, buf);
        
        return CPARSER_OK;
    }    
}

cparser_result_t cparser_cmd_offline_commit(cparser_context_t *context)
{
    int rv;
    char buf[COMMAND_LEN_MAX];
    
    if (context->parser->mode != CPARSER_MODE_CONFIG) {        
        if (ap_work_mode == WORK_OFFLINE) {       
            if (context->parser->mode == CPARSER_MODE_WRITE) {
                assert(context->parser->fp);
                cli_fprintf(context, "commit\n");
            } else {
                cli_printf(context, "commit\n");                
            }
        }
        return CPARSER_OK;
    } else {
        /* 必须配置一个监听网卡 */
        if (get_offline_interface_num() == 0) {
            cli_printf_info(context, "Without a valid interface!\n");
            return CPARSER_NOT_OK;            
        }

        /* 必须配置一个监听地址 */
        if (get_listen_port_num(WORK_OFFLINE) == 0) {
            cli_printf_info(context, "Without a valid listen ipdress!\n");
            return CPARSER_NOT_OK;          
        }
        
        ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, ap_main_server, "set work-mode offline");
        rv = ap_config_update(context, WORK_OFFLINE, 1, CLI_REST);
        if (rv != OK) {
            cli_printf_info(context, "update engine config failure!\n");
            return CPARSER_NOT_OK;
        } 

        snprintf(buf, COMMAND_LEN_MAX, "commit");
        admin_log_process(context, buf);

        return CPARSER_OK;
    }
}

cparser_result_t cparser_cmd_pe_no_protect_engine_work_mode(cparser_context_t *context)
{
    ap_proxy_mode_t new_mode;
    int rv;
    char buf[COMMAND_LEN_MAX];

    if (context == NULL) {
        return CPARSER_OK;
    }
    
    if (context->parser->mode != CPARSER_MODE_CONFIG) { 
        return CPARSER_OK;
    } else {                 
        cli_printf_info(context, "set work-mode to defalut(bridge-proxy),"
            "the mode configure and server policy will be cleared.\n"); 

        new_mode = WORK_DEFAULT; 
        ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, ap_main_server, "set work-mode defalut");
        rv = ap_config_update(context, new_mode, 1, CLI_REST);
        if (rv != OK) {
            cli_printf_info(context, "update work mode failure!\n");
            return CPARSER_NOT_OK;
        }
        
        snprintf(buf, COMMAND_LEN_MAX, "no protect-engine work-mode");
        admin_log_process(context, buf);
        return CPARSER_OK;
    }       
}

/* 汉字编码相关 */
cparser_result_t cparser_cmd_pe_protect_engine_encode_encoding_type(cparser_context_t *context,
                    char **encoding_type_ptr)
{
    char buf[COMMAND_LEN_MAX];
    
    if (context == NULL) {
        return CPARSER_OK;
    }

    if (context->parser->mode != CPARSER_MODE_CONFIG) { 
        switch (encode_type) {
        case UTF_8:
            if (encode_type_flag) {
                if (context->parser->mode == CPARSER_MODE_WRITE) {
                    assert(context->parser->fp);
                    cli_fprintf(context, "protect-engine encode utf-8\n");
                } else {
                    cli_printf(context, "!\n");
                    cli_printf(context, "protect-engine encode utf-8\n");
                }  
            }
            break;
            
        case BIG5:
            if (context->parser->mode == CPARSER_MODE_WRITE) {
                assert(context->parser->fp);
                cli_fprintf(context, "protect-engine encode big5\n");
            } else {
                cli_printf(context, "!\n");
                cli_printf(context, "protect-engine encode big5\n");
            }  
            break;
            
        case GB2312:
            if (context->parser->mode == CPARSER_MODE_WRITE) {
                assert(context->parser->fp);
                cli_fprintf(context, "protect-engine encode gb2312\n");
            } else {
                cli_printf(context, "!\n");
                cli_printf(context, "protect-engine encode gb2312\n");
            }  
            break;
            
        case GBK:
            if (context->parser->mode == CPARSER_MODE_WRITE) {
                assert(context->parser->fp);
                cli_fprintf(context, "protect-engine encode gbk\n");
            } else {
                cli_printf(context, "!\n");
                cli_printf(context, "protect-engine encode gbk\n");
            } 
            break;
            
        case GB18030:
            if (context->parser->mode == CPARSER_MODE_WRITE) {
                assert(context->parser->fp);
                cli_fprintf(context, "protect-engine encode gb18030\n");
            } else {
                cli_printf(context, "!\n");
                cli_printf(context, "protect-engine encode gb18030\n");
            } 
            break;
            
        default:
            break;
        }
    } else {
        if (!encoding_type_ptr || !*encoding_type_ptr) {
            return CPARSER_NOT_OK;
        }
            
        if (!strcmp(*encoding_type_ptr, "utf-8")) {
            encode_type = UTF_8;
        } else if (!strcmp(*encoding_type_ptr, "big5")) {
            encode_type = BIG5;
        } else if (!strcmp(*encoding_type_ptr, "gb2312")) {
            encode_type = GB2312;
        } else if (!strcmp(*encoding_type_ptr, "gbk")) {
            encode_type = GBK;
        } else if (!strcmp(*encoding_type_ptr, "gb18030")) {
            encode_type = GB18030;
        }
        
        encode_type_flag = 1;
        snprintf(buf, COMMAND_LEN_MAX, "protect-engine encode %s", *encoding_type_ptr);
        admin_log_process(context, buf);
    }

    return CPARSER_OK;
}


cparser_result_t cparser_cmd_pe_no_protect_engine_encode(cparser_context_t *context)
{
    char buf[COMMAND_LEN_MAX];
    
    if (context == NULL) {
        return CPARSER_OK;
    }

    if (context->parser->mode != CPARSER_MODE_CONFIG) { 
        return CPARSER_OK;
    } else {
        encode_type = UTF_8;
        snprintf(buf, COMMAND_LEN_MAX, "no protect-engine encode");
        admin_log_process(context, buf);
        return CPARSER_OK;
    }  
}

static void show_bridge_mode(cparser_context_t *context)
{
    bridge_port_t *bridge_port;
    char strbuf[STR_LEN_MAX];
    int num = 0;
    
    if (ap_bridge_ports) {
        bridge_port = ap_bridge_ports->next;
    } else {
        bridge_port = NULL;
    } 

    cli_printf_info(context, "Work mode: bridge-proxy\n");
    if (ap_work_mode == WORK_BRIDGE) {
        cli_printf_info(context, "Work status: %s\n", WORK_MODE_ACTIVE);
    } else {  
        cli_printf_info(context, "Work status: %s\n", WORK_MODE_INACTIVE);
    }
    
    cli_printf_info(context, "Configuration as follows:\n");
    cli_printf_info(context, " No.     Bridge-Name     Protocol     Port\n");   
    while (bridge_port) {
        if (bridge_port->create_mode == WORK_BRIDGE && !bridge_port->deleted) {
            if (bridge_port->proto == PROTO_HTTP) {
                sprintf(strbuf, "http");
            } else {
                sprintf(strbuf, "https");
            }
            cli_printf_info(context, " %-3d     %-11s     %-8s     %d\n", ++num, bridge_port->br_name, 
                strbuf, bridge_port->ser_port);
        }
        bridge_port = bridge_port->next;
    }

    if (ap_work_mode == WORK_BRIDGE) {
        cli_printf_info(context, "Commit status: Succ\n");
    } else {
        cli_printf_info(context, "Commit status: Fail\n");    
    }
}

static void show_route_mode(cparser_context_t *context)
{
    bridge_port_t *bridge_port;
    char strbuf[STR_LEN_MAX];
    int num = 0;
    
    if (ap_bridge_ports) {
        bridge_port = ap_bridge_ports->next;
    } else {
        bridge_port = NULL;
    } 
    
    cli_printf_info(context, "Work mode: route-proxy\n");
    
    if (ap_work_mode == WORK_ROUTE) {
        cli_printf_info(context, "Work status: Succ\n");
    } else {
        cli_printf_info(context, "Work status: Fail\n");
    }
    
    cli_printf_info(context, "Configuration as follows:\n");
    cli_printf_info(context, " No.     Protocol     Port\n");      
    while (bridge_port) {
        if (bridge_port->create_mode == WORK_ROUTE && !bridge_port->deleted) {
            if (bridge_port->proto == PROTO_HTTP) {
                sprintf(strbuf, "http");
            } else {
                sprintf(strbuf, "https");
            }
            cli_printf_info(context, " %-3d     %-8s     %d\n", ++num, strbuf, bridge_port->ser_port);
        }
        bridge_port = bridge_port->next;
    }

    if (ap_work_mode == WORK_ROUTE) {
        cli_printf_info(context, "Commit status: Succ\n");
    } else {
        cli_printf_info(context, "Commit status: Fail\n");
    }
    
}

static void show_reverse_mode(cparser_context_t *context)
{
    listen_port_t *listen_port;
    char strbuf[STR_LEN_MAX];
    int num = 0;
    char ip[STR_LEN_MAX];
    
    if (ap_listen_ports) {
        listen_port = ap_listen_ports->next;
    } else {
        listen_port = NULL;
    } 

    cli_printf_info(context, "Work mode: reverse-proxy\n");

    if (ap_work_mode == WORK_REVERSE) {
        cli_printf_info(context, "Work status: %s\n", WORK_MODE_ACTIVE);
    } else {
        cli_printf_info(context, "Work status: %s\n", WORK_MODE_INACTIVE);
    }
    
    cli_printf_info(context, "Configuration as follows:\n");
    cli_printf_info(context, " No.     IP-Address          Protocol     Port\n");   
    while (listen_port) {
        if (listen_port->create_mode == WORK_REVERSE) {
            if (listen_port->proto == PROTO_HTTP) {
                sprintf(strbuf, "http");
            } else {
                sprintf(strbuf, "https");
            }           
            snprintf(ip, STR_LEN_MAX, "%d.%d.%d.%d", NIPQUAD(listen_port->ipaddr.s_addr));
            cli_printf_info(context, " %-3d     %-15s     %-8s     %d\n", 
                ++num, ip, strbuf, listen_port->port);
        }
        listen_port = listen_port->next;
    }

    if (ap_work_mode == WORK_REVERSE) {
        cli_printf_info(context, "Commit status: Succ\n");
    } else {
        cli_printf_info(context, "Commit status: Fail\n");
    }    
}

static void show_offline_mode(cparser_context_t *context)
{
    listen_port_t *listen_port;
    char strbuf[STR_LEN_MAX];
    int intf_num = 0, listen_num = 0;
    char ip[STR_LEN_MAX];
    int i;

    cli_printf_info(context, "Work mode: offline\n");

    if (ap_work_mode == WORK_OFFLINE) {
        cli_printf_info(context, "Work status: %s\n", WORK_MODE_ACTIVE);
    } else {
        cli_printf_info(context, "Work status: %s\n", WORK_MODE_INACTIVE);
    }
    
    cli_printf_info(context, "Configuration as follows:\n");
    cli_printf_info(context, " Listen interface as follows:\n");
    cli_printf_info(context, "  No.     Interface\n"); 
    for (i = 0; i < OFFLINE_INTF_NUM; i++) {
        if (BitGet(ap_off_iface, i + 1)) {
            cli_printf_info(context, "  %-3d     eth%d\n", ++intf_num, i);
        }
    }  
    
    cli_printf_info(context, " Listen IP as follows:\n");
    cli_printf_info(context, "  No.     IP-Address          Protocol     Port\n"); 
    if (ap_listen_ports) {
        listen_port = ap_listen_ports->next;
    } else {
        listen_port = NULL;
    } 
    while (listen_port) {
        if (listen_port->create_mode == WORK_OFFLINE) {
            if (listen_num == 0) {
 
            }
            if (listen_port->proto == PROTO_HTTP) {
                sprintf(strbuf, "http");
            } else {
                sprintf(strbuf, "https");
            }           
            snprintf(ip, STR_LEN_MAX, "%d.%d.%d.%d", NIPQUAD(listen_port->ipaddr.s_addr));
            cli_printf_info(context, "  %-3d     %-15s     %-8s     %d\n", 
                ++listen_num, ip, strbuf, listen_port->port);
        }
        listen_port = listen_port->next;
    }

    if (ap_work_mode == WORK_OFFLINE) {
        cli_printf_info(context, "Commit status: Succ\n");
    } else {
        cli_printf_info(context, "Commit status: Fail\n");
    }
    
}

/* 显示相关 */
cparser_result_t cparser_cmd_show_protect_engine_work_mode(cparser_context_t *context)
{
    char buf[COMMAND_LEN_MAX];
    
    if (context == NULL) {
        return CPARSER_OK;
    }

    if (context->parser->mode != CPARSER_MODE_CONFIG) { 
        return CPARSER_OK;
    } else {
        cli_printf_info(context, "----------------------------------------------\n");
        switch (ap_work_mode) {
        case WORK_BRIDGE:
            show_bridge_mode(context);
            break;
        case WORK_ROUTE:
            show_route_mode(context);           
            break;
        case WORK_REVERSE:
            show_reverse_mode(context);           
            break;
        case WORK_OFFLINE:
            show_offline_mode(context);
            break;
        default:
            break;
        }
        snprintf(buf, COMMAND_LEN_MAX, "show protect-engine work-mode");
        admin_log_process(context, buf);
        return CPARSER_OK;
    }
}

cparser_result_t cparser_cmd_show_protect_engine_work_mode_online_bridge_proxy(cparser_context_t *context)
{
    char buf[COMMAND_LEN_MAX];
    
    if (context == NULL) {
        return CPARSER_OK;
    }

    if (context->parser->mode != CPARSER_MODE_CONFIG) { 
        return CPARSER_OK;
    } else {
        cli_printf_info(context, "----------------------------------------------\n");
        show_bridge_mode(context);
        snprintf(buf, COMMAND_LEN_MAX, "show protect-engine work-mode online bridge-proxy");
        admin_log_process(context, buf);
        return CPARSER_OK;
    }
}

cparser_result_t cparser_cmd_show_protect_engine_work_mode_online_route_proxy(cparser_context_t *context)
{
    char buf[COMMAND_LEN_MAX];
    
    if (context == NULL) {
        return CPARSER_OK;
    }

    if (context->parser->mode != CPARSER_MODE_CONFIG) { 
        return CPARSER_OK;
    } else {
        cli_printf_info(context, "----------------------------------------------\n");
        show_route_mode(context);
        snprintf(buf, COMMAND_LEN_MAX, "show protect-engine work-mode online bridge-proxy");
        admin_log_process(context, buf);
        return CPARSER_OK;
    }
}

cparser_result_t cparser_cmd_show_protect_engine_work_mode_online_reverse_proxy(cparser_context_t *context)
{
    char buf[COMMAND_LEN_MAX];
    
    if (context == NULL) {
        return CPARSER_OK;
    }

    if (context->parser->mode != CPARSER_MODE_CONFIG) { 
        return CPARSER_OK;
    } else {
        cli_printf_info(context, "----------------------------------------------\n");
        show_reverse_mode(context);
        snprintf(buf, COMMAND_LEN_MAX, "show protect-engine work-mode online bridge-proxy");
        admin_log_process(context, buf);
        return CPARSER_OK;
    }
}

cparser_result_t cparser_cmd_show_protect_engine_work_mode_offline(cparser_context_t *context)
{
    char buf[COMMAND_LEN_MAX];
    
    if (context == NULL) {
        return CPARSER_OK;
    }

    if (context->parser->mode != CPARSER_MODE_CONFIG) { 
        return CPARSER_OK;
    } else {
        cli_printf_info(context, "----------------------------------------------\n");
        show_offline_mode(context);
        snprintf(buf, COMMAND_LEN_MAX, "show protect-engine work-mode online bridge-proxy");
        admin_log_process(context, buf);
        return CPARSER_OK;
    }
}

cparser_result_t cparser_cmd_show_protect_engine_encode(cparser_context_t *context)
{
    char buf[COMMAND_LEN_MAX];
    
    if (context == NULL) {
        return CPARSER_OK;
    }

    if (context->parser->mode != CPARSER_MODE_CONFIG) { 
        return CPARSER_OK;
    } else {
        cli_printf_info(context, "-----------------\n");
        switch (encode_type) {
        case UTF_8:
            cli_printf_info(context, "Encode: utf-8\n");
            break;
            
        case BIG5:
            cli_printf_info(context, "Encode: big5\n");
            break;
            
        case GB2312:
            cli_printf_info(context, "Encode: gb2312\n");
            break;
            
        case GBK:
            cli_printf_info(context, "Encode: gbk\n");
            break;
            
        case GB18030:
            cli_printf_info(context, "Encode: gb18030\n");
            break;
            
        default:
            cli_printf_info(context, "Not set encoding type\n");
            break;
        }

        snprintf(buf, COMMAND_LEN_MAX, "show protect-engine encode");
        admin_log_process(context, buf);
        return CPARSER_OK;
    }
}

