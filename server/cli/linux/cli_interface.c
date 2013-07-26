/*
 * $Id: cli_interface.c 2786 2013-07-09 16:42:55 FreeWAF Development Team $
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
#include <net/if.h>
#include <netinet/in.h>
#include <arpa/inet.h> 
#include <ctype.h>
#include "cparser.h"
#include "cparser_priv.h"
#include "cparser_token.h"
#include "global_root.h"
#include "cparser_show_tree.h"
#include "cparser_tree.h"
#include "cli_common.h"
#include "pe_cli.h"
#include "apr_ring.h"
#include "apr_pools.h"

#define ZERO_IP             "0.0.0.0"
#define FULL_IP             "255.255.255.255"
#define INTF_NAME_LEN_MAX   16

/* 接口状态 */
typedef enum intf_status {
    INTF_UP,
    INTF_DOWN
} intf_status_t;

typedef enum INTF_TYPE {
    ETH_INTF,
    BRI_INTF
} INTF_TYPE;

/* 桥成员或者以太网子接口 */
typedef struct subeth_s {
    apr_pool_t *eth_pool;
    char eth_name[INTF_NAME_LEN_MAX]; 
    apr_uint32_t ipaddr;  
    apr_uint32_t netmask;  
    
    APR_RING_ENTRY(subeth_s) eth_ring;
} subeth_t;

/* 这里的接口分为桥和以太网(eth)接口 */
typedef struct interface_s {
    apr_pool_t *intf_pool;
    INTF_TYPE intf_type;
    char intf_name[INTF_NAME_LEN_MAX];
    apr_uint32_t pri_ipaddr;                         /* 桥的IP地址或者eth的主IP地址 */
    apr_uint32_t netmask;                            /* 子网掩码 */
    int intf_status;                                 /* 接口状态，up或down */
    APR_RING_HEAD(subeth, subeth_s) subeth_head;     /* 桥的eth成员或者以太网的子接口链表 */

    APR_RING_ENTRY(interface_s) intf_ring;
} interface_t;

APR_RING_HEAD(interface_head, interface_s) g_interface_head;
static apr_pool_t *pnet;
static char g_curintf_name[INTF_NAME_LEN_MAX];
static char *abs_interface_shell_path = NULL;
static apr_pool_t *pcli = NULL;   
static char *intf_status_str[] = {"up", "down", NULL};

static interface_t *find_core(const char *intf_name)
{
    interface_t *ring_tmp, *ring_tmp_n;
    
    APR_RING_FOREACH_SAFE(ring_tmp, ring_tmp_n, &g_interface_head, interface_s, intf_ring) {
        if (!strncmp(intf_name, ring_tmp->intf_name, INTF_NAME_LEN_MAX)) { 
            return ring_tmp;
        }
    }  

    return NULL;
}

/* 桥配置相关 */

/* 计算一个桥中桥成员的个数 */
static int count_bridge_member(interface_t *cur_bridge)
{
    int member_num;
    subeth_t *ring_tmp_sub, *ring_tmp_n_sub;
    
    member_num = 0;
    APR_RING_FOREACH_SAFE(ring_tmp_sub, ring_tmp_n_sub, &cur_bridge->subeth_head, subeth_s, eth_ring) {
        member_num++;
    }  
    
    return member_num;
}

static subeth_t *find_bridge_member(const char *br_name, const char *eth_name)
{
    interface_t *ring_tmp, *ring_tmp_n;
    subeth_t *ring_tmp_sub, *ring_tmp_n_sub;

    APR_RING_FOREACH_SAFE(ring_tmp, ring_tmp_n, &g_interface_head, interface_s, intf_ring) {
        if (!strcmp(ring_tmp->intf_name, br_name)) {
            APR_RING_FOREACH_SAFE(ring_tmp_sub, ring_tmp_n_sub, &ring_tmp->subeth_head, subeth_s, eth_ring) {
                if (!strncmp(eth_name, ring_tmp_sub->eth_name, INTF_NAME_LEN_MAX)) { 
                    return ring_tmp_sub;
                }
            }  
        }
    }
    
    return NULL;
}

static subeth_t *add_bridge_member(interface_t *cur_bridge, const char *eth_name)
{
    subeth_t *eth; 
    apr_pool_t *peth;

    apr_pool_create(&peth, cur_bridge->intf_pool);
    apr_pool_tag(peth, "peth"); 
    
    eth = (subeth_t *)apr_pcalloc(peth, sizeof(subeth_t));
    eth->eth_pool = peth;
    strncpy(eth->eth_name, eth_name, INTF_NAME_LEN_MAX - 1);
    eth->ipaddr = inet_addr(ZERO_IP);
    eth->netmask = inet_addr(ZERO_IP);
    
    APR_RING_ELEM_INIT(eth, eth_ring);
    APR_RING_INSERT_TAIL(&cur_bridge->subeth_head, eth, subeth_s, eth_ring); 

    return eth;
}

static void del_bridge_member(subeth_t *cur_eth)
{
    APR_RING_REMOVE(cur_eth, eth_ring);
    apr_pool_destroy(cur_eth->eth_pool);
}

static interface_t *find_bridge(const char *bridge_name)
{
    interface_t *intf;

    intf = find_core(bridge_name);
    if (intf && intf->intf_type == BRI_INTF) {
        return intf;
    }

    return NULL;
}

static interface_t *add_bridge(const char *bridge_name)
{
    interface_t *bridge; 
    apr_pool_t *pintf;

    apr_pool_create(&pintf, pnet);
    apr_pool_tag(pintf, "pintf"); 
    bridge = (interface_t *)apr_pcalloc(pintf, sizeof(interface_t));
    bridge->intf_pool = pintf;
    bridge->intf_type = BRI_INTF;
    strncpy(bridge->intf_name, bridge_name, INTF_NAME_LEN_MAX - 1);
    bridge->pri_ipaddr = inet_addr(ZERO_IP);
    bridge->netmask = inet_addr(ZERO_IP);
    bridge->intf_status = INTF_UP;
    APR_RING_INIT(&bridge->subeth_head, subeth_s, eth_ring);

    APR_RING_ELEM_INIT(bridge, intf_ring);
    APR_RING_INSERT_TAIL(&g_interface_head, bridge, interface_s, intf_ring); 

    return bridge;
}

static void del_bridge(interface_t *cur_bridge)
{
    subeth_t *ring_tmp, *ring_tmp_n;
    
    APR_RING_FOREACH_SAFE(ring_tmp, ring_tmp_n, &cur_bridge->subeth_head, subeth_s, eth_ring) {
        APR_RING_REMOVE(ring_tmp, eth_ring);
        apr_pool_destroy(ring_tmp->eth_pool);
    }  

    APR_RING_REMOVE(cur_bridge, intf_ring);
    apr_pool_destroy(cur_bridge->intf_pool);
}

/* IP地址配置相关 */
static interface_t *find_interface(const char *intf_name)
{
    return find_core(intf_name);
}

/* 这里添加的是eth接口，桥接口不在这里添加 */
static interface_t *add_interface(const char *eth_name)
{
    interface_t *eth; 
    apr_pool_t *pintf;

    apr_pool_create(&pintf, pnet);
    apr_pool_tag(pintf, "pintf"); 
    
    eth = (interface_t *)apr_pcalloc(pintf, sizeof(interface_t));
    eth->intf_pool = pintf;
    eth->intf_type = ETH_INTF;
    strncpy(eth->intf_name, eth_name, INTF_NAME_LEN_MAX - 1);
    eth->pri_ipaddr = inet_addr(ZERO_IP);
    eth->netmask = inet_addr(ZERO_IP);
    eth->intf_status = INTF_UP;
    APR_RING_INIT(&eth->subeth_head, subeth_s, eth_ring);

    APR_RING_ELEM_INIT(eth, intf_ring);
    APR_RING_INSERT_TAIL(&g_interface_head, eth, interface_s, intf_ring); 

    return eth;
}

static int find_interface_ip(char *intf_name, apr_uint32_t ipaddr)
{
    interface_t *ring_tmp, *ring_tmp_n;
    subeth_t *ring_tmp_sub, *ring_tmp_n_sub;

    APR_RING_FOREACH_SAFE(ring_tmp, ring_tmp_n, &g_interface_head, interface_s, intf_ring) {
        if (!intf_name || strcmp(intf_name, ring_tmp->intf_name) != 0) {
            if (ring_tmp->pri_ipaddr == ipaddr) {
                return OK;
            }
        }
        APR_RING_FOREACH_SAFE(ring_tmp_sub, ring_tmp_n_sub, &ring_tmp->subeth_head, subeth_s, eth_ring) {
            if (!intf_name || strcmp(intf_name, ring_tmp_sub->eth_name) != 0) {
                if (ring_tmp_sub->ipaddr == ipaddr) { 
                    return OK;
                }
            }
        }  
    }

    return DECLINED;
}

static int has_interface_ip(interface_t *cur_intf, const char *intf_name) 
{
    subeth_t *ring_tmp_sub, *ring_tmp_n_sub;
    
    if (!strcmp(cur_intf->intf_name, intf_name)) {
        if (cur_intf->pri_ipaddr != inet_addr(ZERO_IP)) {
            return OK;
        }
    }
    
    APR_RING_FOREACH_SAFE(ring_tmp_sub, ring_tmp_n_sub, &cur_intf->subeth_head, subeth_s, eth_ring) {
        if (!strcmp(ring_tmp_sub->eth_name, intf_name) && ring_tmp_sub->ipaddr != inet_addr(ZERO_IP)) { 
            return OK;
        }
    }

    return DECLINED;
}

static subeth_t *find_sub_interface(interface_t *cur_intf, const char *intf_name)
{
    subeth_t *ring_tmp_sub, *ring_tmp_n_sub;

    APR_RING_FOREACH_SAFE(ring_tmp_sub, ring_tmp_n_sub, &cur_intf->subeth_head, subeth_s, eth_ring) {
        if (strcmp(intf_name, ring_tmp_sub->eth_name) == 0) {
            return ring_tmp_sub;
        }
    }  
    
    return NULL;
}

static int add_interface_ip(interface_t *cur_intf, const char *intf_name, apr_uint32_t ipaddr, 
            apr_uint32_t netmask, int intf_status)
{
    subeth_t *eth; 
    apr_pool_t *peth;    

    /* 桥只能配置一个IP地址 */
    if (cur_intf->intf_type == BRI_INTF 
        || ((cur_intf->intf_type == ETH_INTF) && !strcmp(cur_intf->intf_name, intf_name))) {
        cur_intf->pri_ipaddr = ipaddr;
        cur_intf->netmask = netmask;
        if (intf_status != -1) {
            cur_intf->intf_status = intf_status;
        }
        return OK;
    }    

    /* 如果已经有这个子接口，则直接替换ip和掩码 */
    eth = find_sub_interface(cur_intf, intf_name);
    if (eth != NULL) {
        eth->ipaddr = ipaddr;
        eth->netmask = netmask;
        return OK;
    }
    
    apr_pool_create(&peth, cur_intf->intf_pool);
    apr_pool_tag(peth, "peth"); 
    
    eth = (subeth_t *)apr_pcalloc(peth, sizeof(subeth_t));
    strncpy(eth->eth_name, intf_name, INTF_NAME_LEN_MAX);
    eth->eth_pool = peth;
    eth->ipaddr = ipaddr;
    eth->netmask = netmask;
        
    APR_RING_ELEM_INIT(eth, eth_ring);
    APR_RING_INSERT_TAIL(&cur_intf->subeth_head, eth, subeth_s, eth_ring); 

    return OK;
}

static void del_interface_ip(interface_t *cur_intf, char *intf_name)
{
    subeth_t *ring_tmp, *ring_tmp_n;
    
    if (strcmp(cur_intf->intf_name, intf_name) == 0) {
        cur_intf->pri_ipaddr = inet_addr(ZERO_IP);
        cur_intf->netmask = inet_addr(ZERO_IP);
        return;
    }

    if (cur_intf->intf_type == ETH_INTF) { 
        APR_RING_FOREACH_SAFE(ring_tmp, ring_tmp_n, &cur_intf->subeth_head, subeth_s, eth_ring) {
            if (strcmp(ring_tmp->eth_name, intf_name) == 0) { 
                APR_RING_REMOVE(ring_tmp, eth_ring);
                apr_pool_destroy(ring_tmp->eth_pool);
                break;
            }
        }  
    }
}

/* 脚本执行相关 */
static int shell_add_bridge(const char *br_name)
{
    char *argv[MAX_ARGV_NUM] = { NULL };
    apr_pool_t *ptemp;
    int rv;
    int i;

    /* 分配子池 */
    apr_pool_create(&ptemp, pcli);
    apr_pool_tag(ptemp, "ptemp");

    i = 0;
    argv[i++] = apr_psprintf(ptemp, "%s", abs_interface_shell_path);
    argv[i++] = apr_psprintf(ptemp, "addbr");
    argv[i++] = apr_psprintf(ptemp, "%s", br_name);

    rv = ap_exec_shell(abs_interface_shell_path, argv);
    
    apr_pool_destroy(ptemp);
    
    return rv;
}

static int shell_del_bridge(const char *br_name)
{
    char *argv[MAX_ARGV_NUM] = { NULL };
    apr_pool_t *ptemp;
    int rv;
    int i;

    /* 分配子池 */
    apr_pool_create(&ptemp, pcli);
    apr_pool_tag(ptemp, "ptemp");

    i = 0;
    argv[i++] = apr_psprintf(ptemp, "%s", abs_interface_shell_path);
    argv[i++] = apr_psprintf(ptemp, "delbr");
    argv[i++] = apr_psprintf(ptemp, "%s", br_name);

    rv = ap_exec_shell(abs_interface_shell_path, argv);
    
    apr_pool_destroy(ptemp);
    
    return rv;
}

static int shell_add_bridge_member(const char *br_name, const char *eth_name)
{
    char *argv[MAX_ARGV_NUM] = { NULL };
    apr_pool_t *ptemp;
    int rv;
    int i;

    /* 分配子池 */
    apr_pool_create(&ptemp, pcli);
    apr_pool_tag(ptemp, "ptemp");

    i = 0;
    argv[i++] = apr_psprintf(ptemp, "%s", abs_interface_shell_path);
    argv[i++] = apr_psprintf(ptemp, "addif");
    argv[i++] = apr_psprintf(ptemp, "%s", br_name);
    argv[i++] = apr_psprintf(ptemp, "%s", eth_name);

    rv = ap_exec_shell(abs_interface_shell_path, argv);
    
    apr_pool_destroy(ptemp);
    
    return rv;
}

static int shell_del_bridge_member(const char *br_name, const char *eth_name)
{
    char *argv[MAX_ARGV_NUM] = { NULL };
    apr_pool_t *ptemp;
    int rv;
    int i;

    /* 分配子池 */
    apr_pool_create(&ptemp, pcli);
    apr_pool_tag(ptemp, "ptemp");

    i = 0;
    argv[i++] = apr_psprintf(ptemp, "%s", abs_interface_shell_path);
    argv[i++] = apr_psprintf(ptemp, "delif");
    argv[i++] = apr_psprintf(ptemp, "%s", br_name);
    argv[i++] = apr_psprintf(ptemp, "%s", eth_name);

    rv = ap_exec_shell(abs_interface_shell_path, argv);
    
    apr_pool_destroy(ptemp);
    
    return rv;
}

static int shell_add_intf_ip(const char *intf_name, apr_uint32_t ipaddr, apr_uint32_t netmask)
{
    char *argv[MAX_ARGV_NUM] = { NULL };
    apr_pool_t *ptemp;
    int rv;
    int i;

    /* 分配子池 */
    apr_pool_create(&ptemp, pcli);
    apr_pool_tag(ptemp, "ptemp");

    i = 0;
    argv[i++] = apr_psprintf(ptemp, "%s", abs_interface_shell_path);
    argv[i++] = apr_psprintf(ptemp, "addip");
    argv[i++] = apr_psprintf(ptemp, "%s", intf_name);
    argv[i++] = apr_psprintf(ptemp, "%d.%d.%d.%d", NIPQUAD(ipaddr));
    argv[i++] = apr_psprintf(ptemp, "%d.%d.%d.%d", NIPQUAD(netmask));

    rv = ap_exec_shell(abs_interface_shell_path, argv);
    
    apr_pool_destroy(ptemp);
    
    return rv;
}

static int shell_del_intf_ip(const char *intf_name)
{
    char *argv[MAX_ARGV_NUM] = { NULL };
    apr_pool_t *ptemp;
    int rv;
    int i;

    /* 分配子池 */
    apr_pool_create(&ptemp, pcli);
    apr_pool_tag(ptemp, "ptemp");

    i = 0;
    argv[i++] = apr_psprintf(ptemp, "%s", abs_interface_shell_path);
    argv[i++] = apr_psprintf(ptemp, "delip");
    argv[i++] = apr_psprintf(ptemp, "%s", intf_name);

    rv = ap_exec_shell(abs_interface_shell_path, argv);
    
    apr_pool_destroy(ptemp);
    
    return rv;
}

static int shell_set_intf_status(const char *intf_name, char *status)
{
    char *argv[MAX_ARGV_NUM] = { NULL };
    apr_pool_t *ptemp;
    int rv;
    int i;

    /* 分配子池 */
    apr_pool_create(&ptemp, pcli);
    apr_pool_tag(ptemp, "ptemp");

    i = 0;
    argv[i++] = apr_psprintf(ptemp, "%s", abs_interface_shell_path);
    argv[i++] = apr_psprintf(ptemp, "setif");
    argv[i++] = apr_psprintf(ptemp, "%s", intf_name);
    argv[i++] = apr_psprintf(ptemp, "%s", status);

    rv = ap_exec_shell(abs_interface_shell_path, argv);
    
    apr_pool_destroy(ptemp);
    
    return rv;
}

/* 其他工具函数 */
/* 获取顶层接口名，例如子接口eth0:1中的eth0 */
static void get_top_eth_name(char *intf_name, char *top_intf_name)
{
    char *p, *q;
    int i;
    
    /* 获取子接口的上层接口名 */
    p = strchr(intf_name, ':');
    if (p) {
        for (q = intf_name, i = 0; q != p; q++) {
            top_intf_name[i++] = *q;
        }
        top_intf_name[i] = '\0';
    } else {
        strncpy(top_intf_name, intf_name, INTF_NAME_LEN_MAX);
    }
}

/* 解析接口名 */
static int parser_interface_name(char *config_info, char *name)
{
    int i;

    memset(name, 0, INTF_NAME_LEN_MAX);
    for (i = 0; i < INTF_NAME_LEN_MAX; i++) {
        if (isspace(config_info[i])) {
            name[i] ='\0';
            break;
        }
        name[i] = config_info[i];
    }

    if (i <= 0) {
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, NULL, "parser interface name fail!");
        return -1;
    }

    if (i >= INTF_NAME_LEN_MAX) {
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, NULL, "interface name too long, exceed %d!", 
            INTF_NAME_LEN_MAX);
        return -1;
    }
    
    return 0;
}

/* 解析接口ip地址 */
static int parser_interface_ip(char *config_info, apr_uint32_t *intf_ip)
{
    int i;
    char *ip_addr;
    char ip_str[32];

    ip_addr = strstr(config_info, "inet addr:");
    if (ip_addr == NULL) {
        /* 无ip地址 */
        *intf_ip = ntohl(inet_addr(ZERO_IP));
        return 0;
    }

    ip_addr += strlen("inet_addr:");
    for (i = 0; i < 32; i++) {
        if (isspace(ip_addr[i])) {
            ip_str[i] = '\0';
            break;
        }
        ip_str[i] = ip_addr[i];
    }

    if (i <= 0 || i >= 32) {
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, NULL, "parser interface ip fail!");
        return -1;
    }

    *intf_ip = inet_addr(ip_str);
    if (*intf_ip == INADDR_NONE) {
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, NULL, 
            "parser interface ip, inet_addr fail!");
        return -1;
    }
    /* 转换成主机字节序 */
    *intf_ip = ntohl(*intf_ip);
    return 0;
}

/* 解析接口掩码 */
static int parser_interface_mask(char *config_info, apr_uint32_t *intf_mask)
{
    int i;
    char *ip_mask;
    char mask_str[32];

    ip_mask = strstr(config_info, "Mask:");
    if (ip_mask == NULL) {
        /* 无mask */
        *intf_mask = ntohl(inet_addr(ZERO_IP));
        return 0;
    }

    ip_mask += strlen("Mask:");
    for (i = 0; i < 32; i++) {
        if (isspace(ip_mask[i])) {
            mask_str[i] = '\0';
            break;
        }
        mask_str[i] = ip_mask[i];        
    }
    
    if (i <= 0 || i >= 32) {
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, NULL, "parser interface mask fail!");
        return -1;
    }

    *intf_mask = inet_addr(mask_str);
    if (*intf_mask == INADDR_NONE) {
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, NULL, 
            "parser interface mask, inet_addr fail!");
        return -1;
    }
    
    /* 转换成主机字节序 */
    *intf_mask = ntohl(*intf_mask);
    
    return 0;
}

/* 解析接口状态 */
static int parser_interface_status(char *config_info, int *intf_status)
{
    char *status_up;

    status_up = strstr(config_info, " UP ");
    if (status_up == NULL) {
        /* 该接口为down状态 */
        *intf_status = INTF_DOWN;
    } else {
        /* 该接口为up状态 */
        *intf_status = INTF_UP;
    }
    
    return 0;   
}

/* 添加桥接口 */
static int add_interface_bridge(char *intf_name, apr_uint32_t intf_ip, apr_uint32_t intf_mask,
             int intf_status)
{
    interface_t *cur_bridge;
    int rv;

    cur_bridge = find_interface(intf_name);
    if (cur_bridge == NULL) {
        /* 如果没有则直接添加一个桥接口 */
        cur_bridge = add_bridge(intf_name);
        if (cur_bridge == NULL) {
            ap_log_error(APLOG_MARK, APLOG_WARNING, 0, NULL, 
                "add_interface_bridge add_bridge %s failed.", intf_name);
            return -1;
        }
    }

    rv = add_interface_ip(cur_bridge, intf_name, intf_ip, intf_mask, intf_status);
    if (rv != OK) {
        ap_log_error(APLOG_MARK, APLOG_WARNING, 0, NULL, 
            "add_interface_bridge add_interface_ip %s failed.", intf_name);
        return -1;  
    }      

    return 0;
}

/* 添加eth接口 */
static int add_interface_eth(char *intf_name, apr_uint32_t intf_ip, apr_uint32_t intf_mask, 
             int intf_status)
{
    char top_intf_name[INTF_NAME_LEN_MAX];
    interface_t *cur_intf;
    int rv;

    get_top_eth_name(intf_name, top_intf_name);
    cur_intf = find_interface(top_intf_name);
    if (cur_intf == NULL) {           
        /* 如果没有配置则默认为是eth接口配置 */
        cur_intf = add_interface(top_intf_name);
        if (cur_intf == NULL) {
            ap_log_error(APLOG_MARK, APLOG_WARNING, 0, NULL, 
                "add_interface_eth add_interface %s failed.", intf_name);
            return -1;
        }
    }

    /* 存在该interface，并且已经配置了ip则直接覆盖 */
    rv = add_interface_ip(cur_intf, intf_name, intf_ip, intf_mask, intf_status);
    if (rv != OK) {
        ap_log_error(APLOG_MARK, APLOG_WARNING, 0, NULL, 
            "add_interface_eth add_interface_ip failed.");
        return -1;  
    }   

    return 0;    
}

static int parser_bridge_name(char *line, char *br_name)
{
    int i;

    memset(br_name, 0, INTF_NAME_LEN_MAX);
    for (i = 0; i < INTF_NAME_LEN_MAX; i++) {
        if (isspace(line[i])) {
            br_name[i] ='\0';
            break;
        }
        br_name[i] = line[i];
    }
    
    if (i >= INTF_NAME_LEN_MAX) {
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, NULL, "parser bridge name fail!");
        return -1;
    }

    if (i == 0) {
        return 0;
    }
    
    return 1;
}

static int parser_bridge_member(char *line, char *br_member)
{
    char *mem;
    char *enter;
    
    memset(br_member, 0, INTF_NAME_LEN_MAX);
    mem = strstr(line, "eth");
    if (mem) {
        enter = strchr(mem, '\n');
        if (enter != NULL) {
            *enter = 0;
        }
        snprintf(br_member, INTF_NAME_LEN_MAX, "%s", mem);
        return 1;
    }

    return 0;
}

static int get_bridge_member_from_sys()
{
    char line[STR_LEN_MAX];
    char bridge_name[INTF_NAME_LEN_MAX];
    char eth_name[INTF_NAME_LEN_MAX];
    int has_bridge_name;
    int has_bridge_member;
    FILE* fp;
    interface_t *cur_bridge = NULL;
    interface_t *cur_intf = NULL;
    subeth_t *cur_eth;

    /* 获取系统中的接口配置信息 */
    fp = popen("brctl show", "r") ;
    if (fp == NULL) {
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, NULL, "get bridge popen fail!");
        return -1;
    }   

    if (fgets(line, sizeof(line), fp) == NULL) {
        ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, NULL, 
            "get_bridge_member_from_sys fgets fail!");
        pclose(fp);
        return -1;        
    }
    
    while (fgets(line, sizeof(line), fp)) {
        has_bridge_name = parser_bridge_name(line, bridge_name);
        if (has_bridge_name ==  -1) {
            ap_log_error(APLOG_MARK, APLOG_ERR, 0, ap_main_server, 
                "get_bridge_member_from_sys parser_bridge_name fail!");
            pclose(fp);
            return -1;            
        }
        
        if (has_bridge_name) {
            cur_bridge = find_bridge(bridge_name);
            if (cur_bridge == NULL) {
                continue;
            }
        }

        if (cur_bridge != NULL) {
            has_bridge_member = parser_bridge_member(line, eth_name);
            if (has_bridge_member) {    
                /* 清除桥成员接口的主IP */ 
                cur_intf = find_interface(eth_name);
                if (cur_intf != NULL) {
                    (void)shell_del_intf_ip(eth_name);
                    del_interface_ip(cur_intf, eth_name);
                } else {
                    ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, NULL, 
                        "the interface %s do not exist.\n", eth_name);
                    continue;             
                }
                cur_eth = add_bridge_member(cur_bridge, eth_name);
                if (cur_eth == NULL) {
                    ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, NULL, 
                        "get_bridge_member_from_sys add bridge interface %s failed.", eth_name);
                    pclose(fp);
                    return -1;
                }                    
            }           
        }
        
        memset(line, 0, STR_LEN_MAX);
    }

    pclose(fp);
    return 0;
}

/* 判断是否合法的桥名,限定为br，后面跟数字 */
static int is_valid_bridge_name(char *br_name)
{
    char *off;
    
    if (strlen(br_name) <= 2 ) {
        return 0;
    }

    if (strncmp(br_name, "br", 2) != 0) {
        return 0;   
    }
    
    off = br_name + 2;
    while (*off != '\0') {
        if (!isdigit(*off)) {
            return 0;
        }  
        off++;
    }

    return 1;
}

/* 从系统中获取interface配置信息 */
static int get_interface_from_sys()
{
    char buf[BUF_LEN_MAX] ;
    char line[STR_LEN_MAX];
    FILE* fp;
    char intf_name[INTF_NAME_LEN_MAX];
    apr_uint32_t intf_ip = 0;
    apr_uint32_t intf_mask = 0;
    int intf_status = 0;
    int next_interface = 0;
    int len;
    int rv;

    /* 获取系统中的接口配置信息 */
    fp = popen("ifconfig -a", "r") ;
    if (fp == NULL) {
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, NULL, "get interface popen fail!");
        return -1;
    }

    while (1) {
        memset(line, 0, STR_LEN_MAX);
        memset(buf, 0, BUF_LEN_MAX);
        len = 0;
        next_interface = 0;
        while (fgets(line, sizeof(line), fp)) {
            if (!strcmp(line, "\n")) {
                next_interface = 1;
                break;
            }
            len += snprintf(buf + len, BUF_LEN_MAX - len, "%s", line);
            memset(line, 0, STR_LEN_MAX);          
        }
        if (!next_interface) {
            break;
        }
        /* 获取接口名 */
        rv = parser_interface_name(buf, intf_name);
        if (rv == -1) {
            pclose(fp);
            return -1;
        }

        if (strcmp(intf_name, "lo") == 0) {
            continue;
        }
        
        /* 获取ip */
        rv = parser_interface_ip(buf, &intf_ip);
        if (rv == -1) {
            ap_log_error(APLOG_MARK, APLOG_ERR, 0, NULL, "parser interface ip fail!");
            pclose(fp);
            return -1;
        }
        /* 获取mask */
        rv = parser_interface_mask(buf, &intf_mask);
        if (rv == -1) {
            ap_log_error(APLOG_MARK, APLOG_ERR, 0, NULL, "parser interface mask fail!");
            pclose(fp);
            return -1;
        }   

        /* 获取接口状态 */
        rv = parser_interface_status(buf, &intf_status);
        if (rv == -1) {
            ap_log_error(APLOG_MARK, APLOG_ERR, 0, NULL, "parser interface status fail!");
            pclose(fp);
            return -1;
        }   
        
        if (strncmp(intf_name, "eth", 3) == 0) {
            /* 添加以太口 */
            rv = add_interface_eth(intf_name, intf_ip, intf_mask, intf_status);
            if (rv != 0) {
                ap_log_error(APLOG_MARK, APLOG_ERR, 0, NULL, "add_interface_eth fail!");
                pclose(fp);
                return -1;                
            }
        } else if (is_valid_bridge_name(intf_name)) {
            /* 添加桥 */
            rv = add_interface_bridge(intf_name, intf_ip, intf_mask, intf_status);
            if (rv != 0) {
                ap_log_error(APLOG_MARK, APLOG_ERR, 0, NULL, "add_interface_bridge fail!");
                pclose(fp);
                return -1;                
            }            
        } else {     
            /* 不合法的接口名，直接退出 */
            ap_log_error(APLOG_MARK, APLOG_ERR, 0, NULL, "Interface name %s is failure!"
                "The bridge name must begin with \"br\" and flow with digit.", intf_name);
            pclose(fp);
            return -1;
        }
    }
    
    pclose(fp) ;
    return 0;
}

AP_DECLARE(int) interface_init(apr_pool_t *p)
{   
    char *path;
    int rv;
    
    pcli = p;
    
    /* 分配接口的内存池 */   
    apr_pool_create(&pnet, p);    
    apr_pool_tag(pnet, "pnet");  

    APR_RING_INIT(&g_interface_head, interface_s, intf_ring);

    /* 脚本放置在apache根目录的bin目录下(~/bin/interface.sh) */
    path = ap_server_root_relative(pcli, "bin");
    abs_interface_shell_path = apr_pstrcat(pcli, path, "/interface.sh", NULL);

    /* 从系统中获取interface配置信息 */
    rv = get_interface_from_sys();
    if (rv != 0) {
        return DECLINED;
    }
    /* 从系统中获取桥成员 */
    rv = get_bridge_member_from_sys();
    if (rv != 0) {
        return DECLINED;
    }    
    
    return OK;
}

AP_DECLARE(int) interface_find(char *intf_name)
{   
    interface_t *intf;

    intf = find_core(intf_name);
    if (intf == NULL) {
        return DECLINED;
    }

    return OK;
}

AP_DECLARE(int) bridge_check(char *bridge_name)
{
    interface_t *bridge;
    int member_num;
        
    if (bridge_name == NULL) {
        return DECLINED;
    }
    
    bridge = find_bridge(bridge_name);
    if (bridge == NULL) {
       return DECLINED;
    }

    member_num = count_bridge_member(bridge);
    if (member_num < 2) {
        return DECLINED;
    }

    return OK;
}
    
AP_DECLARE(int) clear_bridge()
{   
    interface_t *ring_tmp, *ring_tmp_n;
    
    APR_RING_FOREACH_SAFE(ring_tmp, ring_tmp_n, &g_interface_head, interface_s, intf_ring) {
        if (ring_tmp->intf_type == BRI_INTF) { 
            shell_del_bridge(ring_tmp->intf_name);
            del_bridge(ring_tmp);
        }
    }  

    return OK;
}

static void print_bridge_result(cparser_context_t *context, interface_t *ring_tmp, apr_pool_t *ptemp)
{
    subeth_t *ring_tmp_sub, *ring_tmp_n_sub;
    char *br_info;
    char *temp_info;

    /* 显示桥名 */
    br_info = apr_psprintf(ptemp, "%-20s", ring_tmp->intf_name);
    /* 显示桥IP */
    temp_info = apr_psprintf(ptemp, "%d.%d.%d.%d", NIPQUAD(ring_tmp->pri_ipaddr));
    temp_info = apr_psprintf(ptemp, "%-20s", temp_info);
    br_info = apr_pstrcat(ptemp, br_info, temp_info, NULL);
    /* 显示桥掩码 */
    temp_info = apr_psprintf(ptemp, "%d.%d.%d.%d", NIPQUAD(ring_tmp->netmask));
    temp_info = apr_psprintf(ptemp, "%-20s", temp_info);
    br_info = apr_pstrcat(ptemp, br_info, temp_info, NULL);
    /* 显示状态 */
    temp_info = apr_psprintf(ptemp, "%-11s", intf_status_str[ring_tmp->intf_status]);
    br_info = apr_pstrcat(ptemp, br_info, temp_info, NULL);  
    APR_RING_FOREACH_SAFE(ring_tmp_sub, ring_tmp_n_sub, &ring_tmp->subeth_head, subeth_s, eth_ring) {
        /* 显示桥成员 */
        br_info = apr_pstrcat(ptemp, br_info, ring_tmp_sub->eth_name, NULL);
        br_info = apr_pstrcat(ptemp, br_info, " ", NULL);
    }    
    
    cli_printf_info(context, "%s\n", br_info);    
}

static void show_bridge_info(cparser_context_t *context, char *br_name)
{
    interface_t *ring_tmp, *ring_tmp_n;
    apr_pool_t *ptemp;

    apr_pool_create(&ptemp, pcli);
    apr_pool_tag(ptemp, "ptemp");

    cli_printf_info(context, "-----------------------------------------------------------------------------\n");
    cli_printf_info(context, "Bridge              IP-Address          Mask                Status     Member\n");

    if (br_name) {
        APR_RING_FOREACH_SAFE(ring_tmp, ring_tmp_n, &g_interface_head, interface_s, intf_ring) {
            if (!strncmp(br_name, ring_tmp->intf_name, INTF_NAME_LEN_MAX)
                    && ring_tmp->intf_type == BRI_INTF) { 
                print_bridge_result(context, ring_tmp, ptemp);
                break;
            }
        }     
    } else {
        APR_RING_FOREACH_SAFE(ring_tmp, ring_tmp_n, &g_interface_head, interface_s, intf_ring) {
            if (ring_tmp->intf_type == BRI_INTF) { 
                print_bridge_result(context, ring_tmp, ptemp);
            }
        }  
    }
    
    apr_pool_destroy(ptemp);
}

static void print_interface_result(cparser_context_t *context, interface_t *ring_tmp, apr_pool_t *ptemp)
{
    char *intf_info;
    char *temp_info;
    subeth_t *ring_tmp_sub, *ring_tmp_n_sub;
    
    /* 显示接口名*/
    intf_info = apr_psprintf(ptemp, "%-20s", ring_tmp->intf_name);
    /* 显示IP地址 */
    temp_info = apr_psprintf(ptemp, "%d.%d.%d.%d", NIPQUAD(ring_tmp->pri_ipaddr));
    temp_info = apr_psprintf(ptemp, "%-20s", temp_info);
    intf_info = apr_pstrcat(ptemp, intf_info, temp_info, NULL);
    /* 显示掩码 */
    temp_info = apr_psprintf(ptemp, "%d.%d.%d.%d", NIPQUAD(ring_tmp->netmask));
    temp_info = apr_psprintf(ptemp, "%-20s", temp_info);
    intf_info = apr_pstrcat(ptemp, intf_info, temp_info, NULL);
    /* 显示状态 */
    temp_info = apr_psprintf(ptemp, "%-s", intf_status_str[ring_tmp->intf_status]);
    intf_info = apr_pstrcat(ptemp, intf_info, temp_info, NULL);                
    cli_printf_info(context, "%s\n", intf_info);    
    /* 显示子成员 */
    if (ring_tmp->intf_type == ETH_INTF) {
        APR_RING_FOREACH_SAFE(ring_tmp_sub, ring_tmp_n_sub, &ring_tmp->subeth_head, subeth_s, eth_ring) {
            /* 显示接口名 */
            intf_info = apr_psprintf(ptemp, "%-20s", ring_tmp_sub->eth_name);
            /* 显示IP地址 */
            temp_info = apr_psprintf(ptemp, "%d.%d.%d.%d", NIPQUAD(ring_tmp_sub->ipaddr));
            temp_info = apr_psprintf(ptemp, "%-20s", temp_info);
            intf_info = apr_pstrcat(ptemp, intf_info, temp_info, NULL);
            /* 显示掩码 */
            temp_info = apr_psprintf(ptemp, "%d.%d.%d.%d", NIPQUAD(ring_tmp_sub->netmask));
            temp_info = apr_psprintf(ptemp, "%-20s", temp_info);
            intf_info = apr_pstrcat(ptemp, intf_info, temp_info, NULL);
            /* 显示状态 */
            temp_info = apr_psprintf(ptemp, "%-s", intf_status_str[ring_tmp->intf_status]);
            intf_info = apr_pstrcat(ptemp, intf_info, temp_info, NULL);                            
            cli_printf_info(context, "%s\n", intf_info);  
        }
    }
}
    
static void show_interface_info(cparser_context_t *context, char *intf_name)
{
    interface_t *ring_tmp, *ring_tmp_n;
    apr_pool_t *ptemp;

    apr_pool_create(&ptemp, pcli);
    apr_pool_tag(ptemp, "ptemp");

    cli_printf_info(context, "------------------------------------------------------------------\n");
    cli_printf_info(context, "Interface           IP-Address          Mask                Status\n");

    if (intf_name) {
        APR_RING_FOREACH_SAFE(ring_tmp, ring_tmp_n, &g_interface_head, interface_s, intf_ring) {
            if (!strncmp(intf_name, ring_tmp->intf_name, INTF_NAME_LEN_MAX)) { 
                print_interface_result(context, ring_tmp, ptemp);
                break;
            }
        }     
    } else {
        APR_RING_FOREACH_SAFE(ring_tmp, ring_tmp_n, &g_interface_head, interface_s, intf_ring) {
            print_interface_result(context, ring_tmp, ptemp);
        }
    }
    
    apr_pool_destroy(ptemp);
}

/* CLI执行函数 */
cparser_result_t cparser_cmd_pe_bridge_br_name(cparser_context_t *context, char **br_name_ptr)
{ 
    interface_t *cur_bridge;
    char prompt[CPARSER_MAX_PROMPT] = {0};
    char buf[COMMAND_LEN_MAX];
    interface_t *ring_tmp, *ring_tmp_n;
    apr_status_t rv;
    
    if (context == NULL) {
        return CPARSER_NOT_OK;
    }

    if (context->parser->mode != CPARSER_MODE_CONFIG) {       
        APR_RING_FOREACH_SAFE(ring_tmp, ring_tmp_n, &g_interface_head, interface_s, intf_ring) {
            if (ring_tmp->intf_type == BRI_INTF) {
                if (context->parser->mode == CPARSER_MODE_WRITE) {
                    assert(context->parser->fp);
                    cli_fprintf(context, "bridge %s\n", ring_tmp->intf_name);
                } else {
                    cli_printf(context, "!\n");
                    cli_printf(context, "bridge %s\n", ring_tmp->intf_name);
                }

                context->parser->root_level++;
                context->parser->root[context->parser->root_level] = context->parser->cur_node->children;
                cparser_walk(context->parser, cparser_running_conf_walker, NULL, ring_tmp->intf_name);
                context->parser->root_level--; 
            }
        }  
        
        return CPARSER_OK;
    } else {
        if (!br_name_ptr || !*br_name_ptr) {
            return CPARSER_NOT_OK;
        }
#if 0
        if (!strncmp(*br_name_ptr, "eth", 3)) {
            cli_printf_info(context, "the bridge name do not allow starting with \"eth\"\n");
            return CPARSER_NOT_OK;
        }
#endif
        if (strlen(*br_name_ptr) >= INTF_NAME_LEN_MAX) {
            cli_printf_info(context, "The bridge name is too long,exceed %d.\n", INTF_NAME_LEN_MAX);
            return CPARSER_NOT_OK;
        }
    
        if (!is_valid_bridge_name(*br_name_ptr)) {
            cli_printf_info(context, "The bridge name must begin with \"br\" and follow with digit.\n");
            return CPARSER_NOT_OK;
        }
        
        cur_bridge = find_bridge(*br_name_ptr);
        if (cur_bridge == NULL) {
            rv = shell_add_bridge(*br_name_ptr);
            if (rv != OK) {
                cli_printf_info(context, "Add bridge %s failed.\n", *br_name_ptr);
                ap_log_error(APLOG_MARK, APLOG_WARNING, 0, ap_main_server, "exec add bridge shell failed.");
                return CPARSER_NOT_OK;
            }
            
            cur_bridge = add_bridge(*br_name_ptr);
            if (cur_bridge == NULL) {
                shell_del_bridge(*br_name_ptr);
                ap_log_error(APLOG_MARK, APLOG_WARNING, 0, ap_main_server, "add bridge %s failed.", *br_name_ptr);
                cli_printf_info(context, "Add bridge %s failed.\n", *br_name_ptr);
                return CPARSER_NOT_OK;
            }
        }

        snprintf(buf, COMMAND_LEN_MAX, "bridge %s", *br_name_ptr);
        admin_log_process(context, buf);
        ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, ap_main_server, "add bridge %s success.", *br_name_ptr);
        strncpy(g_curintf_name, *br_name_ptr, INTF_NAME_LEN_MAX);
        snprintf(prompt, CPARSER_MAX_PROMPT, "%s(bridge)#", g_cli_prompt);       
        return cparser_submode_enter(context->parser, g_curintf_name, prompt);
    }
    
    return CPARSER_OK;
}

cparser_result_t cparser_cmd_pe_no_bridge_br_name(cparser_context_t *context, char **br_name_ptr)
{
    interface_t *cur_bridge;
    apr_status_t rv;
    char buf[COMMAND_LEN_MAX];
        
    if (context == NULL) {
        return CPARSER_NOT_OK;
    }

    if (context->parser->mode != CPARSER_MODE_CONFIG) {
        return CPARSER_OK;
    } else {
        if (!br_name_ptr || !*br_name_ptr) {
            return CPARSER_NOT_OK;
        }

        cur_bridge = find_bridge(*br_name_ptr);
        if (cur_bridge == NULL) {
            cli_printf_info(context, "The bridge %s dose not exist.\n", *br_name_ptr);
            return CPARSER_NOT_OK; 
        }

        rv = shell_del_bridge(*br_name_ptr);
        if (rv != OK) {
            cli_printf_info(context, "Delete bridge %s failed.", *br_name_ptr);
            ap_log_error(APLOG_MARK, APLOG_WARNING, 0, ap_main_server, "exec delete bridge shell failed.");
            return CPARSER_NOT_OK;
        }
                
        del_bridge(cur_bridge);
        ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, ap_main_server, "delete bridge %s success.", *br_name_ptr);

        snprintf(buf, COMMAND_LEN_MAX, "no bridge %s", *br_name_ptr);
        admin_log_process(context, buf);
        return CPARSER_OK; 
    }
}

cparser_result_t cparser_cmd_br_interface_interface_name(cparser_context_t *context, char **interface_name_ptr)
{
    interface_t *cur_bridge;
    char *cur_bridge_name;
    subeth_t *cur_eth;
    subeth_t *ring_tmp, *ring_tmp_n;
    apr_status_t rv;
    interface_t *cur_intf;
    char buf[COMMAND_LEN_MAX];
    
    if (context == NULL) {
        return CPARSER_NOT_OK;
    }

    cur_bridge_name = (char *)context->cookie[context->parser->root_level];
    cur_bridge = find_bridge(cur_bridge_name);
    if (cur_bridge == NULL) {
        return CPARSER_OK;
    }

    if (context->parser->mode != CPARSER_MODE_CONFIG) {
        APR_RING_FOREACH_SAFE(ring_tmp, ring_tmp_n, &cur_bridge->subeth_head, subeth_s, eth_ring) {
            if (context->parser->mode == CPARSER_MODE_WRITE) {
                assert(context->parser->fp);
                cli_fprintf(context, "interface %s\n", ring_tmp->eth_name);
            } else {
                cli_printf(context, "interface %s\n", ring_tmp->eth_name);
            }
        }  
        
        return CPARSER_OK;
    } else {
        if (!interface_name_ptr || !*interface_name_ptr) {
            return CPARSER_NOT_OK;
        }

        if (strncmp(*interface_name_ptr, "eth", 3)) {
            cli_printf_info(context, "the bridge member must be eth interface.\n");
            return CPARSER_NOT_OK;
        }
        
        rv = ap_query_interface_exist(*interface_name_ptr);
        if (rv != OK) {
            cli_printf_info(context, "the interface %s do not exist.\n", *interface_name_ptr);
            return CPARSER_NOT_OK;  
        }
  
        /* 清除接口的主IP */ 
        cur_intf = find_interface(*interface_name_ptr);
        if (cur_intf != NULL) {
            (void)shell_del_intf_ip(*interface_name_ptr);
            del_interface_ip(cur_intf, *interface_name_ptr);
        } else {
            cli_printf_info(context, "the interface %s do not exist.\n", *interface_name_ptr);
            return CPARSER_NOT_OK;             
        }

        cur_eth = find_bridge_member(cur_bridge_name, *interface_name_ptr);
        if (cur_eth != NULL) {
            cli_printf_info(context, "the interface %s is already a member of bridge.\n", *interface_name_ptr);
            return CPARSER_NOT_OK; 
        }

        rv = shell_add_bridge_member(cur_bridge_name, *interface_name_ptr);
        if (rv != OK) {
            cli_printf_info(context, "exec add bridge member shell failed.\n");
            ap_log_error(APLOG_MARK, APLOG_WARNING, 0, ap_main_server, "exec add bridge member shell failed.");
            return CPARSER_NOT_OK;
        }
        
        cur_eth = add_bridge_member(cur_bridge, *interface_name_ptr);
        if (cur_eth == NULL) {
            shell_del_bridge_member(cur_bridge_name, *interface_name_ptr);
            ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, ap_main_server, 
                "add bridge interface %s failed.", *interface_name_ptr);
            cli_printf_info(context, "add bridge interface %s failed.\n", *interface_name_ptr);
            return CPARSER_NOT_OK;
        }

        snprintf(buf, COMMAND_LEN_MAX, "interface %s", *interface_name_ptr);
        admin_log_process(context, buf);
        ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, ap_main_server, 
            "add bridge member %s success.", *interface_name_ptr);
        
        return CPARSER_OK; 
    }
}

cparser_result_t cparser_cmd_br_no_interface_interface_name(cparser_context_t *context, char **interface_name_ptr)
{
    interface_t *cur_bridge;
    subeth_t *cur_eth;
    char *cur_bridge_name;
    apr_status_t rv;
    char buf[COMMAND_LEN_MAX];
    
    if (context == NULL) {
        return CPARSER_NOT_OK;
    }   
    
    if (context->parser->mode != CPARSER_MODE_CONFIG) {
        return CPARSER_OK;
    } else {
        if (!interface_name_ptr || !*interface_name_ptr) {
            return CPARSER_NOT_OK;
        }

        rv = ap_query_interface_exist(*interface_name_ptr);
        if (rv != OK) {
            cli_printf_info(context, "the interface %s do not exist.\n", *interface_name_ptr);
            return CPARSER_NOT_OK;  
        }

        cur_bridge_name = (char *)context->cookie[context->parser->root_level];
        cur_bridge = find_bridge(cur_bridge_name);
        if (cur_bridge == NULL) {
            return CPARSER_NOT_OK;
        }
    
        cur_eth = find_bridge_member(cur_bridge_name, *interface_name_ptr); 
        if (cur_eth == NULL) {
            cli_printf_info(context, "the current bridge do not has this %s interface.\n", *interface_name_ptr);
            return CPARSER_NOT_OK; 
        }

        rv = shell_del_bridge_member(cur_bridge_name, *interface_name_ptr);
        if (rv != OK) {
            ap_log_error(APLOG_MARK, APLOG_WARNING, 0, ap_main_server, "exec del bridge eth shell failed.");
            return CPARSER_NOT_OK;
        }
        
        del_bridge_member(cur_eth);

        snprintf(buf, COMMAND_LEN_MAX, "no interface %s", *interface_name_ptr);
        admin_log_process(context, buf);
        return CPARSER_OK; 
    }
}

cparser_result_t cparser_cmd_pe_interface_interface_name_ip_address_ip_address_mask_mask(cparser_context_t *context,
    char **interface_name_ptr, uint32_t *ip_address_ptr, uint32_t *mask_ptr)
{
    interface_t *cur_intf;
    apr_status_t rv;
    interface_t *ring_tmp, *ring_tmp_n;
    subeth_t *ring_tmp_sub, *ring_tmp_n_sub;
    char eth_name[INTF_NAME_LEN_MAX] = {0};
    char buf[COMMAND_LEN_MAX];
    int mark_print = 0;
    
    if (context == NULL) {
        return CPARSER_NOT_OK;
    }   
    
    if (context->parser->mode != CPARSER_MODE_CONFIG) {
        APR_RING_FOREACH_SAFE(ring_tmp, ring_tmp_n, &g_interface_head, interface_s, intf_ring) {
            if (ring_tmp->pri_ipaddr != inet_addr(ZERO_IP)) {
                if (context->parser->mode == CPARSER_MODE_WRITE) {
                    assert(context->parser->fp);
                    cli_fprintf(context, "interface %s ip-address %d.%d.%d.%d mask %d.%d.%d.%d\n", 
                        ring_tmp->intf_name, NIPQUAD(ring_tmp->pri_ipaddr), NIPQUAD(ring_tmp->netmask));
                } else {
                    if (mark_print == 0) {
                        cli_printf(context, "!\n");
                        mark_print = 1;
                    }
                    cli_printf(context, "interface %s ip-address %d.%d.%d.%d mask %d.%d.%d.%d\n", 
                        ring_tmp->intf_name, NIPQUAD(ring_tmp->pri_ipaddr), NIPQUAD(ring_tmp->netmask));
                }
            }
            
            /* 子接口 */
            APR_RING_FOREACH_SAFE(ring_tmp_sub, ring_tmp_n_sub, &ring_tmp->subeth_head, subeth_s, eth_ring) {
                if (ring_tmp_sub->ipaddr != inet_addr(ZERO_IP)) {
                    if (context->parser->mode == CPARSER_MODE_WRITE) {
                        assert(context->parser->fp);
                        cli_fprintf(context, "interface %s ip-address %d.%d.%d.%d mask %d.%d.%d.%d\n", 
                            ring_tmp_sub->eth_name, NIPQUAD(ring_tmp_sub->ipaddr), NIPQUAD(ring_tmp_sub->netmask));
                    } else {
                        if (mark_print == 0) {
                            cli_printf(context, "!\n");
                            mark_print = 1;
                        }
                        cli_printf(context, "interface %s ip-address %d.%d.%d.%d mask %d.%d.%d.%d\n", 
                            ring_tmp_sub->eth_name, NIPQUAD(ring_tmp_sub->ipaddr), NIPQUAD(ring_tmp_sub->netmask));
                    }
                }
            }               
        }  

        return CPARSER_OK;
    } else {
        if (!interface_name_ptr || !*interface_name_ptr || !ip_address_ptr || !mask_ptr) {
            return CPARSER_NOT_OK;
        }
        
        if (strlen(*interface_name_ptr) >= INTF_NAME_LEN_MAX) {
            cli_printf_info(context, "The interface name is too long, exceed %d.\n", INTF_NAME_LEN_MAX);
            return CPARSER_NOT_OK;  
        }

        /* 掩码正确性检测 */  
        rv = ap_check_mask_validation(*(apr_int32_t *)mask_ptr);
        if (rv != OK) {
            cli_printf_info(context, "the mask is invalid.\n");
            return CPARSER_NOT_OK;  
        }

        if (*ip_address_ptr == inet_addr(ZERO_IP) || *ip_address_ptr == inet_addr(FULL_IP)) {
            cli_printf_info(context, "the ip address is error.\n");
            return CPARSER_NOT_OK;            
        }

        /* 接口检查 */
        get_top_eth_name(*interface_name_ptr, eth_name);
        rv = ap_query_interface_exist(eth_name);
        if (rv != OK) {
            cli_printf_info(context, "the interface %s do not exist.\n", eth_name);
            return CPARSER_NOT_OK;  
        }
        
        /* 确定配置IP的唯一性 */
        rv = find_interface_ip(*interface_name_ptr, *ip_address_ptr);
        if (rv == OK) {
            cli_printf_info(context, "the ip address has been configured.\n");
            return CPARSER_NOT_OK;   
        }
        
        /* 查找接口 */
        cur_intf = find_interface(eth_name);
        if (cur_intf == NULL) {           
            /* 如果没有配置则默认为是eth接口配置 */
            cur_intf = add_interface(eth_name);
            if (cur_intf == NULL) {
                ap_log_error(APLOG_MARK, APLOG_WARNING, 0, ap_main_server, 
                    "add interface %s failed.", *interface_name_ptr);
                cli_printf_info(context, "add interface %s failed.", *interface_name_ptr);
                return CPARSER_NOT_OK;
            }
        } 

        rv = shell_add_intf_ip(*interface_name_ptr, *(apr_uint32_t *)ip_address_ptr, *(apr_uint32_t *)mask_ptr);
        if (rv != OK) {
            cli_printf_info(context, "exec add interface ip shell failed.\n");
            ap_log_error(APLOG_MARK, APLOG_WARNING, 0, ap_main_server, "exec add interface ip shell failed.");
            return CPARSER_NOT_OK;
        }

        /* 添加接口IP ,给主接口配置ip，其状态会自动up起来 */
        rv = add_interface_ip(cur_intf, *interface_name_ptr, *(apr_uint32_t *)ip_address_ptr, 
                *(apr_uint32_t *)mask_ptr, INTF_UP);
        if (rv != OK) {
            shell_del_intf_ip(*interface_name_ptr);
            cli_printf_info(context, "ip address configure failed.\n");
            return CPARSER_NOT_OK;  
        }

        snprintf(buf, COMMAND_LEN_MAX, "interface %s ip-address %d.%d.%d.%d mask %d.%d.%d.%d", 
            *interface_name_ptr, NIPQUAD(*ip_address_ptr), NIPQUAD(*mask_ptr));
        admin_log_process(context, buf);
        ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, ap_main_server, 
            "add interface %s ip %d.%d.%d.%d success.", *interface_name_ptr, NIPQUAD(*ip_address_ptr));
        
        return CPARSER_OK;
    }

}

cparser_result_t cparser_cmd_pe_no_interface_interface_name(cparser_context_t *context,
                   char **interface_name_ptr)
{
    interface_t *cur_intf;
    apr_status_t rv;
    char eth_name[INTF_NAME_LEN_MAX] = {0};
    char buf[COMMAND_LEN_MAX];
    int is_sub_interface = 0;
    
    if (context == NULL) {
        return CPARSER_NOT_OK;
    }   
    
    if (context->parser->mode != CPARSER_MODE_CONFIG) {
        return CPARSER_OK;
    } else {
        if (!interface_name_ptr || !*interface_name_ptr) {
            return CPARSER_NOT_OK;
        }
        
        if (strlen(*interface_name_ptr) >= INTF_NAME_LEN_MAX) {
            cli_printf_info(context, "The interface name is too long, exceed %d.\n", INTF_NAME_LEN_MAX);
            return CPARSER_NOT_OK;  
        }

        if (strchr(*interface_name_ptr, ':')) {
            is_sub_interface = 1;
        }
        
        get_top_eth_name(*interface_name_ptr, eth_name);
        
        /* 接口检查 */     
        rv = ap_query_interface_exist(eth_name);
        if (rv != OK) {
            cli_printf_info(context, "the interface %s do not exist.\n", eth_name);
            return CPARSER_NOT_OK;  
        }      

        cur_intf = find_interface(eth_name);
        if (cur_intf == NULL) {
            cli_printf_info(context, "the interface %s do not exist\n", *interface_name_ptr);
            return CPARSER_NOT_OK;
        }

        if (is_sub_interface) {
            if (find_sub_interface(cur_intf, *interface_name_ptr) == NULL) {
                cli_printf_info(context, "the interface %s do not exist\n", *interface_name_ptr);
                return CPARSER_NOT_OK;
            }
        }

        rv = shell_del_intf_ip(*interface_name_ptr);
        if (rv != OK) {
            cli_printf_info(context, "exec del interface ip shell failed.\n");
            ap_log_error(APLOG_MARK, APLOG_WARNING, 0, ap_main_server, "exec del interface ip shell failed.");
            return CPARSER_NOT_OK;
        }

        del_interface_ip(cur_intf, *interface_name_ptr);
        
        /* 清掉主接口的ip，相当于给接口配置0.0.0.0地址，状态会被up起来 */
        if (!is_sub_interface) {
            cur_intf->intf_status = INTF_UP;
        }
        
        snprintf(buf, COMMAND_LEN_MAX, "no interface %s", *interface_name_ptr);
        admin_log_process(context, buf);
        ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, ap_main_server,  "delete interface %s success.", 
            *interface_name_ptr);

        return CPARSER_OK; 
    }
}

static int set_interface_status(cparser_context_t *context, char **interface_name_ptr, 
             intf_status_t status) 
{
    interface_t *cur_intf;
    apr_status_t rv;
    char eth_name[INTF_NAME_LEN_MAX] = {0};
    char buf[COMMAND_LEN_MAX];
    
    if (!interface_name_ptr || !*interface_name_ptr) {
        return CPARSER_NOT_OK;
    }

    /* 目前不能设置子接口 */
    if (strchr(*interface_name_ptr, ':')) {
        cli_printf_info(context, "the status of sub interface can not be modified.\n");
        return CPARSER_NOT_OK; 
    }
    
    if (strlen(*interface_name_ptr) >= INTF_NAME_LEN_MAX) {
        cli_printf_info(context, "The interface name is too long, exceed %d.\n", INTF_NAME_LEN_MAX);
        return CPARSER_NOT_OK;  
    }
    
    get_top_eth_name(*interface_name_ptr, eth_name); 

    /* 接口检查 */
    rv = ap_query_interface_exist(eth_name);
    if (rv != OK) {
        cli_printf_info(context, "the interface %s do not exist.\n", eth_name);
        return CPARSER_NOT_OK;  
    }
    
    cur_intf = find_interface(eth_name);
    if (cur_intf == NULL) {           
        cli_printf_info(context, "the interface %s do not exist.\n", *interface_name_ptr);
        return CPARSER_NOT_OK;
    } 
    
    rv = shell_set_intf_status(*interface_name_ptr, intf_status_str[status]);
    if (rv != OK) {
        cli_printf_info(context, "exec set interface %s shell failed.\n", intf_status_str[status]);
        ap_log_error(APLOG_MARK, APLOG_WARNING, 0, 
            ap_main_server, "exec set interface %s shell failed.", intf_status_str[status]);
        return CPARSER_NOT_OK;
    }

    cur_intf->intf_status = status;
    
    snprintf(buf, COMMAND_LEN_MAX, "interface %s %s", *interface_name_ptr, intf_status_str[status]);
    admin_log_process(context, buf);
    ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, ap_main_server, 
        "interface %s %s", *interface_name_ptr, intf_status_str[status]);
    
    return CPARSER_OK;
}

cparser_result_t cparser_cmd_pe_interface_interface_name_up(cparser_context_t *context,
    char **interface_name_ptr)
{  
    if (context == NULL) {
        return CPARSER_NOT_OK;
    }   
    
    if (context->parser->mode != CPARSER_MODE_CONFIG) {
        return CPARSER_OK;
    } else {
        return set_interface_status(context, interface_name_ptr, INTF_UP);
    }
}

cparser_result_t cparser_cmd_pe_interface_interface_name_down(cparser_context_t *context,
    char **interface_name_ptr)
{
    if (context == NULL) {
        return CPARSER_NOT_OK;
    }   
    
    if (context->parser->mode != CPARSER_MODE_CONFIG) {
        return CPARSER_OK;
    } else {
        return set_interface_status(context, interface_name_ptr, INTF_DOWN);
    }
}

cparser_result_t cparser_cmd_show_bridge_br_name(cparser_context_t *context, char **br_name_ptr)
{
    char buf[COMMAND_LEN_MAX];
    
    if (context == NULL) {
        return CPARSER_OK;
    }
    
    if (context->parser->mode != CPARSER_MODE_CONFIG) {
        return CPARSER_OK;
    } else {       
        if (br_name_ptr && *br_name_ptr) {
            show_bridge_info(context, *br_name_ptr);
            snprintf(buf, COMMAND_LEN_MAX, "show bridge %s", *br_name_ptr);
        } else {
            /* 显示全部桥信息 */
            show_bridge_info(context, NULL);
            snprintf(buf, COMMAND_LEN_MAX, "show bridge");
        }
        
        admin_log_process(context, buf);
        return CPARSER_OK;
    }
}

cparser_result_t cparser_cmd_show_interface_intf_name(cparser_context_t *context, char **intf_name_ptr)
{
    char buf[COMMAND_LEN_MAX];
    
    if (context == NULL) {
        return CPARSER_OK;
    }

    if (context->parser->mode != CPARSER_MODE_CONFIG) {
        return CPARSER_OK;
    } else {       
        if (intf_name_ptr && *intf_name_ptr) {
            show_interface_info(context, *intf_name_ptr);   
            snprintf(buf, COMMAND_LEN_MAX, "show interface %s", *intf_name_ptr);
        } else {
            /* 显示全部接口信息 */
            show_interface_info(context, NULL);   
            snprintf(buf, COMMAND_LEN_MAX, "show interface");
        }

        admin_log_process(context, buf);
        return CPARSER_OK;
    }
}

