/*
 * $Id: ip_bwlist.h 2786 2013-07-09 16:42:55 FreeWAF Development Team $
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

 
#ifndef _IP_BWLIST_H_
#define _IP_BWLIST_H_

#include "apr_global_mutex.h"
#include "apr_thread_mutex.h"
#include "apr_hash.h"
#include "apr_ring.h"
#include "apr_time.h"

#define IPADDR_LEN                   32
#define IP_DYN_BLIST_ENTRY_NUM       128               /* 动态黑名单可存放的结点数目 */
#define IP_BWLIST_ENTRY_NUM          128               /* IP黑白名单可存放的结点数目 */
#define IP_DYN_BLIST_FILENAME        "/tmp/ip_blist.txt"
#define IP_BWLIST_ADD                "Add"
#define IP_BWLIST_DEL                "Del"
#define IP_BLIST_ATTACK              1U

/* 静态IP结构 */
typedef struct cli_ip_s {
    char *ip;                                         /* ip或域名 */
    apr_thread_mutex_t *mutex;                        /* 线程会修改hitcount和last_logtime，需要锁 */
    apr_time_t  last_logtime;                         /* 最近的一次log记录时间 */
    int  hitcount;                                    /* 一分钟之内的命中次数 */
} cli_ip_t;

/* 动态IP结构 */
typedef struct dyn_cli_ip_s {
    APR_RING_ENTRY(dyn_cli_ip_s) link;    
    char cli_ip[IPADDR_LEN];                           /* 客户端动态ip */
    apr_time_t start_time;                             /* ip被锁定时间 */
    apr_time_t end_time;                               /* ip解锁时间 */
    apr_time_t last_logtime;                           /* 最近的一次log记录时间 */
    int hitcount;                                      /* 一分钟之内的命中次数 */
} dyn_cli_ip_t;

/* 共享内存管理结点 */
typedef struct shm_info_mg_s {
    apr_global_mutex_t *shm_mutex;                         /* 共享内存锁 */
    int free_num;                                          /* 当前空闲结点数目 */
    APR_RING_HEAD(ip_free_head, dyn_cli_ip_s) free_list;   /* 空闲结点链表 */
    APR_RING_HEAD(ip_used_head, dyn_cli_ip_s) used_list;   /* 客户端动态IP结点链表 */
} shm_info_mg_t;

enum ip_wlist_type_s {
    IP_WLIST_CLI_IP,
    IP_WLIST_SERV_IP,
    IP_WLIST_HOSTNAME,
    IP_WLIST_NUM
};

enum ip_blist_type_s {
    IP_BLIST_CLI_IP,
    IP_BLIST_EXCPT_IP,
    IP_BLIST_NUM
};

/**
 * ip_dyn_blist_add - 添加一个ip到客户端动态ip黑名单
 * @cli_ip: 客户端ip
 * 
 * 返回-1表示添加失败，返回APR_SUCCESS表示添加成功；
 */
extern int ip_dyn_blist_add(const char *cli_ip);

/**
 * ip_bwlist_proccess - ip黑白名单处理
 * @msr: 事务处理上下文
 *
 * 处理过程遵循黑名单优先原则 
 *
 * 返回值: 出错返回-1，匹配到黑名单返回HTTP_FORBDDEN,匹配到白名单或什么都没匹配到返回OK
 */
extern int ip_bwlist_proccess(modsec_rec *msr);

/**
 * ip_bwlist_create - 创建ip黑白名单
 * @pool: 内存池
 *
 * 返回值: 初始化成功返回APR_SUCCESS,失败返回-1
 */
extern int ip_bwlist_create(apr_pool_t *pool);

/**
 * ip_dyn_blist_create - 创建动态ip黑名单和动态黑名单定时器
 * @pool: 内存池
 *
 * 返回值: 初始化成功返回APR_SUCCESS,失败返回-1
 */
extern int ip_dyn_blist_create(apr_pool_t *pool);

/*
 * ip_dyn_blist_get - 获取动态ip黑名单内容
 * @result: 返回数组
 *
 * 返回值: 成功返回APR_SUCCESS,失败返回-1
 */
extern int ip_dyn_blist_get(apr_array_header_t **result);

/**
 * cmd_blist_cli_ip - 客户端ip黑名单命令函数
 * @cmd: 和命令有关的参数结构指针
 * @dcfg: 配置结构
 * @action: 命令动作
 * @cli_ip: ip参数
 *
 * 返回值: 成功返回NULL,失败返回字符串
 */
extern const char *cmd_blist_cli_ip(cmd_parms *cmd, void *_dcfg, const char *action, 
    const char *cli_ip);

/**
 * cmd_blist_dyn_ip_timeout - 客户端动态ip黑名单命令函数
 * @cmd: 和命令有关的参数结构指针
 * @dcfg: 配置结构
 * @strtimeout: 时间字符串
 *
 * 返回值: 成功返回NULL,失败返回字符串
 */
extern const char *cmd_blist_dyn_ip_timeout(cmd_parms *cmd, void *_dcfg, const char *strtimeout);

/**
 * cmd_blist_dyn_ip_except - 客户端动态例外ip黑名单命令函数
 * @cmd: 和命令有关的参数结构指针
 * @dcfg: 配置结构
 * @action: 命令动作
 * @excpt_ip: ip参数
 *
 * 返回值: 成功返回NULL,失败返回字符串
 */
extern const char *cmd_blist_dyn_ip_except(cmd_parms *cmd, void *_dcfg, const char *action, 
    const char *excpt_ip);

/**
 * cmd_blist_dyn_cli_ip - 客户端动态ip黑名单命令函数
 * @cmd: 和命令有关的参数结构指针
 * @dcfg: 配置结构
 * @action: 命令动作
 * @cli_ip: ip参数
 *
 * 返回值: 成功返回NULL,失败返回字符串
 */
extern const char *cmd_blist_dyn_cli_ip(cmd_parms *cmd, void *_dcfg, const char *action, 
    const char *cli_ip);

/**
 * cmd_wlist_cli_ip - 客户端ip白名单命令函数
 * @cmd: 和命令有关的参数结构指针
 * @dcfg: 配置结构
 * @action: 命令动作
 * @cli_ip: ip参数
 *
 * 返回值: 成功返回NULL,失败返回字符串
 */
extern const char *cmd_wlist_cli_ip(cmd_parms *cmd, void *_dcfg, const char *action, 
    const char *cli_ip);

/**
 * cmd_wlist_serv_ip - 服务器端ip白名单命令函数
 * @cmd: 和命令有关的参数结构指针
 * @dcfg: 配置结构
 * @action: 命令动作
 * @serv_ip: ip参数
 *
 * 返回值: 成功返回NULL,失败返回字符串
 */
extern const char *cmd_wlist_serv_ip(cmd_parms *cmd, void *_dcfg, const char *action, 
    const char *serv_ip); 

/**
 * cmd_wlist_serv_host - 服务器端域名白名单命令函数
 * @cmd: 和命令有关的参数结构指针
 * @dcfg: 配置结构
 * @action: 命令动作
 * @host: 域名参数
 *
 * 返回值: 成功返回NULL,失败返回字符串
 */
extern const char *cmd_wlist_serv_host(cmd_parms *cmd, void *_dcfg, const char *action, 
    const char *host);

/**
 * cmd_wlist_serv_host - 服务器端域名白名单命令函数
 * @cmd: 和命令有关的参数结构指针
 * @p1: ip黑白名单开关，on/off
 *
 * 返回值: 成功返回NULL,失败返回字符串
 */
extern const char *cmd_ip_bwlist(cmd_parms *cmd, void *_dcfg, const char *p1);
/**
 * ip_dyn_blist_timer_destroy - 停止定时器线程
 * 无参数
 *
 * 返回值: 初始化成功返回OK,失败返回DECLIEND
 */
extern int ip_dyn_blist_timer_destroy(void);   

#endif  /* _IP_BWLIST_H_ */

