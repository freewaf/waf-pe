/*
 * $Id: url_bwlist.h 2786 2013-07-09 16:42:55 FreeWAF Development Team $
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

 
#ifndef _URL_BWLIST_H_
#define _URL_BWLIST_H_

#include "apr_global_mutex.h"
#include "apr_thread_mutex.h"
#include "apr_hash.h"
#include "apr_ring.h"
#include "apr_time.h"

#define URL_STRING_LEN           64
#define URL_TYPE_PLAINTEXT       0
#define URL_TYPE_REGULEREXP      1
#define URL_TYPE_ALL             2
#define URL_BWLIST_ENTRY_NUM     128
#define URL_DYN_BLIST_ENTRY_NUM  128
#define URL_DYN_BLIST_FILENAME   "/tmp/url_blist.txt"
#define URL_BWLIST_ADD           "Add"
#define URL_BWLIST_DEL           "Del"
#define URL_BLIST_ATTACK         2U
   
/* 静态URL结构 */
typedef struct cli_url_s {
    char *url;                            /* url字符串 */
    int type;                             /* url的类型，普通字符串或正则表达式 */
    msc_regex_t *url_regex;               /* 编译后的正则表达式 */
    apr_thread_mutex_t *mutex;            /* 线程会修改hitcount和last_logtime，需要锁 */       
    apr_time_t  last_logtime;             /* 最近的一次log记录时间 */
    int  hitcount;                        /* 一分钟之内的命中次数 */                    
} cli_url_t;

typedef struct dyn_ref_url_s {
    APR_RING_ENTRY(dyn_ref_url_s) link;   
    char ref_url[URL_STRING_LEN];                           /* Refferrer URL */
    apr_time_t start_time;                                  /* 禁用起始时间 */
    apr_time_t end_time;                                    /* 禁用结束时间 */
    apr_time_t last_logtime;                                /* 最近的一次log记录时间 */
    int hitcount;                                           /* 一分钟之内的命中次数 */                        
} dyn_ref_url_t;

/* 动态ref url共享内存管理结点 */
typedef struct dyn_url_blist_mg_s {
    apr_global_mutex_t *shm_mutex;                           /* 共享内存锁 */
    int free_num;                                            /* 当前空闲结点数目 */
    APR_RING_HEAD(url_free_head, dyn_ref_url_s) free_list;   /* 空闲结点链表 */
    APR_RING_HEAD(url_used_head, dyn_ref_url_s) used_list;   /* 动态Ref URL结点链表 */
} dyn_url_blist_mg_t;

enum url_bwlist_type_e {
    URL_BLIST,                                               /* URL黑名单 */
    URL_REF_BLIST_EXCPT,                                     /* Referrer URL 动态例外黑名单 */
    URL_WLIST,                                               /* URL白名单 */
    URL_BWLIST_NUM
};

enum url_error_type_e {
    URL_LIST_IS_FULL = 1,
    URL_REF_IN_EXCPT,
    URL_HAS_IN_LIST,
    URL_TRUNCATE_INVALID
};

/**
 * url_bwlist_create - 创建url黑白名单
 * @pool: 内存池
 *
 * 返回值: 初始化成功返回APR_SUCCESS,失败返回-1
 */
extern int url_bwlist_create(apr_pool_t *pool);

/*
 * url_dyn_blist_get - 获取动态url黑名单内容
 * @result: 返回数组
 *
 * 返回值: 无
 */
extern int url_dyn_blist_get(apr_array_header_t **result);

/**
 * url_dyn_blist_add - 添加一个url到动态referrer url黑名单
 * @ref_url: referrer url
 * 
 * 返回-1表示添加失败，返回APR_SUCCESS表示添加成功；
 */
extern int url_dyn_blist_add(char *ref_url);

/**
 * url_dyn_blist_create - 创建动态url黑名单
 * @pool: 内存池
 *
 * 返回值: 成功返回APR_SUCCESS,失败返回-1
 */
extern int url_dyn_blist_create(apr_pool_t *pool);

/**
 * url_bwlist_process - url黑白名单匹配处理
 * @msr: 事务处理上下文结构，从中可以获得url信息，并且可以记载黑白名单命中标记
 *
 * 返回值: 成功返回APR_SUCCESS,失败返回-1
 */
extern int url_bwlist_process(modsec_rec *msr);

/**
 * cmd_blist_url - URL黑名单命令函数
 * @cmd: 和命令有关的参数结构指针
 * @dcfg: 配置结构
 * @action: 命令动作
 * @url_type: url类型，普通字符串或者正则表达式
 * @url: url
 *
 * 返回值: 成功返回NULL,失败返回字符串
 */
extern const char *cmd_blist_url(cmd_parms *cmd, void *_dcfg, const char *action, 
                    const char *url_type, const char *url);

/**
 * cmd_blist_dyn_ref_url_timeout - 动态ref url黑名单命令超时函数
 * @cmd: 和命令有关的参数结构指针
 * @dcfg: 配置结构
 * @strtimeout: 时间字符串
 *
 * 返回值: 成功返回NULL,失败返回字符串
 */
extern const char *cmd_blist_dyn_ref_url_timeout(cmd_parms *cmd, void *_dcfg, 
                    const char *strtimeout);

/**
 * cmd_blist_dyn_ref_url - Referrer URL黑名单命令函数
 * @cmd: 和命令有关的参数结构指针
 * @dcfg: 配置结构
 * @action: 命令动作
 * @ref_url: referrer url参数
 *
 * 返回值: 成功返回NULL,失败返回字符串
 */
extern const char *cmd_blist_dyn_ref_url(cmd_parms *cmd, void *_dcfg, const char *action, 
                    const char *ref_url);

/**
 * cmd_blist_ref_url_except - 例外referrer url黑名单命令函数
 * @cmd: 和命令有关的参数结构指针
 * @dcfg: 配置结构
 * @action: 命令动作
 * @excpt_url: url参数
 *
 * 返回值: 成功返回NULL,失败返回字符串
 */
extern const char *cmd_blist_ref_url_except(cmd_parms *cmd, void *_dcfg, const char *action, 
                    const char *excpt_url);

/**
 * cmd_wlist_url - url白名单命令函数
 * @cmd: 和命令有关的参数结构指针
 * @dcfg: 配置结构
 * @action: 命令动作
 * @url_type:url类型
 * @url: url参数
 *
 * 返回值: 成功返回NULL,失败返回字符串
 */
extern const char *cmd_wlist_url(cmd_parms *cmd, void *_dcfg, const char *action, 
                    const char *url_type, const char *url);

/**
 * cmd_url_bwlist - url黑白名单开启或关闭函数
 * @cmd: 和命令有关的参数结构指针
 * @p1: url黑白名单开关，on/off
 *
 * 返回值: 成功返回NULL,失败返回字符串
 */
extern const char *cmd_url_bwlist(cmd_parms *cmd, void *_dcfg, const char *p1);

/**
 * url_dyn_blist_timer_destroy - 停止定时器线程
 * 无参数
 *
 * 返回值: 初始化成功返回APR_SUCCESS,失败返回-1
 */
extern int url_dyn_blist_timer_destroy(void);

#endif  /* _URL_BWLIST_H_ */

