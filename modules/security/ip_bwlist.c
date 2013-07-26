/*
 * $Id: ip_bwlist.c 2786 2013-07-09 16:42:55 FreeWAF Development Team $
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

#include <string.h>
#include "modsecurity.h"
#include "apr_errno.h"
#include "apr_pools.h"
#include "apr_tables.h"
#include "apr_shm.h"
#include "bwlist_common.h"
#include "ip_bwlist.h"

static apr_hash_t *wlist[IP_WLIST_NUM];             /* 白名单 */      
static apr_hash_t *blist[IP_BLIST_NUM];             /* 黑名单 */
static shm_info_mg_t *dyn_ip_blist_base;            /* 动态黑名单共享内存管理结点 */
static blist_timer_t *dyn_ip_blist_timer;           /* 动态黑名单定时器 */
static long timeout = DYN_BLIST_DEFAULT_TIMEOUT;    /* 超时时间 */                                
static int ip_bwlist_stop = 0;                      /* IP动态黑名单停止标志 */

/*
 * dyn_cli_ip_find - 从客户端动态ip链表中查找指定的客户端动态ip
 * @ip: 需要查找的ip结点
 *
 * 返回值: 指向ip结点的指针
 */
static dyn_cli_ip_t *dyn_cli_ip_find(const char *ip)
{
    dyn_cli_ip_t *node;
    
    APR_RING_FOREACH(node, &dyn_ip_blist_base->used_list, dyn_cli_ip_s, link) {
        if (strcmp(node->cli_ip, ip) == 0) {
            return node;
        }
    }

    return NULL;
}

/*
 * dyn_cli_ip_del - 从客户端动态ip链表中删除指定的客户端动态ip
 * @node: 需要删除的ip结点
 *
 * 返回值: 无
 */
static void dyn_cli_ip_del(dyn_cli_ip_t *node)
{
    /* 从动态ip链表中摘下该结点 */
    APR_RING_REMOVE(node, link);
    /* 将该结点插入空闲列表 */
    APR_RING_INSERT_TAIL(&dyn_ip_blist_base->free_list, node, dyn_cli_ip_s, link);
    dyn_ip_blist_base->free_num++;
}

/*
 * dyn_cli_ip_add - 将一个新结点插入到客户端动态ip链表
 * @new_ip: 需要插入的ip结点
 *
 * 返回值: 无
 */
static void dyn_cli_ip_add(dyn_cli_ip_t *new_ip)
{
    dyn_cli_ip_t *node;
    apr_time_t new_ip_endtime;

    new_ip_endtime = new_ip->end_time;
    /* 链表按到期时间由小到大排序 */
    APR_RING_FOREACH(node, &dyn_ip_blist_base->used_list, dyn_cli_ip_s, link) {
        if (new_ip_endtime < node->end_time) {   
            APR_RING_INSERT_BEFORE(node, new_ip, link);
            return;
        }
    }
    /* 新结点的到期时间大于所有的结点，则直接插在最后面 */
    APR_RING_INSERT_TAIL(&dyn_ip_blist_base->used_list, new_ip, dyn_cli_ip_s, link);
}

/*
 * dyn_blist_del - 从客户端动态ip黑名单中删除指定的ip或所有ip
 * @cli_ip: 需要删除的ip，取值为ip地址或"all"
 *
 * 返回值: 成功返回NULL,失败返回字符串
 */
static char *dyn_blist_del(const char *cli_ip)
{
    dyn_cli_ip_t *node, *node_tmp;
    unsigned int ip_len;

    if (cli_ip == NULL || (ip_len = strlen(cli_ip)) == 0 || ip_len >= IPADDR_LEN) {
        return "ModSecurity: Failed to get the current args";
    }
    
    apr_global_mutex_lock(dyn_ip_blist_base->shm_mutex);
    if (strcmp(cli_ip, "all") == 0) {
        /* 删除名单中所有ip结点 */
        APR_RING_FOREACH_SAFE(node, node_tmp, &dyn_ip_blist_base->used_list, dyn_cli_ip_s, link) {
            dyn_cli_ip_del(node);
        }
        apr_global_mutex_unlock(dyn_ip_blist_base->shm_mutex);
        return NULL;
    }
     
    node = dyn_cli_ip_find(cli_ip);
    if (node != NULL) {
        dyn_cli_ip_del(node);
    }
    apr_global_mutex_unlock(dyn_ip_blist_base->shm_mutex);

    return NULL;
}

/*
 * dyn_blist_free_list_init - 初始化空闲结点链表
 * 参数: 无
 * 将共享内存中除头部管理结点以外的空间挂在空闲结点链表上
 *
 * 返回值: 无
 */
static void dyn_blist_free_list_init(void)
{
    int i;
    dyn_cli_ip_t *dyn_blist;

    dyn_blist = (dyn_cli_ip_t *)((void *)dyn_ip_blist_base + sizeof(shm_info_mg_t));
    for(i = 0; i < IP_DYN_BLIST_ENTRY_NUM; i++) {
         APR_RING_INSERT_TAIL(&dyn_ip_blist_base->free_list, dyn_blist + i, dyn_cli_ip_s, link);
    }  
}

/*
 * dyn_blist_create - 创建动态客户IP黑名单
 * @pool: 所属内存池
 * 
 * 创建共享内存，初始化头部管理结点以及空闲链表 
 *
 * 返回值: 成功返回APR_SUCCESS,失败返回-1
 */
static int dyn_blist_create(apr_pool_t *pool)
{
    apr_shm_t *dyn_blist_shm;
    apr_size_t shm_size;
    int status;
    
    apr_shm_remove(IP_DYN_BLIST_FILENAME, pool);
    shm_size = IP_DYN_BLIST_ENTRY_NUM * sizeof(dyn_cli_ip_t) + sizeof(shm_info_mg_t);
    status = apr_shm_create(&dyn_blist_shm, shm_size, IP_DYN_BLIST_FILENAME, pool);   
    if (status != APR_SUCCESS) {
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, NULL, "ModSecurity:Failed to create ip_blist_shm.");
        return -1;
    }

    dyn_ip_blist_base = (shm_info_mg_t *)apr_shm_baseaddr_get(dyn_blist_shm);
    status = apr_global_mutex_create(&dyn_ip_blist_base->shm_mutex, NULL, APR_LOCK_DEFAULT, pool);
    if (status != APR_SUCCESS) {
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, NULL, "ModSecurity:Failed to create ip shm mutex.");
        return -1;
    }

    dyn_ip_blist_base->free_num = IP_DYN_BLIST_ENTRY_NUM;
    APR_RING_INIT(&dyn_ip_blist_base->free_list, dyn_cli_ip_s, link);
    APR_RING_INIT(&dyn_ip_blist_base->used_list, dyn_cli_ip_s, link);
    dyn_blist_free_list_init();

    return APR_SUCCESS;
}

/**
 * ip_dyn_blist_add - 添加一个ip到客户端动态ip黑名单
 * @cli_ip: 客户端ip
 * 
 * 返回-1表示添加失败，返回APR_SUCCESS表示添加成功；
 */
int ip_dyn_blist_add(const char *cli_ip) 
{
    void *excpt_ip;
    dyn_cli_ip_t *new_cli_ip;
    unsigned int ip_len; 

    if (cli_ip == NULL || (ip_len = strlen(cli_ip)) == 0 || ip_len >= IPADDR_LEN) {
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, NULL, 
            "ip_dyn_blist_add: Failed to get the current args");
        return -1;
    }
    
    if (ip_bwlist_stop) {
        return APR_SUCCESS;
    }
    
    excpt_ip = apr_hash_get(blist[IP_BLIST_EXCPT_IP], cli_ip, strlen(cli_ip));
    if (excpt_ip != NULL) {
        ap_log_error(APLOG_MARK, APLOG_WARNING, 0, NULL, 
            "ModSecurity:%s has be in the ip_dyn excpt blist", cli_ip);
        return APR_SUCCESS;
    }

    apr_global_mutex_lock(dyn_ip_blist_base->shm_mutex);
    if (dyn_ip_blist_base->free_num == 0) {
        apr_global_mutex_unlock(dyn_ip_blist_base->shm_mutex);
        ap_log_error(APLOG_MARK, APLOG_WARNING, 0, NULL, 
            "ModSecurity:ip dyn blist has no free node");
        return APR_SUCCESS;
    }

    if (dyn_cli_ip_find(cli_ip) != NULL) {
        apr_global_mutex_unlock(dyn_ip_blist_base->shm_mutex);
        ap_log_error(APLOG_MARK, APLOG_WARNING, 0, NULL, 
            "ModSecurity:%s has be in the ip dyn blist", cli_ip);
        return APR_SUCCESS;
    }

    /* 获得一个空闲结点 */
    new_cli_ip = (dyn_cli_ip_t *)APR_RING_FIRST(&dyn_ip_blist_base->free_list);
    APR_RING_REMOVE(new_cli_ip, link);
    dyn_ip_blist_base->free_num--;
    
    memset(new_cli_ip, 0, sizeof(dyn_cli_ip_t));
    strcpy(new_cli_ip->cli_ip, cli_ip);
    new_cli_ip->start_time = apr_time_now();
    /* apr获取的时间单位为微秒 */
    new_cli_ip->end_time = new_cli_ip->start_time + (apr_time_t)(BLIST_TIME_TO_USEC(timeout));
    dyn_cli_ip_add(new_cli_ip);
    apr_global_mutex_unlock(dyn_ip_blist_base->shm_mutex);\
        
    return APR_SUCCESS;
}

/*
 * ip_dyn_blist_get - 获取动态ip黑名单内容
 * @result: 返回数组
 *
 * 返回值: 成功返回APR_SUCCESS,失败返回-1
 */
int ip_dyn_blist_get(apr_array_header_t **result)
{
    dyn_cli_ip_t *node;
    dyn_blist_show_str_t *ip_info, **arr_node;
    apr_pool_t *pool;
    
    if (result == NULL || *result == NULL) {
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, NULL, 
            "ip_dyn_blist_get: Failed to get the current args");
        return -1;
    }

    pool = (*result)->pool;
    apr_global_mutex_lock(dyn_ip_blist_base->shm_mutex);
    APR_RING_FOREACH(node, &dyn_ip_blist_base->used_list, dyn_cli_ip_s, link) {   
        ip_info = (dyn_blist_show_str_t *)apr_pcalloc(pool, sizeof(dyn_blist_show_str_t));
        if (ip_info == NULL) {
            apr_global_mutex_unlock(dyn_ip_blist_base->shm_mutex);
            return -1;
        }
        ip_info->str = (char *)apr_pcalloc(pool, IPADDR_LEN);
        if (ip_info->str == NULL) {
            apr_global_mutex_unlock(dyn_ip_blist_base->shm_mutex);
            return -1;
        }
        strcpy(ip_info->str, node->cli_ip);
        ip_info->start_time = (char *)apr_pcalloc(pool, TIME_STRING_LEN);
        if (ip_info->start_time == NULL) {
            apr_global_mutex_unlock(dyn_ip_blist_base->shm_mutex);
            return -1;
        }
        apr_ctime(ip_info->start_time, node->start_time);
        ip_info->end_time = (char *)apr_pcalloc(pool, TIME_STRING_LEN);
        if (ip_info->end_time == NULL) {
            apr_global_mutex_unlock(dyn_ip_blist_base->shm_mutex);
            return -1;
        }
        apr_ctime(ip_info->end_time, node->end_time);
        arr_node = (dyn_blist_show_str_t **)apr_array_push(*result);
        *arr_node = ip_info;
    }
    apr_global_mutex_unlock(dyn_ip_blist_base->shm_mutex);
    
    return APR_SUCCESS;
}

/*
 * dyn_timeout_ip_find_and_del - 查找超时的动态ip并摘除
 * 参数: 无
 *
 * 返回值: 无
 */
static void dyn_timeout_ip_find_and_del(void)
{
    dyn_cli_ip_t *node, *node_tmp;
    apr_time_t nowtime;

    nowtime = apr_time_now();
    apr_global_mutex_lock(dyn_ip_blist_base->shm_mutex);
    APR_RING_FOREACH_SAFE(node, node_tmp, &dyn_ip_blist_base->used_list, dyn_cli_ip_s, link) {
        if (node->end_time <= nowtime) {
            dyn_cli_ip_del(node);
        }
    }
    apr_global_mutex_unlock(dyn_ip_blist_base->shm_mutex);
}

/*
 * bwlist_create - 创建黑白名单
 * @pool: 所属内存池
 * @list_arr: 黑名单或白名单数组
 * @arr_num: 数组大小
 *
 * 返回值: 成功返回APR_SUCCESS,失败返回-1
 */
static int bwlist_create(apr_pool_t *pool, apr_hash_t **list_arr, int arr_num)             
{
    int i;
    
    for (i = 0; i < arr_num; i++) {
        if ((list_arr[i] = apr_hash_make(pool)) == NULL) {
            return -1;
        }
    }
    
    return APR_SUCCESS;
}

/*
 * bwlist_add - 添加一个ip结点到指定的名单
 * @pool: 所属内存池
 * @list: 名单
 * @s: ip字符串或者域名字符串
 *
 * 返回值: 成功返回NULL,失败返回字符串
 */
static char *bwlist_add(apr_pool_t *pool, apr_hash_t *list, const char *s)
{
    char *new_s;
    cli_ip_t *cli_ip;
    int rv;
    
    if (pool == NULL || s == NULL || strlen(s) == 0) {   
        return "ModSecurity: Failed to get the current args";
    }

    if (apr_hash_get(list, s, strlen(s)) != NULL) {
        ap_log_error(APLOG_MARK, APLOG_WARNING, 0, NULL, "ModSecurity:%s has be in the table", s);
        return NULL;
    }
    
    if (apr_hash_count(list) >= IP_BWLIST_ENTRY_NUM) {
        ap_log_error(APLOG_MARK, APLOG_WARNING, 0, NULL, "ModSecurity: The table is full");
        return NULL;
    }

    if ((new_s = apr_pstrdup(pool, s)) == NULL) {
        return FATAL_ERROR;
    }

    cli_ip  = (cli_ip_t *)apr_pcalloc(pool, sizeof(cli_ip_t));
    if (cli_ip == NULL) {
        return FATAL_ERROR;
    }

    cli_ip->ip = new_s;
    rv = apr_thread_mutex_create(&(cli_ip->mutex), APR_THREAD_MUTEX_DEFAULT, pool);
    if (rv != APR_SUCCESS) {
        return FATAL_ERROR;
    }
    apr_hash_set(list, new_s, strlen(new_s), (void *)cli_ip);
    
    return NULL;
}

/*
 * bwlist_del - 删除指定的名单中的一个或所有结点
 * @list: 需要删除的名单
 * @s: 需要删除的结点，若为"all"则清除名单中所有结点
 *
 * 返回值: 成功返回NULL,失败返回字符串
 */
static char *bwlist_del(apr_hash_t *list, const char *s)
{   
    if (s == NULL || strlen(s) == 0) {
        return "ModSecurity: Failed to get the current args";
    }
    
    if (strcmp(s, "all") == 0) {
        apr_hash_clear(list);
        return NULL;
    }

    if (apr_hash_get(list, s, strlen(s)) == NULL) {
        ap_log_error(APLOG_MARK, APLOG_WARNING, 0, NULL, "ModSecurity:%s is not in the table", s);
        return NULL;
    }
    
    apr_hash_set(list, s, strlen(s), NULL);
    
    return NULL;
}

/**
 * ip_bwlist_proccess - ip黑白名单处理
 * @msr: 事务处理上下文
 *
 * 处理过程遵循黑名单优先原则 
 *
 * 返回值: 出错返回-1，匹配到黑名单返回HTTP_FORBDDEN,匹配到白名单或什么都没匹配到返回OK
 */
int ip_bwlist_proccess(modsec_rec *msr)
{
    const char *cli_ip;
    const char *serv_ip;
    const char *hostname;
    cli_ip_t *blackip;
    apr_time_t now;
    dyn_cli_ip_t *dyn_blackip;
    
    if (msr == NULL || msr->txcfg == NULL) {
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, NULL, 
            "ip_bwlist_proccess: Failed to get the current args");
        return -1;
    }

    /* 如果处于非检测模式，不匹配黑白名单 */
    if (msr->txcfg->is_enabled == MODSEC_DISABLED) {
        msr_log(msr, 1, "Current work-mode: detection-distable");
        return OK;
    }
    
    cli_ip = msr->remote_addr;
    serv_ip = msr->local_addr;
    hostname = msr->hostname;
    if (cli_ip == NULL || serv_ip == NULL || hostname == NULL) {
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, NULL, 
            "ip_bwlist_proccess: Failed to get the current args.");
        return -1;
    }

    now = apr_time_now();
    
    /* 查找客户端ip黑名单 */
    blackip = (cli_ip_t *)apr_hash_get(blist[IP_BLIST_CLI_IP], cli_ip, strlen(cli_ip));
    if (blackip != NULL) {
        apr_thread_mutex_lock(blackip->mutex);
        blackip->hitcount++;
        /* 如果该ip命中黑名单，并且距上次记录log时间大于1分钟，
         * 则标识black_list_log，并在log阶段进行记录 
         */
        if ((now - blackip->last_logtime) >= BLIST_TIME_TO_USEC(1)) {
            msr->black_list_log = 1;
            msr->black_list_hitcount = blackip->hitcount;
            blackip->last_logtime = now;
            blackip->hitcount = 0;
        }
        apr_thread_mutex_unlock(blackip->mutex);
        msr->black_list_flag |= IP_BLIST_ATTACK;
#ifdef DEBUG_DBLOG
        if (msr->txcfg->attacklog_flag) {
            msc_record_attacklog(msr, NULL,  NULL);
        }
#endif
        ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, msr->r->server, " %s hit ip black list", cli_ip);
        if (msr->txcfg->is_enabled == MODSEC_DETECTION_ONLY) {
            msr_log(msr, 1, "Current work-mode: detection-only");
            return OK;
        }
        return HTTP_SERVICE_UNAVAILABLE;
    }

    /* 查找客户端动态ip黑名单 */
    apr_global_mutex_lock(dyn_ip_blist_base->shm_mutex);
    dyn_blackip = dyn_cli_ip_find(cli_ip);
    if (dyn_blackip != NULL) {
        dyn_blackip->hitcount++;
        if ((now - dyn_blackip->last_logtime) >= BLIST_TIME_TO_USEC(1)) {
            msr->black_list_log = 1;
            msr->black_list_hitcount = dyn_blackip->hitcount;
            dyn_blackip->last_logtime = now;
            dyn_blackip->hitcount = 0;
        }
        msr->black_list_flag |= IP_BLIST_ATTACK;
#ifdef DEBUG_DBLOG
        if (msr->txcfg->attacklog_flag) {
            msc_record_attacklog(msr, NULL, NULL);
        }
#endif
        apr_global_mutex_unlock(dyn_ip_blist_base->shm_mutex);
        ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, msr->r->server, "%s hit dyn_cli_ip_blist", cli_ip);
        if (msr->txcfg->is_enabled == MODSEC_DETECTION_ONLY) {
            msr_log(msr, 1, "Current work-mode: detection-only");
            return OK;
        }
        return HTTP_SERVICE_UNAVAILABLE;
    }
    apr_global_mutex_unlock(dyn_ip_blist_base->shm_mutex);

    /* 查找客户端ip白名单 */
    if (apr_hash_get(wlist[IP_WLIST_CLI_IP], cli_ip, strlen(cli_ip)) != NULL) {
        ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, msr->r->server, "%s hit client ip white list",
            cli_ip);
        msr->white_list = 1;
        return OK;
    }

    /* 查找服务器ip白名单 */
    if (apr_hash_get(wlist[IP_WLIST_SERV_IP], serv_ip, strlen(serv_ip)) != NULL) {
        ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, msr->r->server, 
            "%s hit server ip white list", serv_ip);
        msr->white_list = 1;
        return OK;
    } 

    /* 查找服务器端域名白名单 */
    if(apr_hash_get(wlist[IP_WLIST_HOSTNAME] , hostname, strlen(hostname)) != NULL) {
        ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, msr->r->server, 
            "%s hit server hostname white list", hostname);
        msr->white_list = 1;
        return OK;
    }
    
    return OK;
}

/**
 * ip_bwlist_create - 创建ip黑白名单
 * @pool: 内存池
 *
 * 返回值: 初始化成功返回APR_SUCCESS,失败返回-1
 */
int ip_bwlist_create(apr_pool_t *pool)
{     
    if (pool == NULL) {
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, NULL, 
            "ip_bwlist_create: Failed to get the current args");
        return -1;
    }
    
    if (bwlist_create(pool, wlist, IP_WLIST_NUM) != APR_SUCCESS) {
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, NULL, 
            "ip_bwlist_create: Failed to create ip white list");
        return -1;
    }
    
    if (bwlist_create(pool, blist, IP_BLIST_NUM) != APR_SUCCESS) {
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, NULL, 
            "ip_bwlist_create: Failed to create ip black list");
        return -1;
    }
    
    return APR_SUCCESS;
}

/**
 * ip_dyn_blist_timer_destroy - 停止定时器线程
 * 无参数
 *
 * 返回值: 初始化成功返回OK,失败返回DECLINED
 */
int ip_dyn_blist_timer_destroy(void)
{
    int rv;
    
    if (dyn_ip_blist_timer == NULL) {
        return OK;
    }

    /* 停止定时器线程 */
    rv = dyn_blist_timer_stop(dyn_ip_blist_timer);
    if (rv != APR_SUCCESS) {
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, NULL, "stop ip dynamic black list timer failed"); 
        return DECLINED;
    }
    
    dyn_ip_blist_timer = NULL;  

    return OK;
}

static apr_status_t ip_dyn_blist_timer_create(apr_pool_t *pool)
{
    int rv;

    /* 创建定时器 */
    dyn_ip_blist_timer = dyn_blist_timer_create(pool, dyn_timeout_ip_find_and_del);
    if (dyn_ip_blist_timer == NULL) {
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, NULL, 
            "ip_dyn_blist_create: Failed to create ip timer");
        return -1;
    }

    /* 运行定时器线程 */
    rv = dyn_blist_timer_start(pool, dyn_ip_blist_timer);
    if (rv != APR_SUCCESS) {
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, NULL, "start ip timer thread fail"); 
        dyn_ip_blist_timer = NULL;
        return -1;
    }
   
    return APR_SUCCESS;
}

/**
 * ip_dyn_blist_create - 创建动态ip黑名单和动态黑名单定时器
 * @pool: 内存池
 *
 * 返回值: 初始化成功返回APR_SUCCESS,失败返回-1
 */
int ip_dyn_blist_create(apr_pool_t *pool)
{
    apr_pool_t *gpool;
    
    if (pool == NULL) {
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, NULL, 
            "ip_dyn_blist_create: Failed to get the current args");
        return -1;
    }

    /* 获得全局内存池 */
    gpool = apr_pool_parent_get(pool);
    apr_pool_userdata_get((void **)&dyn_ip_blist_base, "dyn-blist-init", gpool);
    
    if (dyn_ip_blist_base == NULL) {
        /* 创建动态ip黑名单 */
        if (dyn_blist_create(gpool) != APR_SUCCESS) {
            ap_log_error(APLOG_MARK, APLOG_ERR, 0, NULL, 
                "ip_dyn_blist_create: Failed to create ip dynamic black list");
            return -1;
        }
        apr_pool_userdata_set((const void *)dyn_ip_blist_base, "dyn-blist-init", 
            apr_pool_cleanup_null, gpool);
        return APR_SUCCESS;
    }

    /* 创建定时器线程，使用的是配置池，初始化的时候在第二次pre_config创建，之后重启都先销毁，再重新创建 */
    return ip_dyn_blist_timer_create(pool);
}

/**
 * cmd_blist_cli_ip - 客户端ip黑名单命令函数
 * @cmd: 和命令有关的参数结构指针
 * @dcfg: 配置结构
 * @action: 命令动作
 * @cli_ip: ip参数
 *
 * 返回值: 成功返回NULL,失败返回字符串
 */
const char *cmd_blist_cli_ip(cmd_parms *cmd, void *_dcfg, const char *action, const char *cli_ip)
{
    if (cmd == NULL || action == NULL) {
        return "ModSecurity: Failed to get the current args";
    }

    if (strcasecmp(action, IP_BWLIST_ADD) == 0) {
        return bwlist_add(cmd->pool, blist[IP_BLIST_CLI_IP], cli_ip);
    } else if (strcmp(action, IP_BWLIST_DEL) == 0) {
        return bwlist_del(blist[IP_BLIST_CLI_IP], cli_ip);
    } else {
        return "ModSecurity: cmd_blist_cli_ip cann't proccess the action.";
    }
}

/**
 * cmd_blist_dyn_ip_timeout - 客户端动态ip黑名单命令函数
 * @cmd: 和命令有关的参数结构指针
 * @dcfg: 配置结构
 * @strtimeout: 时间字符串
 *
 * 返回值: 成功返回NULL,失败返回字符串
 */
const char *cmd_blist_dyn_ip_timeout(cmd_parms *cmd, void *_dcfg, const char *strtimeout) 
{
    long new_timeout;

    if (strtimeout == NULL) {
        return "ModSecurity: Failed to get the current args";
    }

    /* 由字符串转换为长整型 */
    new_timeout = strtol(strtimeout, NULL, 0);   
    if (new_timeout < BLIST_MIN_TIMEOUT || new_timeout > BLIST_MAX_TIMEOUT) {
        return "ModSecurity: The timeout is not in the range";
    }
    timeout = new_timeout;
    
    return NULL;
}

/**
 * cmd_blist_dyn_ip_except - 客户端动态例外ip黑名单命令函数
 * @cmd: 和命令有关的参数结构指针
 * @dcfg: 配置结构
 * @action: 命令动作
 * @excpt_ip: ip参数
 *
 * 返回值: 成功返回NULL,失败返回字符串
 */
const char *cmd_blist_dyn_ip_except(cmd_parms *cmd, void *_dcfg, const char *action, 
             const char *excpt_ip)
{
    char *msg_error;

    if (cmd == NULL || action == NULL) {
        return "ModSecurity: Failed to get the current args";
    }

    if (strcasecmp(action, IP_BWLIST_ADD) == 0) {
        msg_error = bwlist_add(cmd->pool, blist[IP_BLIST_EXCPT_IP], excpt_ip);
        if (msg_error != NULL) {
            return msg_error;
        }
        msg_error = dyn_blist_del(excpt_ip);
        return msg_error;
    } else if (strcasecmp(action, IP_BWLIST_DEL) == 0) {
        return bwlist_del(blist[IP_BLIST_EXCPT_IP], excpt_ip);
    } else {
        return "ModSecurity: cmd_blist_dyn_ip_except cann't proccess the action.";
    }
}

/**
 * cmd_blist_dyn_cli_ip - 客户端动态ip黑名单命令函数
 * @cmd: 和命令有关的参数结构指针
 * @dcfg: 配置结构
 * @action: 命令动作
 * @cli_ip: ip参数
 *
 * 返回值: 成功返回NULL,失败返回字符串
 */
const char *cmd_blist_dyn_cli_ip(cmd_parms *cmd, void *_dcfg, const char *action, 
             const char *cli_ip)
{     
    if (action == NULL) {
        return "ModSecurity: Failed to get the current args";
    }

    if (strcasecmp(action, IP_BWLIST_DEL) == 0) {
        return dyn_blist_del(cli_ip);
    } else {
        return "ModSecurity: cmd_blist_dyn_cli_ip cann't proccess the action.";
    }
}

/**
 * cmd_wlist_cli_ip - 客户端ip白名单命令函数
 * @cmd: 和命令有关的参数结构指针
 * @dcfg: 配置结构
 * @action: 命令动作
 * @cli_ip: ip参数
 *
 * 返回值: 成功返回NULL,失败返回字符串
 */
const char *cmd_wlist_cli_ip(cmd_parms *cmd, void *_dcfg, const char *action, const char *cli_ip)
{
    if (cmd == NULL || action == NULL) {
        return "ModSecurity: Failed to get the current args";
    }

    if (strcasecmp(action, IP_BWLIST_ADD) == 0) {
        return bwlist_add(cmd->pool, wlist[IP_WLIST_CLI_IP], cli_ip);
    } else if (strcasecmp(action, IP_BWLIST_DEL) == 0) {
        return bwlist_del(wlist[IP_WLIST_CLI_IP], cli_ip);
    } else {
        return "ModSecurity: cmd_wlist_cli_ip cann't proccess the action.";
    }
}

/**
 * cmd_wlist_serv_ip - 服务器端ip白名单命令函数
 * @cmd: 和命令有关的参数结构指针
 * @dcfg: 配置结构
 * @action: 命令动作
 * @serv_ip: ip参数
 *
 * 返回值: 成功返回NULL,失败返回字符串
 */
const char *cmd_wlist_serv_ip(cmd_parms *cmd, void *_dcfg, const char *action, const char *serv_ip)
{
    if (cmd == NULL || action == NULL) {
        return "ModSecurity: Failed to get the current args";
    }

    if (strcasecmp(action, IP_BWLIST_ADD) == 0) {
        return bwlist_add(cmd->pool, wlist[IP_WLIST_SERV_IP], serv_ip);
    } else if (strcasecmp(action, IP_BWLIST_DEL) == 0) {
        return bwlist_del(wlist[IP_WLIST_SERV_IP], serv_ip);
    } else {
        return "ModSecurity: cmd_wlist_serv_ip cann't proccess the action.";
    }
}

/**
 * cmd_wlist_serv_host - 服务器端域名白名单命令函数
 * @cmd: 和命令有关的参数结构指针
 * @dcfg: 配置结构
 * @action: 命令动作
 * @host: 域名参数
 *
 * 返回值: 成功返回NULL,失败返回字符串
 */
const char *cmd_wlist_serv_host(cmd_parms *cmd, void *_dcfg, const char *action, 
             const char *host)
{   
    if (cmd == NULL || action == NULL) {
        return "ModSecurity: Failed to get the current args";
    }

    if (strcasecmp(action, IP_BWLIST_ADD) == 0) {
        return bwlist_add(cmd->pool, wlist[IP_WLIST_HOSTNAME], host);
    } else if (strcasecmp(action, IP_BWLIST_DEL) == 0) {
        return bwlist_del(wlist[IP_WLIST_HOSTNAME], host);
    } else {
        return "ModSecurity: cmd_wlist_serv_ip cann't proccess the action.";
    }
}

/**
 * cmd_ip_bwlist - ip黑白名单开启或关闭函数
 * @cmd: 和命令有关的参数结构指针
 * @p1: ip黑白名单开关，on/off
 *
 * 返回值: 成功返回NULL,失败返回字符串
 */
const char *cmd_ip_bwlist(cmd_parms *cmd, void *_dcfg, const char *p1)
{   
    if (cmd == NULL || p1 == NULL) {
        return "ModSecurity: Failed to get the current args";
    }

    if (strcasecmp(p1, "On") == 0) {
        ip_bwlist_stop = 0;
        return NULL;
    } else if (strcasecmp(p1, "Off") == 0) {
        ip_bwlist_stop = 1;
        return NULL;
    } else {
        return (const char *)apr_psprintf(cmd->pool, "ModSecurity: Unrecognised parameter value "
            "for SecIPBWList: %s", p1);
    }
}

