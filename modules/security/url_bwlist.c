/*
 * $Id: url_bwlist.c 2786 2013-07-09 16:42:55 FreeWAF Development Team $
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
#include "url_bwlist.h"

static apr_hash_t *url_bwlist[URL_BWLIST_NUM];        /* URL黑白名单 */
static dyn_url_blist_mg_t *dyn_url_blist_base;        /* URL动态黑白名单共享内存基地址 */
static blist_timer_t *dyn_url_blist_timer;            /* url动态黑名单定时器 */
static long url_timeout = DYN_BLIST_DEFAULT_TIMEOUT;  /* URL动态黑名单超时时间 */
static int url_bwlist_stop = 0;                       /* URL动态黑白名单停止标志 */

/*
 * url_truncate - 截断url
 * @url: url字符串
 *
 * url字符串处理，截断url，假如后面有查询字符串，则去掉查询字符串，
 * 假如长度超过64，则取长度小于64的url部分  
 *
 * 返回值:无
 */
static void url_truncate(char **url)
{
    char *url_end;
    char *url_temp;
    
    /* 截断协议部分 */
    url_end = strstr(*url, "://");   
    if (url_end != NULL) {
        *url = url_end + 3;
    }

    /* 截断查询字符串之后的内容 */
    url_end = strchr(*url, '?');
    if (url_end != NULL) {           
        *url_end = '\0';
    }
    
#if 0
    if (strlen(*url) < URL_STRING_LEN) {
        return;
    }
#endif 

    url_end = *url;
    while (1) {
        url_temp = url_end;
        url_end = strchr(url_end + 1, '/');
        if (url_end == NULL) {
            if (strlen(*url) >= URL_STRING_LEN) {
                *url_temp = '\0';
            } else if (*url_temp == '/' && *(url_temp + 1) == '\0') {
                *url_temp = '\0';
            }
            break;
        }
        
        if (url_end - *url >= URL_STRING_LEN) {
            *url_temp = '\0';
            break;
        }
    }

    return;
}

/* 正则表达式初始化 */
static char *url_regex_compile(apr_pool_t *pool, cli_url_t *url_node) 
{
    const char *errptr;
    int erroffset;

    errptr = NULL;        
    url_node->url_regex = msc_pregcomp(pool, (const char *)url_node->url,
        PCRE_DOTALL | PCRE_CASELESS | PCRE_DOLLAR_ENDONLY, &errptr, &erroffset);  
    if (url_node->url_regex == NULL) {
        return apr_psprintf(pool, "ModSecurity:Error compiling url pattern (offset %d): %s",
            erroffset, errptr);
    }

    return NULL;
}

/*
 * bwlist_add - 添加一个url结点到指定的名单
 * @pool: 所属内存池
 * @list: 名单
 * @url_type: url字符串类型(普通字符串或者正则表达式)
 * @url: url
 *
 * 返回值: 成功返回NULL,失败返回字符串
 */
static char *bwlist_add(apr_pool_t *pool, apr_hash_t *list, int url_type, const char *url)
{
    char *new_url;
    cli_url_t *cli_url;
    int rv;
    char *error_info;
    char key[URL_STRING_LEN + 6];
    char *urlkey;
    
    if (pool == NULL || url == NULL ||  strlen(url) == 0) {   
        return "ModSecurity: Failed to get the current args";
    }

    if ((new_url = apr_pstrdup(pool, url)) == NULL) {
        return FATAL_ERROR;
    }

    url_truncate(&new_url);
    if (strlen(new_url) == 0) {
        ap_log_error(APLOG_MARK, APLOG_WARNING, 0, NULL, 
            "ModSecurity:truncating %s is invalid", url);
        return NULL;
    }

    /* 构造关键字，使用url+type做为关键字 */
    snprintf(key, URL_STRING_LEN + 6, "%s+%d", new_url, url_type);

    if (apr_hash_get(list, key, strlen(key)) != NULL) {
        ap_log_error(APLOG_MARK, APLOG_WARNING, 0, NULL, "ModSecurity:%s %s has be in the list", 
            url_type?"plaintext":"pegularpxp",new_url);
        return NULL;
    }

    if (apr_hash_count(list) >= URL_BWLIST_ENTRY_NUM) {
        ap_log_error(APLOG_MARK, APLOG_WARNING, 0, NULL, "ModSecurity: The list is full");
        return NULL;
    }

    cli_url = (cli_url_t *)apr_pcalloc(pool, sizeof(cli_url_t));
    if (cli_url == NULL) {
        return FATAL_ERROR;
    }
    
    cli_url->url = new_url;
    cli_url->type = url_type;
    if (url_type == URL_TYPE_REGULEREXP) {
        error_info = url_regex_compile(pool, cli_url);  
        if (error_info != NULL) {
            return error_info;
        }
    } else {
        cli_url->url_regex = NULL;
    }

    cli_url->last_logtime = 0;
    cli_url->hitcount = 0;
    rv = apr_thread_mutex_create(&(cli_url->mutex), APR_THREAD_MUTEX_DEFAULT, pool);
    if (rv != APR_SUCCESS) {
        return FATAL_ERROR;
    }

    if ((urlkey = apr_pstrdup(pool, key)) == NULL) {
        apr_thread_mutex_destroy(cli_url->mutex);
        return FATAL_ERROR;
    }
    
    apr_hash_set(list, urlkey, strlen(urlkey), (const void *)cli_url);

    return NULL;
}

/*
 * bwlist_del - 删除指定的名单中的一个或所有结点
 * @pool: 内存池
 * @list: 需要删除的名单
 * @type: 需要删除的url类型
 * @url: 需要删除的结点，若为"all"则清除名单中所有结点
 *
 * 返回值: 成功返回NULL,失败返回字符串
 */
static char *bwlist_del(apr_pool_t *pool, apr_hash_t *list, int type, const char *url)
{   
    int url_len;
    char *new_url;
    char key[URL_STRING_LEN + 6];
    
    if (pool == NULL) {
        return "ModSecurity: Failed to get the current args.";
    }

    if (type == URL_TYPE_ALL) {
        /* 删除表中所有url */
        apr_hash_clear(list);
        return NULL; 
    }

    if (url == NULL || (url_len = strlen(url)) == 0) {
        return "ModSecurity: the url string can't be null.";        
    }
    
    if ((new_url = apr_pstrdup(pool, url)) == NULL) {
        return FATAL_ERROR;
    }

    url_truncate(&new_url);
    if (strlen(new_url) == 0) {
        ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, NULL, "ModSecurity: truncate %s invalid", url);
        return NULL;
    }    

    /* 构造关键字 */
    snprintf(key, URL_STRING_LEN + 6, "%s+%d", new_url, type);
    
    if (apr_hash_get(list, key, strlen(key)) == NULL) {
        ap_log_error(APLOG_MARK, APLOG_WARNING, 0, NULL, "ModSecurity:%s %s is not in the list",
            type?"plaintext":"regularexp", new_url);
        return NULL;
    }

    apr_hash_set(list, key, strlen(key), NULL);
    
    return NULL;
}

/**
 * url_bwlist_create - 创建url黑白名单
 * @pool: 内存池
 *
 * 返回值: 初始化成功返回APR_SUCCESS,失败返回-1
 */
int url_bwlist_create(apr_pool_t *pool)
{
    int i;
     
    if (pool == NULL) {
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, NULL, 
            "url_bwlist_create: Failed to get the current args");
        return -1;
    }   
    
    for (i = 0; i < URL_BWLIST_NUM; i++) {
        if ((url_bwlist[i] = apr_hash_make(pool)) == NULL) {
            ap_log_error(APLOG_MARK, APLOG_ERR, 0, NULL, 
                "url_bwlist_create: Failed to create url black white list");
            return -1;
        }
    }

    return APR_SUCCESS;
}

/*
 * dyn_ref_url_find - 从ref url链表中查找指定的url
 * @url: 需要查找的url结点
 *
 * 返回值: 指向url结点的指针
 */
static dyn_ref_url_t *dyn_ref_url_find(const char *url)
{
    dyn_ref_url_t *url_node;
    
    APR_RING_FOREACH(url_node, &dyn_url_blist_base->used_list, dyn_ref_url_s, link) {
        if (strcmp(url_node->ref_url, url) == 0) {
            return url_node;
        }
    }

    return NULL;
}

/*
 * dyn_ref_url_del - 从动态ref_url链表中删除指定的refferrer url
 * @node: 需要删除的url结点
 *
 * 返回值: 无
 */
static void dyn_ref_url_del(dyn_ref_url_t *url_node)
{
    APR_RING_REMOVE(url_node, link);
    APR_RING_INSERT_TAIL(&dyn_url_blist_base->free_list, url_node, dyn_ref_url_s, link);
    dyn_url_blist_base->free_num++;
}

/*
 * dyn_cli_ip_add - 将一个新结点插入到客户端动态ip链表
 * @new_ip: 需要插入的ip结点
 *
 * 返回值: 无
 */
static void dyn_ref_url_add(dyn_ref_url_t *new_ref_url)
{
    dyn_ref_url_t *url_node;
    apr_time_t new_url_endtime;

    new_url_endtime = new_ref_url->end_time;
    APR_RING_FOREACH(url_node, &dyn_url_blist_base->used_list, dyn_ref_url_s, link) {
        if (new_url_endtime < url_node->end_time) {   
            APR_RING_INSERT_BEFORE(url_node, new_ref_url, link);
            return;
        }
    }
   
    APR_RING_INSERT_TAIL(&dyn_url_blist_base->used_list, new_ref_url, dyn_ref_url_s, link);
}

/*
 * dyn_blist_del - 从referrer url动态黑名单中删除指定的url或所有url
 * @pool: 内存池
 * @ref_url: 需要删除的referrer url，取值为"all"时删除所有referrer url
 *
 * 返回值: 成功返回NULL,失败返回字符串
 */
static char *dyn_blist_del(apr_pool_t *pool, const char *ref_url)
{
    dyn_ref_url_t *url_node, *url_node_tmp;
    unsigned int url_len;
    char *new_url;
    
    if (pool == NULL || ref_url == NULL || (url_len = strlen(ref_url)) == 0) {
        return "ModSecurity: Failed to get the current args";
    }

    if ((new_url = apr_pstrdup(pool, ref_url)) == NULL) {
        return FATAL_ERROR;
    }

#if 0
    url_truncate(&new_url);
    if (strlen(new_url) == 0) {
        ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, NULL, "ModSecurity: truncate %s invalid", 
            ref_url);
        return NULL;
    }  
#endif

    apr_global_mutex_lock(dyn_url_blist_base->shm_mutex);
    if (strcmp(new_url, "all") == 0) {
        APR_RING_FOREACH_SAFE(url_node, url_node_tmp, &dyn_url_blist_base->used_list, dyn_ref_url_s, 
                link) {
            dyn_ref_url_del(url_node);
        }

        apr_global_mutex_unlock(dyn_url_blist_base->shm_mutex);
        return NULL;
    }
    
    url_node = dyn_ref_url_find(new_url);
    if (url_node != NULL) {
        dyn_ref_url_del(url_node);
    }
    apr_global_mutex_unlock(dyn_url_blist_base->shm_mutex);

    return NULL;
}

static dyn_ref_url_t *dyn_blist_match(char *url)
{
    char *url_end;
    char url_new[URL_STRING_LEN];
    dyn_ref_url_t *refurlnode;
    
    url_end = url;
    memset(url_new, 0, URL_STRING_LEN);
    while (1) {
        url_end = strchr(url_end + 1, '/');
        if (url_end == NULL) {
            snprintf(url_new, URL_STRING_LEN, "%s", url);
            refurlnode = dyn_ref_url_find(url_new);
            return refurlnode;
        }
        
        snprintf(url_new, url_end - url + 1, "%s", url);
        refurlnode = dyn_ref_url_find(url_new);
        if (refurlnode != NULL) {
            return refurlnode;
        }
    }
}

/*
 * url_dyn_blist_get - 获取动态url黑名单内容
 * @result: 返回数组
 *
 * 返回值: 无
 */
int url_dyn_blist_get(apr_array_header_t **result)
{
    dyn_ref_url_t *node;
    dyn_blist_show_str_t *url_info, **arr_node;
    apr_pool_t *pool;
    
    if (result == NULL || *result == NULL) {
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, NULL, 
            "url_dyn_blist_get: Failed to get the current args");
        return -1;
    }

    pool = (*result)->pool;
    apr_global_mutex_lock(dyn_url_blist_base->shm_mutex);
    APR_RING_FOREACH(node, &dyn_url_blist_base->used_list, dyn_ref_url_s, link) {   
        url_info = (dyn_blist_show_str_t *)apr_pcalloc(pool, sizeof(dyn_blist_show_str_t));
        if (url_info == NULL) {
            apr_global_mutex_unlock(dyn_url_blist_base->shm_mutex);
            return -1;
        }
        url_info->str = (char *)apr_pcalloc(pool, URL_STRING_LEN);
        if (url_info->str == NULL) {
            apr_global_mutex_unlock(dyn_url_blist_base->shm_mutex);
            return -1;
        }
        strcpy(url_info->str, node->ref_url);
        url_info->start_time = (char *)apr_pcalloc(pool, TIME_STRING_LEN);
        if (url_info->start_time == NULL) {
            apr_global_mutex_unlock(dyn_url_blist_base->shm_mutex);
            return -1;
        }
        apr_ctime(url_info->start_time, node->start_time);
        url_info->end_time = (char *)apr_pcalloc(pool, TIME_STRING_LEN);
        if (url_info->end_time == NULL) {
            apr_global_mutex_unlock(dyn_url_blist_base->shm_mutex);
            return -1;
        }
        apr_ctime(url_info->end_time, node->end_time);
        arr_node = (dyn_blist_show_str_t **)apr_array_push(*result);
        *arr_node = url_info;
    }
    apr_global_mutex_unlock(dyn_url_blist_base->shm_mutex);
    
    return APR_SUCCESS;
}

/**
 * url_dyn_blist_add - 添加一个url到动态referrer url黑名单
 * @ref_url: referrer url
 * 
 * 返回-1表示添加失败，返回APR_SUCCESS表示添加成功；
 */
int url_dyn_blist_add(char *ref_url) 
{
    void *excpt_url;
    dyn_ref_url_t *new_ref_url;
    unsigned int url_len; 
    char ref_key[URL_STRING_LEN + 6];

    if (ref_url == NULL || (url_len = strlen(ref_url)) == 0) {
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, NULL, 
            "url_dyn_blist_add: Failed to get the current args");
        return -1;
    }

    if (url_bwlist_stop) {
        return APR_SUCCESS;
    }

    ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, NULL, "ModSecurity: url dyn blist add (%s)", ref_url);
    url_truncate(&ref_url);
    if (strlen(ref_url) == 0) {  
        ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, NULL, "ModSecurity: truncate invalid");
        return URL_TRUNCATE_INVALID;
    }

    /* 构造关键字，使用url+type做为关键字 */
    snprintf(ref_key, URL_STRING_LEN + 6, "%s+%d", ref_url, URL_TYPE_PLAINTEXT);
    
    excpt_url = apr_hash_get(url_bwlist[URL_REF_BLIST_EXCPT], ref_key, strlen(ref_key));
    if (excpt_url != NULL) {
        ap_log_error(APLOG_MARK, APLOG_WARNING, 0, NULL, 
            "ModSecurity:%s has be in the url dyn excpt blist", ref_url);
        return URL_REF_IN_EXCPT;
    }

    apr_global_mutex_lock(dyn_url_blist_base->shm_mutex);
    if (dyn_url_blist_base->free_num == 0) {
        apr_global_mutex_unlock(dyn_url_blist_base->shm_mutex);
        ap_log_error(APLOG_MARK, APLOG_WARNING, 0, NULL, 
            "ModSecurity:url dyn blist has no free node");
        return URL_LIST_IS_FULL;
    }

    if (dyn_ref_url_find(ref_url) != NULL) {
        apr_global_mutex_unlock(dyn_url_blist_base->shm_mutex);
        ap_log_error(APLOG_MARK, APLOG_WARNING, 0, NULL, 
            "ModSecurity:%s has be in the url dyn blist", ref_url);
        return URL_HAS_IN_LIST;
    }

    /* 获得一个空闲结点 */
    new_ref_url = (dyn_ref_url_t *)APR_RING_FIRST(&dyn_url_blist_base->free_list);
    APR_RING_REMOVE(new_ref_url, link);
    dyn_url_blist_base->free_num--;
    
    memset(new_ref_url, 0, sizeof(dyn_ref_url_t));
    strcpy(new_ref_url->ref_url, ref_url);
    new_ref_url->start_time = apr_time_now();
    /* apr获取的时间单位为微秒 */
    new_ref_url->end_time = new_ref_url->start_time + (apr_time_t)BLIST_TIME_TO_USEC(url_timeout);
    dyn_ref_url_add(new_ref_url);
    apr_global_mutex_unlock(dyn_url_blist_base->shm_mutex);

    return APR_SUCCESS;
}

/*
 * dyn_timeout_url_find_and_del - 查找超时的动态ip并摘除
 * 参数: 无
 * 返回值: 无
 */
static void dyn_timeout_url_find_and_del(void)
{
    dyn_ref_url_t *node, *node_tmp;
    apr_time_t nowtime;
    
    nowtime = apr_time_now();
    apr_global_mutex_lock(dyn_url_blist_base->shm_mutex);
    APR_RING_FOREACH_SAFE(node, node_tmp, &dyn_url_blist_base->used_list, dyn_ref_url_s, link) {
        if (node->end_time <= nowtime) {
            dyn_ref_url_del(node);
        }
    }
    apr_global_mutex_unlock(dyn_url_blist_base->shm_mutex);
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
    dyn_ref_url_t *url_dyn_blist;
    
    url_dyn_blist = (dyn_ref_url_t *)((void *)dyn_url_blist_base + sizeof(dyn_url_blist_mg_t));
    for(i = 0; i < URL_DYN_BLIST_ENTRY_NUM; i++) {
         APR_RING_INSERT_TAIL(&dyn_url_blist_base->free_list, url_dyn_blist + i, dyn_ref_url_s, link);
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
    
    apr_shm_remove(URL_DYN_BLIST_FILENAME, pool);
    shm_size = URL_DYN_BLIST_ENTRY_NUM * sizeof(dyn_ref_url_t) + sizeof(dyn_url_blist_mg_t);
    status = apr_shm_create(&dyn_blist_shm, shm_size, URL_DYN_BLIST_FILENAME, pool);   
    if (status != APR_SUCCESS) {
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, NULL, "ModSecurity: Failed to create url_blist_shm");
        return -1;
    }

    dyn_url_blist_base = (dyn_url_blist_mg_t *)apr_shm_baseaddr_get(dyn_blist_shm);
    status = apr_global_mutex_create(&dyn_url_blist_base->shm_mutex, NULL, APR_LOCK_DEFAULT, pool);
    if (status != APR_SUCCESS) {
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, NULL, "ModSecurity: Failed to create url shm_mutex");
        return -1;
    }
    dyn_url_blist_base->free_num = URL_DYN_BLIST_ENTRY_NUM;
    APR_RING_INIT(&dyn_url_blist_base->free_list, dyn_ref_url_s, link);
    APR_RING_INIT(&dyn_url_blist_base->used_list, dyn_ref_url_s, link);
    dyn_blist_free_list_init();
    
    return APR_SUCCESS;
}

/**
 * url_dyn_blist_timer_destroy - 停止定时器线程
 * 无参数
 *
 * 返回值: 初始化成功返回OK,失败返回-1
 */
int url_dyn_blist_timer_destroy(void)
{
    int rv;
    
    if (dyn_url_blist_timer == NULL) {
        return OK;
    }

    /* 停止定时器线程 */
    rv = dyn_blist_timer_stop(dyn_url_blist_timer);
    if (rv != APR_SUCCESS) {
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, NULL, "stop url dynamic black list timer failed"); 
        return DECLINED;
    }
    
    dyn_url_blist_timer = NULL;

    return OK;
}

static apr_status_t url_dyn_blist_timer_create(apr_pool_t *pool)
{
    int rv;
    
    /* 创建定时器 */
    dyn_url_blist_timer = dyn_blist_timer_create(pool, dyn_timeout_url_find_and_del); 
    if (dyn_url_blist_timer == NULL) {
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, NULL, 
            "url_dyn_blist_create: Failed to create url timer");
        return -1;
    }

    /* 运行定时器线程 */
    rv = dyn_blist_timer_start(pool, dyn_url_blist_timer);
    if (rv != APR_SUCCESS) {
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, NULL, "start url timer thread fail"); 
        dyn_url_blist_timer = NULL;
        return -1;
    }    

    return APR_SUCCESS;
}

/**
 * url_dyn_blist_create - 创建动态url黑名单
 * @pool: 内存池
 *
 * 返回值: 成功返回APR_SUCCESS,失败返回-1
 */
int url_dyn_blist_create(apr_pool_t *pool)
{
    apr_pool_t *gpool;
        
    if (pool == NULL) {
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, NULL, 
            "url_dyn_blist_create: Failed to get the current args");
        return -1;
    }

    /* 获得全局内存池 */
    gpool = apr_pool_parent_get(pool);
    apr_pool_userdata_get((void **)&dyn_url_blist_base, "url-dyn-blist-init", gpool);
    
    if (dyn_url_blist_base == NULL) {
        /* 创建动态url黑名单 */
        if (dyn_blist_create(gpool) != APR_SUCCESS) {
            ap_log_error(APLOG_MARK, APLOG_ERR, 0, NULL, 
                "url_dyn_blist_create: Failed to create url dynamic black list");
            return -1;
        }
        apr_pool_userdata_set((const void *)dyn_url_blist_base, "url-dyn-blist-init", 
            apr_pool_cleanup_null, gpool);
        return APR_SUCCESS;
    }    

    /* 创建定时器线程，使用的是配置池，初始化的时候在第二次pre_config创建，之后重启都先销毁，再重新创建 */
    return url_dyn_blist_timer_create(pool);
}

static cli_url_t *_bwlist_match(apr_pool_t *pool, char *url, apr_hash_t *list)
{
    cli_url_t *urlnode;
    apr_hash_index_t *hi;
    char *my_error_msg;
    int rv;

    my_error_msg = NULL;
    for (hi = apr_hash_first(pool, list); hi; hi = apr_hash_next(hi)) {
        apr_hash_this(hi, NULL, NULL, (void **)&urlnode);
        if (urlnode == NULL) {
            continue;
        }
        if (urlnode->type == URL_TYPE_REGULEREXP) { 
            /* 正则匹配 */
            rv = msc_regexec(urlnode->url_regex, url, strlen(url), &my_error_msg);
            if (rv != PCRE_ERROR_NOMATCH) {
                return urlnode;
            }                   
        } else { 
            /* 普通匹配 */
            if (strcmp(urlnode->url, url) == 0) {
                return urlnode;
            }
        }
    }  
    
    return NULL;
}

static cli_url_t *bwlist_match(apr_pool_t *pool, char *url, apr_hash_t *list)
{
    char *url_end;
    char url_new[URL_STRING_LEN];
    cli_url_t *urlnode;

    url_end = url;
    memset(url_new, 0, URL_STRING_LEN);
    while (1) {
        url_end = strchr(url_end + 1, '/');
        if (url_end == NULL) {
            snprintf(url_new, URL_STRING_LEN, "%s", url);
            return _bwlist_match(pool, url_new, list);
        }
        snprintf(url_new, url_end - url + 1, "%s", url);
        urlnode = _bwlist_match(pool, url_new, list);
        if (urlnode != NULL) {
            return urlnode;
        }
    }
}

/**
 * url_bwlist_process - url黑白名单匹配处理
 * @msr: 事务处理上下文结构，从中可以获得url信息，并且可以记载黑白名单命中标记
 *
 * 返回值: 成功返回OK或者503,失败返回-1
 */
int url_bwlist_process(modsec_rec *msr)
{
    char *url, *referrer ;
    const char *refurl;
    cli_url_t *cliurl;
    dyn_ref_url_t *dynrefurl;
    apr_time_t now;
   
    if (msr == NULL) {
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, NULL, 
            "url_bwlist_process: Failed to get the current args");
        return -1;
    }
    
    /* 如果处于非检测模式，不匹配黑白名单 */
    if (msr->txcfg->is_enabled == MODSEC_DISABLED) {
        msr_log(msr, 1, "Current work-mode: detection-distable");
        return OK;
    }

    url = apr_pstrcat(msr->mp, msr->hostname, msr->request_uri, NULL);
    if (strlen(url) >= URL_STRING_LEN) {
        url_truncate(&url);                              
        if (strlen(url) == 0) {  
            ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, NULL, "ModSecurity: truncate %s%s invalid", 
                msr->hostname, msr->request_uri);
            return OK;
        }
    }
    
    now = apr_time_now();

    /* 匹配url黑名单 */
    cliurl = bwlist_match(msr->mp, url, url_bwlist[URL_BLIST]);
    if (cliurl != NULL) {
        apr_thread_mutex_lock(cliurl->mutex);
        cliurl->hitcount++;
        if ((now - cliurl->last_logtime) > BLIST_TIME_TO_USEC(1)) {
            msr->black_list_log = 1;
            msr->black_list_hitcount = cliurl->hitcount;
            cliurl->last_logtime = now;
            cliurl->hitcount = 0;
        }
        apr_thread_mutex_unlock(cliurl->mutex);
        msr->black_list_flag |= URL_BLIST_ATTACK;
#ifdef DEBUG_DBLOG
        if (msr->txcfg->attacklog_flag) {
            msc_record_attacklog(msr, NULL, NULL);
        }
#endif          
        ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, msr->r->server, "%s hit url black list",
            cliurl->url);
        if (msr->txcfg->is_enabled == MODSEC_DETECTION_ONLY) {
            msr_log(msr, 1, "Current work-mode: detection-only");
            return OK;
        }
        return HTTP_SERVICE_UNAVAILABLE;
    }

    /* 获取referrer url */
    refurl = apr_table_get(msr->r->headers_in, "Referer");
    if (refurl != NULL) {
        referrer = apr_pstrdup(msr->mp, refurl);
        url_truncate(&referrer);                              
        if (strlen(referrer) == 0) {  
            ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, NULL, "ModSecurity: truncate %s invalid", 
                refurl);
            return OK;
        }

        /* 匹配referrer url动态黑名单 */
        apr_global_mutex_lock(dyn_url_blist_base->shm_mutex);
        dynrefurl = dyn_blist_match(referrer);
        if (dynrefurl != NULL) {
            dynrefurl->hitcount++;
            if ((now - dynrefurl->last_logtime) > BLIST_TIME_TO_USEC(1)) {
                msr->black_list_log = 1;
                msr->black_list_hitcount = dynrefurl->hitcount;
                dynrefurl->last_logtime = now;
                dynrefurl->hitcount = 0;
            }
            ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, msr->r->server, 
                "%s hit dynamic referrer url black list", dynrefurl->ref_url);
            apr_global_mutex_unlock(dyn_url_blist_base->shm_mutex);
            msr->black_list_flag |= URL_BLIST_ATTACK;
#ifdef DEBUG_DBLOG
            if (msr->txcfg->attacklog_flag) {
                msc_record_attacklog(msr, NULL, NULL);
            }
#endif      
            if (msr->txcfg->is_enabled == MODSEC_DETECTION_ONLY) {
                msr_log(msr, 1, "Current work-mode: detection-only");
                return OK;
            }
        
            return HTTP_SERVICE_UNAVAILABLE;
        }
        apr_global_mutex_unlock(dyn_url_blist_base->shm_mutex);
    }  

    /* 匹配url白名单 */
    cliurl = bwlist_match(msr->mp, url, url_bwlist[URL_WLIST]);
    if (cliurl != NULL) {
        ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, msr->r->server, "%s hit url white list", 
            cliurl->url);
        msr->white_list = 1;
    }
    
    return OK;
}

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
const char *cmd_blist_url(cmd_parms *cmd, void *_dcfg, const char *action, const char *url_type,
             const char *url)
{
    int type;
    
    if (cmd == NULL || action == NULL) {
        return "ModSecurity: Failed to get the current args";
    }

    if (url_type == NULL) {
        return "ModSecurity: The rule is SecBListURL Add|Del PlainText/RegularExp/All url-string";
    }
        
    if (strcasecmp(action, URL_BWLIST_ADD) == 0) {
        /* 添加 */
        if (strcasecmp(url_type, "PlainText") == 0) {
            type = URL_TYPE_PLAINTEXT;
        } else if (strcasecmp(url_type, "RegularExp") == 0) {
            type = URL_TYPE_REGULEREXP;
        } else {
            return "ModSecurity: url-type string must be PlainText/RegularExp."; 
        }
        
        return bwlist_add(cmd->pool, url_bwlist[URL_BLIST], type, url);
    } else if (strcasecmp(action, URL_BWLIST_DEL) == 0) {
        /* 删除 */
        if (strcasecmp(url_type, "All") == 0) {
            type = -1;
        } else if (strcasecmp(url_type, "PlainText") == 0) {
            type = URL_TYPE_PLAINTEXT;
        } else if (strcasecmp(url_type, "RegularExp") == 0) {
            type = URL_TYPE_REGULEREXP;
        } else {
            return "ModSecurity: url-type string must be PlainText/RegularExp/All."; 
        }
        
        return bwlist_del(cmd->pool, url_bwlist[URL_BLIST], type, url);
    } else {
        return "ModSecurity: cmd_blist_url can't proccess the action.";
    }
}

/**
 * cmd_blist_dyn_ref_url_timeout - 动态ref url黑名单命令超时函数
 * @cmd: 和命令有关的参数结构指针
 * @dcfg: 配置结构
 * @strtimeout: 时间字符串
 *
 * 返回值: 成功返回NULL,失败返回字符串
 */
const char *cmd_blist_dyn_ref_url_timeout(cmd_parms *cmd, void *_dcfg, const char *strtimeout) 
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
    url_timeout = new_timeout;
    
    return NULL;
}

/**
 * cmd_blist_dyn_ref_url - Referrer URL黑名单命令函数
 * @cmd: 和命令有关的参数结构指针
 * @dcfg: 配置结构
 * @action: 命令动作
 * @ref_url: referrer url参数
 *
 * 返回值: 成功返回NULL,失败返回字符串
 */
const char *cmd_blist_dyn_ref_url(cmd_parms *cmd, void *_dcfg, const char *action, 
    const char *ref_url)
{     
    if (cmd == NULL || action == NULL) {
        return "ModSecurity: Failed to get the current args";
    }

    if (strcasecmp(action, URL_BWLIST_DEL) == 0) {
        return dyn_blist_del(cmd->pool, ref_url);
    } else {
        return "ModSecurity: cmd_blist_dyn_ref_url cann't proccess the action.";
    }
}

/**
 * cmd_blist_ref_url_except - 例外referrer url黑名单命令函数
 * @cmd: 和命令有关的参数结构指针
 * @dcfg: 配置结构
 * @action: 命令动作
 * @excpt_url: url参数
 *
 * 返回值: 成功返回NULL,失败返回字符串
 */
const char *cmd_blist_ref_url_except(cmd_parms *cmd, void *_dcfg, const char *action, 
    const char *excpt_url)
{
    char *msg_error;
    int type;
    
    if (cmd == NULL || action == NULL) {
        return "ModSecurity: Failed to get the current args";
    }

    /* url默认为普通字符串类型 */
    type = URL_TYPE_PLAINTEXT;
    if (strcasecmp(action, URL_BWLIST_ADD) == 0) {
        /* 添加 */
         msg_error = bwlist_add(cmd->pool, url_bwlist[URL_REF_BLIST_EXCPT], type, excpt_url);
        if (msg_error != NULL) {
            return msg_error;
        } 
        
        msg_error = dyn_blist_del(cmd->pool, excpt_url);
        return msg_error;
    } else if (strcasecmp(action, URL_BWLIST_DEL) == 0) {
        /* 删除 */
        if (strcasecmp(excpt_url, "All") == 0) {
            type = URL_TYPE_ALL;
        }
        
        return bwlist_del(cmd->pool, url_bwlist[URL_REF_BLIST_EXCPT], type, excpt_url);
    } else {
        return "ModSecurity: cmd_blist_ref_url_except cann't proccess the action";
    }
}

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
const char *cmd_wlist_url(cmd_parms *cmd, void *_dcfg, const char *action, const char *url_type,
            const char *url)
{
    int type;
        
    if (cmd == NULL || action == NULL) {
        return "ModSecurity: Failed to get the current args";
    }

    if (url_type == NULL) {
        return "ModSecurity: The rule is SecWListURL Add|Del PlainText/RegularExp/All url-string";
    }
        
    if (strcasecmp(action, URL_BWLIST_ADD) == 0) {
        /* 添加 */
        if (strcasecmp(url_type, "PlainText") == 0) {
            type = URL_TYPE_PLAINTEXT;
        } else if (strcasecmp(url_type, "RegularExp") == 0) {
            type = URL_TYPE_REGULEREXP;
        } else {
            return "ModSecurity: url-type string must be PlainText/RegularExp."; 
        }
        
        return bwlist_add(cmd->pool, url_bwlist[URL_WLIST], type, url);
    } else if (strcasecmp(action, URL_BWLIST_DEL) == 0) {
        /* 删除 */
        if (strcasecmp(url_type, "All") == 0) {
            type = URL_TYPE_ALL;
        } else if (strcasecmp(url_type, "PlainText") == 0) {
            type = URL_TYPE_PLAINTEXT;
        } else if (strcasecmp(url_type, "RegularExp") == 0) {
            type = URL_TYPE_REGULEREXP;
        } else {
            return "ModSecurity: url-type string must be PlainText/RegularExp/All."; 
        }

        return bwlist_del(cmd->pool, url_bwlist[URL_WLIST], type, url);
    } else {
        return "ModSecurity: cmd_wlist_url cann't proccess the action";
    }
}

/**
 * cmd_url_bwlist - url黑白名单开启或关闭函数
 * @cmd: 和命令有关的参数结构指针
 * @p1: url黑白名单开关，on/off
 *
 * 返回值: 成功返回NULL,失败返回字符串
 */
const char *cmd_url_bwlist(cmd_parms *cmd, void *_dcfg, const char *p1)
{   
    if (cmd == NULL || p1 == NULL) {
        return "ModSecurity: Failed to get the current args";
    }

    if (strcasecmp(p1, "On") == 0) {
        url_bwlist_stop = 0;
        return NULL;
    } else if (strcasecmp(p1, "Off") == 0) {
        url_bwlist_stop = 1;
        return NULL;
    } else {
        return (const char *)apr_psprintf(cmd->pool, "ModSecurity: Unrecognised parameter value "
            "for SecIPBWList: %s", p1);
    }
}

