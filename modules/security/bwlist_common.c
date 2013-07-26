/*
 * $Id: bwlist_common.c 2786 2013-07-09 16:42:55 FreeWAF Development Team $
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
 
#include "apr_thread_cond.h"
#include "apr_pools.h"
#include "apr_thread_proc.h"
#include "apr_time.h"
#include "apr_errno.h"
#include "modsecurity.h"
#include "bwlist_common.h"

/*
 * dyn_blist_timer_destroy - 销毁定时器
 * @data: 数据
 *
 * 返回值: 返回0
 */
apr_status_t dyn_blist_timer_destroy(void *data) 
{
    blist_timer_t *timer;

    if (data == NULL) {
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, NULL, "destroy timer, args fail");
        return -1;
    }
    
    timer = (blist_timer_t *)data;
    sem_destroy(&timer->sem_timeout);

    return APR_SUCCESS;
}

/*
 * dyn_blist_timer_cb - 定时器线程回调函数
 * @thd: 线程结构
 * @data: 数据
 *
 * 返回值: 无符号指针
 */
static void *dyn_blist_timer_cb(apr_thread_t *thd, void *data)
{
    blist_timer_t *timer;
    int ret;
    struct timeval now;
    struct timespec timespec;
    
    timer = (blist_timer_t *)data;
    
    while (1) {
        gettimeofday(&now, NULL);
        timespec.tv_sec = now.tv_sec + BLIST_ONE_MINUTE * 60;
        timespec.tv_nsec = now.tv_usec * 1000; 
        ret = sem_timedwait(&timer->sem_timeout, &timespec); 
        if (ret == 0) {
            if (timer->terminated == 1) {
                ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, NULL, "timer thread terminated seccess!");
                break;
            } else {
                ap_log_error(APLOG_MARK, APLOG_ERR, 0, NULL, "timer thread terminated fail!");
            }
        } else if (ret == -1 && errno == ETIMEDOUT) {
            (timer->fn)();
        } else if (ret == -1 && errno == EINTR) {
            ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, NULL, "timer thread, get EINTR!");
        } else {
            ap_log_error(APLOG_MARK, APLOG_WARNING, 0, NULL, 
                "timer thread, errno(%d), %s!", errno, strerror(errno));
        }
    }
 
    return NULL;
}

/**
 * dyn_blist_timer_start - 开始运行一个线程定时器
 * @pool: 使用的池
 * @timer: 定时器结构指针
 *
 * 返回值: 成功返回APR_SUCCESS,失败返回-1
 */
apr_status_t dyn_blist_timer_start(apr_pool_t *pool, blist_timer_t *timer)
{ 
    if (pool == NULL || timer == NULL) {
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, NULL, "start timer thread, args fail");
        return -1;
    }
    
    /* 创建定时器线程 */
    return apr_thread_create(&timer->thread, NULL, dyn_blist_timer_cb, (void *)timer, pool);
}

/**
 * dyn_blist_timer_stop - 停止一个线程定时器
 * @timer: 定时器结构指针
 *
 * 返回值: 成功返回APR_SUCCESS,失败返回-1
 */
apr_status_t dyn_blist_timer_stop(blist_timer_t *timer)
{
    apr_status_t retvalue;
    int rv;
    
    if (timer == NULL) {
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, NULL, "stop timer thread, args fail");
        return -1;
    }

    timer->terminated = 1;
    rv = sem_post(&timer->sem_timeout);
    if (rv == -1) {
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, NULL, 
            "stop timer thread, sem_post fail,errno(%d), %s", errno, strerror(errno));
        return -1;    
    }
    
    rv = apr_thread_join(&retvalue, timer->thread);
    if (rv != APR_SUCCESS) {
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, NULL, "stop timer thread, apr_thread_join fail");
        return -1;
    }

    return APR_SUCCESS;
}

/**
 * dyn_blist_timer_create - 创建一个线程定时器
 * @pool: 所属内存池
 * @fn: 线程执行函数
 *
 * 返回值: 成功返回定时器结构指针,失败返回NULL
 */
blist_timer_t *dyn_blist_timer_create(apr_pool_t *pool, fn_dyn_blist_t fn)
{
    blist_timer_t *timer;
    int rv;

    if (pool == NULL || fn == NULL) {
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, NULL, "create timer thread, args fail");
        return NULL;
    }
    
    timer = (blist_timer_t *)apr_pcalloc(pool, sizeof(blist_timer_t));
    if (timer == NULL) {
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, NULL, "create timer thread, apr_pcalloc fail");
        return NULL;
    }

    memset(timer, 0, sizeof(blist_timer_t));
    timer->pool = pool;
    timer->fn = fn;
    timer->terminated = 0;

    rv = sem_init(&timer->sem_timeout, 1, 0);
    if (rv == -1) {
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, NULL, 
            "create timer thread, sem_init failed!errno(%d),%s", errno, strerror(errno));
        return NULL;
    }

    apr_pool_cleanup_register(pool, (const void *)timer, dyn_blist_timer_destroy, 
        apr_pool_cleanup_null);
    
    return timer;
}

