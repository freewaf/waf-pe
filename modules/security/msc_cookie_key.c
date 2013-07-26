/*
 * $Id: msc_cookie_key.c 2786 2013-07-09 16:42:55 FreeWAF Development Team $
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

 
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "apr_errno.h"
#include "apr_shm.h"
#include "apr_file_io.h"
#include "msc_cookie_key.h"

char cookie_key_set[COOKIE_KEY_CHAR_NUM] = {
    '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 
    'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 
    'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T', 
    'U', 'V', 'W', 'X', 'Y', 'Z', 'a', 'b', 'c', 'd',
    'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 
    'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x',
    'y', 'z'
};

key_shm_t *cookie_key_shm_base;

static char *get_path(char *file_name, apr_pool_t *pool)
{
    char *fname;

    fname = ap_server_root_relative(pool, file_name);
    if (!fname) {

        return NULL;
    }
    
    return fname;
}


static void make_key(char *key, int keylen)
{ 
    int i, randcount;
    
    srand((unsigned int)(time(NULL)));
    for(i = 0; i < keylen; i++) {
        randcount = rand() % COOKIE_KEY_CHAR_NUM;  /* 生成一个[0-61]之间的随机数 */
        *(key + i) = cookie_key_set[randcount]; 
    }
}

static int read_from_file(apr_pool_t *pool, char *key, long *expire)
{
    apr_file_t *key_file;
    char timestr[COOKIE_KEY_TIMELEN];
    apr_size_t len;
    int ret;
    long now;
    char *filename;

    filename = get_path(COOKIE_KEY_PATHNAME, pool);
    if (filename == NULL) {
        ap_log_error(APLOG_MARK,APLOG_DEBUG, 0, NULL, "Invalid process file path");
        return -1;
    }
    
    ret = apr_file_open(&key_file, filename, APR_READ | APR_CREATE, APR_OS_DEFAULT, pool);
    if (ret != APR_SUCCESS) {
        ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, NULL, "Failed to open cookie key file:%s.",
            filename);
        return -1;
    } 

    len = COOKIE_KEY_LEN;
    ret = apr_file_read(key_file, key, &len);
    if (ret != APR_SUCCESS || len < COOKIE_KEY_LEN) {
        apr_file_close(key_file);
        return -1;
    }

    len = COOKIE_KEY_TIMELEN;
    memset(timestr, 0, COOKIE_KEY_TIMELEN);
    ret = apr_file_read(key_file, timestr, &len);
    if (ret != APR_SUCCESS) {
        apr_file_close(key_file);
        return -1;
    }
    
    timestr[len] = '\0';
    *expire =  strtol(timestr, NULL, 0);
    now = time(NULL);
    if (*expire < now) {
        apr_file_close(key_file);
        return -1;
    }

    apr_file_close(key_file);
    
    return 0;
}

static int write_to_file(apr_pool_t *pool, char *key, long expire)
{
    apr_file_t *key_file;
    int ret;
    char *filename;

    filename = get_path(COOKIE_KEY_PATHNAME, pool);
    if (filename == NULL) {
        ap_log_error(APLOG_MARK,APLOG_DEBUG, 0, NULL, "Invalid process file path");
        return -1;
    }    
    
    ret = apr_file_open(&key_file, filename, APR_WRITE, APR_OS_DEFAULT, pool);
    if (ret != APR_SUCCESS) {
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, NULL, "Failed to open cookie key file:%s.",
                    filename);
        return -1;
    } 
    
    apr_file_printf(key_file, "%s%ld", key, expire);
    
    return 0;
}

/**
 * create_cookie_key_shm - 创建存放cookie关键字的共享内存
 * @pool: 内存池
 *
 * 成功返回0，失败返回-1
 */
int create_cookie_key_shm(apr_pool_t *pool)
{
    int shm_size;
    apr_shm_t *cookie_key_shm;
    int ret;
     
    apr_shm_remove(COOKIE_KEY_SHMPATH, pool);
    shm_size = sizeof(key_shm_t);
    ret = apr_shm_create(&cookie_key_shm, shm_size, COOKIE_KEY_SHMPATH, pool);
    if (ret != APR_SUCCESS) {
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, NULL, "Failed to create cookie key shm.");
        return -1;
    }

    cookie_key_shm_base = (key_shm_t *)apr_shm_baseaddr_get(cookie_key_shm);
    memset(cookie_key_shm_base, 0, shm_size);
    ret = apr_global_mutex_create(&(cookie_key_shm_base->shm_mutex), NULL, APR_LOCK_DEFAULT, pool);
    if (ret != APR_SUCCESS) {
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, NULL, "Failed to create cookie key shm mutex.");
        return -1;
    }
    
    ret = read_from_file(pool, cookie_key_shm_base->key, &(cookie_key_shm_base->expire));
    if (ret == -1) {
        goto new_a_key;
    }
    cookie_key_shm_base->file_is_synchronize = 1;

    return 0;
    
new_a_key:
    make_key(cookie_key_shm_base->key, COOKIE_KEY_LEN);
    cookie_key_shm_base->expire = time(NULL) + COOKIE_KEY_TIMEOUT;
    ret = write_to_file(pool, cookie_key_shm_base->key, cookie_key_shm_base->expire);
    if (ret == 0) {
        cookie_key_shm_base->file_is_synchronize = 1;
    }
    
    return 0;
}

/**
 * get_cookie_key - 获得一个150个字符的cookie关键字
 * @msr - 事务处理上下文
 *
 * 成功返回关键字，失败返回NULL
 */
char *get_cookie_key(modsec_rec *msr)
{
    long now;
    char *key;
    int ret;
   
    key = (char *)apr_pcalloc(msr->mp, COOKIE_KEY_LEN + 1);
    if (key == NULL) {
        return NULL;
    }

    now = time(NULL);
    apr_global_mutex_lock(cookie_key_shm_base->shm_mutex);
    if (cookie_key_shm_base->expire >= now) {
        memcpy(key, cookie_key_shm_base->key, COOKIE_KEY_LEN);
        if (!cookie_key_shm_base->file_is_synchronize) {
            ret = write_to_file(msr->mp, cookie_key_shm_base->key, cookie_key_shm_base->expire);
            if (ret == 0) {
                cookie_key_shm_base->file_is_synchronize = 1; 
            } else {
                msr_log(msr, 1, "Failed to write cookie key to KEY file.");          
            }
        }
        apr_global_mutex_unlock(cookie_key_shm_base->shm_mutex);
        return key;
    }

    /* key超时，重新创建key */
    make_key(cookie_key_shm_base->key, COOKIE_KEY_LEN);
    cookie_key_shm_base->expire = now + COOKIE_KEY_TIMEOUT;
    ret = write_to_file(msr->mp, cookie_key_shm_base->key, cookie_key_shm_base->expire);
    if (ret != 0) {
        cookie_key_shm_base->file_is_synchronize = 0;
        msr_log(msr, 1, "Failed to write cookie key to KEY file."); 
    }
    
    memcpy(key, cookie_key_shm_base->key, COOKIE_KEY_LEN);
    apr_global_mutex_unlock(cookie_key_shm_base->shm_mutex);
    
    return key; 
}

