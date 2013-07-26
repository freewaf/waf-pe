/*
 * $Id: msc_cookie_key.h 2786 2013-07-09 16:42:55 FreeWAF Development Team $
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
 
#ifndef _MSC_COOKIE_KEY_H_
#define _MSC_COOKIE_KEY_H_

#include "modsecurity.h"
#include "apr_global_mutex.h"

#define COOKIE_KEY_LEN       150
#define COOKIE_KEY_TIMEOUT   324000
#define COOKIE_KEY_PATHNAME  "data/KEY"
#define COOKIE_KEY_SHMPATH   "/tmp/signature_key_shm_txt"
#define COOKIE_KEY_CHAR_NUM  62
#define COOKIE_KEY_TIMELEN   25

typedef struct key_shm_s {
    apr_global_mutex_t *shm_mutex;
    char key[COOKIE_KEY_LEN];   /* 存放150个随机字符 */
    long  expire;          
    int file_is_synchronize;  
} key_shm_t;

/**
 * create_cookie_key_shm - 创建存放cookie关键字的共享内存
 * @pool: 内存池
 *
 * 成功返回0，失败返回-1
 */
extern int create_cookie_key_shm(apr_pool_t *pool);

/**
 * get_cookie_key - 获得一个150个字符的cookie关键字
 * @msr - 事务处理上下文
 *
 * 成功返回关键字，失败返回NULL
 */
extern char *get_cookie_key(modsec_rec *msr);

#endif  /*_MSC_COOKIE_KEY_H_ */

