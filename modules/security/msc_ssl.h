/*
 * $Id: msc_ssl.h 2786 2013-07-09 16:42:55 FreeWAF Development Team $
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

#ifndef _MSC_SSL_H_
#define _MSC_SSL_H_

#include "openssl/des.h"
#include "msc_parsers.h"
#include "modsecurity.h"

#define LEN_OF_KEY              24
#define LEN_OF_STEP             8


/**
 * get_3des_key:获取3des加密的密钥，长度24个字节
 * @msr:上下文结构体
 *
 * 返回值：失败返回NULL，成功返回key字符串
 */
extern unsigned char *get_3des_key(modsec_rec *msr);

/**
 * get_3des_vector:获取3des加密的明文向量，向量长度为8个字节
 * @msr:上下文结构体
 *
 * 返回值：失败返回NULL，成功返回vector字符串
 */
extern unsigned char *get_3des_vector(modsec_rec *msr);

/**
 * msc_tripleDes:3des加/解密
 * @mptmp:用于分配内存的内存池
 * @data:明文
 * @kkey:密钥
 * @iv:明文向量 
 * @decode_or_encode_flag:加密/解密开关
 *
 * 返回值：失败返回NULL，成功返回vector字符串
 */
extern unsigned char *msc_tripleDes(apr_pool_t *mptmp, const unsigned char *data,
                        const unsigned char *kkey, const unsigned char *iv, int decode_or_encode_flag);

#endif
