/*
 * $Id: msc_ssl.c 2786 2013-07-09 16:42:55 FreeWAF Development Team $
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
 
#include "msc_cookie_key.h"
#include "msc_util.h"
#include "msc_ssl.h"

/**
 * get_3des_key:获取3des加密的密钥，长度24个字节
 * @msr:上下文结构体
 *
 * 返回值：失败返回NULL，成功返回key字符串
 */
unsigned char *get_3des_key(modsec_rec *msr)
{
    unsigned char *key;
    
    if (msr == NULL) {
        return NULL;
    }
    
    /*先取key产生器的前25字节*/
    key = (unsigned char *)apr_pmemdup(msr->mp, (void *)get_cookie_key(msr), 25);
    if (key == NULL) {
        return NULL;
    }
    /*第25位设置字符串结束符，返回24个字节的key*/
    key[24] = 0;
    
    return key;
}

/**
 * get_3des_vector:获取3des加密的明文向量，向量长度为8个字节
 * @msr:上下文结构体
 *
 * 返回值：失败返回NULL，成功返回vector字符串
 */
unsigned char *get_3des_vector(modsec_rec *msr)
{

    unsigned char* vector;
    
    if (msr == NULL) {
        return NULL;
    }
    
    /*先取key产生器的第25位到第33位*/
    vector = (unsigned char *)apr_pmemdup(msr->mp, (void *)get_cookie_key(msr) + 24, 9);
    if (vector == NULL) {
        return NULL;
    }
    /*第9位设置字符串结束符，返回8个字节的向量*/
    vector[8] = 0;
    
    return vector;
}

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
unsigned char *msc_tripleDes(apr_pool_t *mptmp, const unsigned char *data,
                const unsigned char *kkey, const unsigned char *iv, int decode_or_encode_flag)
{   
    int data_rest;
    int data_len;
    int count, i;
    unsigned char ch;

    unsigned char *tmp;
    unsigned char *data_real;
    unsigned char *src; /* 补齐后的明文 */
    unsigned char *dst; /* 解密后的明文 */
    int len; 
    
    unsigned char in[LEN_OF_STEP];
    unsigned char out[LEN_OF_STEP];

    int key_len;
    unsigned char key[LEN_OF_KEY]; /* 补齐后的密钥 */
    unsigned char block_key[LEN_OF_STEP + 1];
    DES_key_schedule ks,ks2,ks3;
    
    /* 入参检查 */
    if (mptmp == NULL || data == NULL || kkey == NULL || iv == NULL) {
        return NULL;
    }
    if (decode_or_encode_flag != DES_ENCRYPT && decode_or_encode_flag != DES_DECRYPT) {
        return NULL;
    }

    /* 构造补齐后的密钥 */
    key_len = strlen((char *)kkey);
    memcpy(key, (char *)kkey, (key_len < LEN_OF_KEY)?key_len:LEN_OF_KEY);
    if (key_len < LEN_OF_KEY) {
        memset(key + key_len, 0x00, LEN_OF_KEY - key_len);
    }

    /* 拷贝一份原始数据 */
    data_len = strlen((char *)data);
    data_real = apr_pmemdup(mptmp, data, data_len + 1);    
    
    /* 加密/解密前处理 */
    ch = '\0';
    len = 0;
    data_rest = 0;
    if (decode_or_encode_flag == DES_ENCRYPT) {
        data_real = (unsigned char *)apr_pstrcat(mptmp, (char *)data_real, "|", (char *)iv, NULL);
        
        /* 分析补齐明文所需空间及补齐填充数据 */
        data_len = strlen((char *)data_real);
        data_rest = data_len % LEN_OF_STEP;
        if (data_rest != 0) {
            len = data_len + (LEN_OF_STEP - data_rest);
            ch = LEN_OF_STEP - data_rest;
        } else {
            len = data_len;
        }
        
    } else {
        /* 解密前要将16进制字符串转换成字节流 */
        data_len = hex2bytes_inplace_3des(data_real, data_len);
        len = data_len;
    }

    src = (unsigned char *)apr_palloc(mptmp, len + 1);
    dst = (unsigned char *)apr_palloc(mptmp, len + 1);
    if (src != NULL && dst != NULL) {

        /* 构造补齐后的加密内容 */
        memset(src, 0, len + 1);
        memcpy(src, data_real, data_len);
        
        if (data_rest != 0) {
            memset(src + data_len, ch, LEN_OF_STEP - data_rest);
        }        
        
        /* 密钥置换 */
        memset(block_key, 0, sizeof(block_key));
        memcpy(block_key, key + 0, LEN_OF_STEP);
        DES_set_key_unchecked((const_DES_cblock *)block_key, &ks);
        memcpy(block_key, key + LEN_OF_STEP, LEN_OF_STEP);
        DES_set_key_unchecked((const_DES_cblock *)block_key, &ks2);
        memcpy(block_key, key + LEN_OF_STEP * 2, LEN_OF_STEP);
        DES_set_key_unchecked((const_DES_cblock *)block_key, &ks3);

        /* 循环加密/解密，每8字节一次 */
        count = len / LEN_OF_STEP;
        for (i = 0; i < count; i++) {
            memset(in, 0, LEN_OF_STEP);
            memset(out, 0, LEN_OF_STEP);
            memcpy(in, src + LEN_OF_STEP * i, LEN_OF_STEP);

            DES_ecb3_encrypt((const_DES_cblock *)in, (DES_cblock *)out, &ks, &ks2, &ks3, decode_or_encode_flag);
            /* 将解密的内容拷贝到解密后的明文 */
            memcpy(dst + LEN_OF_STEP * i, out, LEN_OF_STEP);
        }
        *(dst + len) = 0; 
        
        if (decode_or_encode_flag == DES_DECRYPT) {
        /* 解密需要检验明文后面的向量，最后去除向量 */
            tmp = (unsigned char *)strrchr((const char *)dst, '|');
            if (tmp != NULL) {
                *tmp++ = 0;
                if (strncasecmp((const char *)tmp, (const char *)iv, strlen((char *)iv)) == 0) {
                    return dst;
                }
            }
        } else {
        /* 加密需要将密文编码成16进制字符串 */
            return (unsigned char *)bytes2hex(mptmp, dst, len);
        }
        
    }
    
    return NULL;
}