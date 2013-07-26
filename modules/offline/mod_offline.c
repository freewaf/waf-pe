/*
 * $Id: mod_offline.c 2786 2013-07-09 16:42:55 FreeWAF Development Team $
 *
 * (C) 2013-2014 FreeWAF Development Team
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
#define CORE_PRIVATE
#include "mod_offline.h"
#include "apr_strings.h"
#include "apr_tables.h"
#include "apr_lib.h"
#include "apr_network_io.h"
#include "apr_buckets.h"
#include "http_core.h"
#include "http_connection.h"
#include "http_config.h"
#include "util_filter.h"
#include "mod_core.h"

#include <stdlib.h>
#include <string.h>

#include <fcntl.h>
#include <sys/ioctl.h>
#include <sys/select.h>
#include <linux/if.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>

#define MIPS_WAF_DEVICE 0

#if MIPS_WAF_DEVICE
#include "efmp_libpcap_api.h"
#endif

/* 创建的假的conn */
#define OFFLINE_FAKE_CONN "offline_fake_conn"

/* 默认的IO_BUFFER_SIZE */
#define OFFLINE_IO_BUFFER_SIZE 8192

/* 最大容忍INTERIM  数量*/
#define OFFLINE_MAX_INTERIM_RESPONSES 10

/* 网口名称 */
struct offline_net_device {
    char ethname[256];
};

/* 配置结构体 */
typedef struct offline_server_conf {
    /* 内存池指针 */
    apr_pool_t * pool;
    /* 网口名称 */
    apr_array_header_t * devices;
    /* 缓存队列报文数量上限 */
    int pkt_num;
    /* 报文内存容量，单位KB */
    int mem_limit;
    /* 单个连接单个方向总流量限制，单位KB */
    int max_recv_len;    
    /* 日志级别 */
    int log_level;
    /* 日志大小限制，单位KB */
    int log_limit;
    /* 读取响应的超时值，单位秒 */
    apr_interval_time_t recv_timeout;
    /* 用于记录打开的句柄 */
    int fd;
    /* 日志名称 */
    char log_name[512];
    /* 模块是否打开的开关 */
    int is_opened;
} offline_server_conf;

/* 声明该某块 */
module AP_MODULE_DECLARE_DATA offline_module;

/* 钩子定义 */
APR_IMPLEMENT_OPTIONAL_HOOK_RUN_ALL(offline, OFFLINE, int, create_req,
                                   (request_rec *r, request_rec *pr), (r, pr),
                                   OK, DECLINED)
                                   
APR_IMPLEMENT_OPTIONAL_HOOK_RUN_ALL(offline, OFFLINE, int, pre_connection,
                                   (conn_rec *c, void *csd), (c, csd),
                                   OK, DECLINED)


static void * create_offline_config(apr_pool_t *p, server_rec *s)
{
    offline_server_conf *ps = apr_pcalloc(p, sizeof(offline_server_conf));
    char *path;
            
    if ( !ps ) {
        return 0;
    }
    /* 初始化默认值 */
    ps->pool = p;
    /* 默认fatal */
    ps->log_level = 0;
    /* 默认1024MB */
    ps->log_limit = 1024 * 1024;
    /* 默认1MB */
    ps->max_recv_len = 1 * 1024;
    /* 默认512MB */
    ps->mem_limit = 512 * 1024;
    /* 默认 1000000个*/
    ps->pkt_num = 1000000;
    /* 默认60 秒 */
    ps->recv_timeout = 60000000;
    /* 申请数组*/
    ps->devices = apr_array_make(p, 1,  sizeof(struct offline_net_device *));
    if ( !ps->devices ) {
        return 0;
    }
    /* 初始化句柄 */
    ps->fd = 0;
    /* 日志名称 */
    path = ap_server_root_relative(p, "logs/pe_offline.log");
    snprintf(ps->log_name, 512, "%s", path);
    /* 开启开关 */
    ps->is_opened = 0;

    return ps;
}

static void * merge_offline_config(apr_pool_t *p, void *basev, void *overridesv)
{
    offline_server_conf *ps, *base, *overrides;
    
    ps = apr_pcalloc(p, sizeof(offline_server_conf));
    if ( !ps ) {
        return 0;
    }
    base = (offline_server_conf *) basev;
    overrides = (offline_server_conf *) overridesv;
    if ( !base || !overrides ) {
        return 0;
    } else {
        ps->pool = p;

        ps->log_level = overrides->log_level;
        ps->log_limit = overrides->log_limit;
        ps->max_recv_len = overrides->max_recv_len;
        ps->mem_limit = overrides->mem_limit;
        ps->pkt_num = base->pkt_num > overrides->pkt_num ? base->pkt_num : overrides->pkt_num;

        ps->recv_timeout = base->recv_timeout > overrides->recv_timeout ? base->recv_timeout : overrides->recv_timeout;
        ps->devices = apr_array_append(p, base->devices, overrides->devices);

        memset(ps->log_name, 0, sizeof(ps->log_name));
        strcpy(ps->log_name, overrides->log_name);

        ps->is_opened = overrides->is_opened;
    }
    
    return ps;
}

/* 获取过滤器中的Client Socket */
static apr_socket_t * offline_get_client_socket(request_rec *r)
{
    core_net_rec * net;
    struct ap_filter_t * current;

    if ( !r ) {
        return NULL;
    }
    if ( !r->input_filters ) {
        return NULL;
    }

    /* 遍历过滤器链表 */
    for ( current = r->input_filters; current != 0;  current = current->next ) {
        if ( ap_core_input_filter_handle == current->frec ) {
            net = current->ctx;
            if ( net != 0 && net->client_socket != 0 ) {
                return net->client_socket;
            }
        }
    }

    return NULL;
}

/* 创建伪造请求 */
static request_rec * offline_make_fake_request(conn_rec *c, request_rec *r)
{
    request_rec * rp = apr_pcalloc(r->pool, sizeof(*r));
    if ( !rp ) {
        return 0;
    }

    rp->pool = r->pool;
    rp->status = HTTP_OK;

    rp->headers_in = apr_table_make(r->pool, 50);
    rp->subprocess_env = apr_table_make(r->pool, 50);
    rp->headers_out = apr_table_make(r->pool, 50);
    rp->err_headers_out = apr_table_make(r->pool, 10);
    rp->notes = apr_table_make(r->pool, 10);

    rp->server = r->server;
    rp->request_time = r->request_time;
    rp->connection = c;
    rp->output_filters = c->output_filters;
    rp->input_filters = c->input_filters;
    rp->proto_output_filters = c->output_filters;
    rp->proto_input_filters = c->input_filters;

    rp->request_config = (ap_conf_vector_t *)ap_create_request_config(r->pool);
    offline_run_create_req(r, rp);

    return rp;
}

/* 获取一行 */
static apr_status_t offline_getline(apr_bucket_brigade * bb, char * s, int n, request_rec * r, int fold, int * writen)
{
    char *tmp_s = s;
    apr_status_t rv;
    apr_size_t len;

    rv = ap_rgetline(&tmp_s, n, &len, r, fold, bb);
    apr_brigade_cleanup(bb);

    if (rv == APR_SUCCESS) {
        *writen = (int) len;
    } else if (rv == APR_ENOSPC) {
        *writen = n;
    } else {
        *writen = -1;
    }

    return rv;
}

/* 连接关闭的处理 */
static void offline_backend_broke(request_rec *r, apr_bucket_brigade *brigade)
{
    apr_bucket *e;
    conn_rec *c = r->connection;

    r->no_cache = 1;
    if (r->main)
        r->main->no_cache = 1;

    /* 插入错误存储段和结束存储段，表示结束 */
    e = ap_bucket_error_create(HTTP_BAD_GATEWAY, NULL, c->pool, c->bucket_alloc);
    APR_BRIGADE_INSERT_TAIL(brigade, e);
    e = apr_bucket_eos_create(c->bucket_alloc);
    APR_BRIGADE_INSERT_TAIL(brigade, e);
}

/* 表项的添加 */
static int offline_addit_dammit(void *v, const char *key, const char *val)
{
    apr_table_addn(v, key, val);
    return 1;
}

/* 读取HTTP 头 */
static void offline_read_headers(request_rec *r, request_rec *rr
                                 , char *buffer, int size, conn_rec *c, int *pread_len)
{
    int len;
    char *value, *end;
    char field[MAX_STRING_LEN];

    /* 初始化50 个头的空间 */
    r->headers_out = apr_table_make(r->pool, 50);
    *pread_len = 0;

    /* 
    * 该循环结束的条件
    * 1. 读到一个空行
    * 2. 读取超时
    * 3. 读取的连接已经关闭
    * 4. 读取的其他错误
    */
    while ( (len = ap_getline(buffer, size, rr, 1)) > 0 ) {
        if ( !(value = strchr(buffer, ':')) ) {
            /* 找不到冒号的行直接忽略 */
            continue;
        }

        /* 找到冒号后的解析工作 */
        *value = '\0';
        ++value;
        while (apr_isspace(*value)) {
            ++value; /* 找到非空字符为止 */
        }
        /* 去除字符串末尾的空格 */
        for ( end = &value[strlen(value) - 1]; end > value && apr_isspace(*end); --end ) {
            *end = '\0';
        }

        /* 将解析出来的key-value对放入headers-out */
        apr_table_add(r->headers_out, buffer, value) ;
        
        /* 当该头过长时候的处理 */
        if (len >= size - 1) {
            while ((len = ap_getline(field, MAX_STRING_LEN, rr, 1)) >= MAX_STRING_LEN - 1) {
                ;
            }
            if (len == 0) /* time to exit the larger loop as well */
                break;
        }
    }
}

static apr_status_t offline_buckets_lifetime_transform(request_rec *r, apr_bucket_brigade *from,
                                    apr_bucket_brigade *to)
{
    apr_bucket *e;
    apr_bucket *new;
    const char *data;
    apr_size_t bytes;
    apr_status_t rv = APR_SUCCESS;

    apr_brigade_cleanup(to);
    for (e = APR_BRIGADE_FIRST(from);
         e != APR_BRIGADE_SENTINEL(from);
         e = APR_BUCKET_NEXT(e)) {
        if (!APR_BUCKET_IS_METADATA(e)) {
            apr_bucket_read(e, &data, &bytes, APR_BLOCK_READ);
            new = apr_bucket_transient_create(data, bytes, r->connection->bucket_alloc);
            APR_BRIGADE_INSERT_TAIL(to, new);
        }
        else if (APR_BUCKET_IS_FLUSH(e)) {
            new = apr_bucket_flush_create(r->connection->bucket_alloc);
            APR_BRIGADE_INSERT_TAIL(to, new);
        }
        else if (APR_BUCKET_IS_EOS(e)) {
            new = apr_bucket_eos_create(r->connection->bucket_alloc);
            APR_BRIGADE_INSERT_TAIL(to, new);
        }
        else {
            ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r,
                          "offline: Unhandled bucket type of type %s in"
                          " offline_buckets_lifetime_transform", e->type->name);
            rv = APR_EGENERAL;
        }
    }
    return rv;
}

static apr_status_t offline_http_process_response(apr_pool_t * p, request_rec *r, conn_rec * origin, offline_server_conf * psf) 
{
    conn_rec * c = r->connection;
    char buffer[HUGE_STRING_LEN];
    const char * buf;
    char keepchar;
    request_rec * rp;
    apr_bucket * e;
    apr_bucket_brigade *bb, *tmp_bb;
    apr_bucket_brigade *pass_bb;
    int len, backasswards;
    apr_socket_t * client_socket;

    /* 是否读到了1xx 类似的响应状态行 */
    int interim_response = 0; 

    int pread_len = 0;
    apr_table_t * save_table;
    int backend_broke = 0;
    const char * te = NULL;
    int offline_status = OK;
    const char * offline_status_line = NULL;

    pass_bb = apr_brigade_create(p, c->bucket_alloc);
    tmp_bb = apr_brigade_create(p, c->bucket_alloc);

    /* 创建伪造请求 */
    rp = offline_make_fake_request(origin, r);
    if ( !rp ) {
        return APR_EGENERAL;
    }

    /* 设置请求种类 */
    rp->offlinereq = OFFLINEREQ_RESPONSE;

    /* 获取响应并且将响应往过滤器链后面传 */
    bb = apr_brigade_create(p, c->bucket_alloc);
    do {
        apr_status_t rc;
        apr_brigade_cleanup(bb);

        rc = offline_getline(tmp_bb, buffer, sizeof(buffer), rp, 0, &len);

        if (r->proxy_response_time == 0) {
            r->proxy_response_time = apr_time_now();
        }
        
        if ( len == 0 ) {
            ap_log_rerror(APLOG_MARK, APLOG_DEBUG, rc, r, "offline: error reading double CRLF, rc(%d), len(%d)", rc, len);
            /* 处理可能存在的多余的 CRLF */
            rc = offline_getline(tmp_bb, buffer, sizeof(buffer), rp, 0, &len);
        }
        if ( len <= 0 ) {
            ap_log_rerror(APLOG_MARK, APLOG_DEBUG, rc, r, "offline: error reading status line from remote server, rc(%d), len(%d)", rc, len);
            if ( APR_STATUS_IS_TIMEUP(rc) ) {
                /* 读取超时*/
                ap_log_rerror(APLOG_MARK, APLOG_NOTICE, rc, r, "read timeout");
            } else {
                /* 未超时，读取完毕 */
                apr_bucket *eos;
                ap_log_rerror(APLOG_MARK, APLOG_DEBUG, rc, r, "offline_backend_broke");
                offline_backend_broke(r, bb);

                e = (apr_bucket *)ap_bucket_eoc_create(c->bucket_alloc);
                eos = APR_BRIGADE_LAST(bb);
                while ((APR_BRIGADE_SENTINEL(bb) != eos) && !APR_BUCKET_IS_EOS(eos)) {
                    eos = APR_BUCKET_PREV(eos);
                }
                if (eos == APR_BRIGADE_SENTINEL(bb)) {
                    APR_BRIGADE_INSERT_TAIL(bb, e);
                } else {
                    APR_BUCKET_INSERT_BEFORE(eos, e);
                }
                ap_pass_brigade(r->output_filters, bb);
                return OK;
            }
            return HTTP_BAD_GATEWAY;
        }

        /* 响应状态行的处理*/
        if (apr_date_checkmask(buffer, "HTTP/#.# ###*")) {
            int major, minor;

            major = buffer[5] - '0';
            minor = buffer[7] - '0';

            if ( (major != 1) || (len >= sizeof(buffer) - 1) ) {
                /* HTTP 协议不为1的主版本，或者长度超过8192 */
                return HTTP_BAD_GATEWAY;
            }
            backasswards = 0;

            keepchar = buffer[12];
            buffer[12] = '\0';
            offline_status = atoi(&buffer[9]);

            if (keepchar != '\0') {
                buffer[12] = keepchar;
            } else {
                /* 
                 * RFC 2616 要求状态行以空格结束，
                 * 但是 ap_rgetline_core 可能将其删掉，
                 * 故这里补上。
                 */
                buffer[12] = ' ';
                buffer[13] = '\0';
            }
            offline_status_line = apr_pstrdup(p, &buffer[9]);

            /* 状态行的处理 */
            r->status = offline_status;
            r->status_line = offline_status_line;

            /* 解析头部到r->headers_out，包含对Set-Cookie 的处理 */
            save_table = apr_table_make(r->pool, 1);
            apr_table_do(offline_addit_dammit, save_table, r->headers_out, "Set-Cookie", NULL);
            offline_read_headers(r, rp, buffer, sizeof(buffer), origin, &pread_len);
            if (r->headers_out == NULL) {
                r->headers_out = apr_table_make(r->pool, 1);
                r->status = HTTP_BAD_GATEWAY;
                r->status_line = "bad gateway";
                return r->status;
            }
            apr_table_do(offline_addit_dammit, save_table, r->headers_out, "Set-Cookie", NULL);
            if (!apr_is_empty_table(save_table)) {
                apr_table_unset(r->headers_out, "Set-Cookie");
                r->headers_out = apr_table_overlay(r->pool, r->headers_out, save_table);
            }

            /* 头中同时包含"Transfer-Encoding" 和 "Content-Length"，认为是有问题的 */
            if (apr_table_get(r->headers_out, "Transfer-Encoding")
                && apr_table_get(r->headers_out, "Content-Length")) {
                    /* 如果上述两者同时存在，忽略"Content-Length" */
                    apr_table_unset(r->headers_out, "Content-Length");
            }

            /* 获取 TE */
            te = apr_table_get(r->headers_out, "Transfer-Encoding");

            /* 设置"Content-Type" */
            if ((buf = apr_table_get(r->headers_out, "Content-Type"))) {
                ap_set_content_type(r, apr_pstrdup(p, buf));
            }
            /* 给伪造请求增加HTTP_IN 输入过滤器 */
            if (!ap_is_HTTP_INFO(offline_status)) {
                ap_add_input_filter("HTTP_IN", NULL, rp, origin);
            }

            /* 如果HTTP版本小于1.1，就直接取消keepalive设置 */
            if ((major < 1) || (minor < 1)) {
                origin->keepalive = AP_CONN_CLOSE;
            }
        } else {
            /* 0.9 版本的响应 */
            backasswards = 1;
            r->status = 200;
            r->status_line = "200 OK";
        }

        if ( ap_is_HTTP_INFO(offline_status) ) {
            interim_response++;
        } else {
            interim_response = 0;
        }

        if ( interim_response ) {
            const char *policy = apr_table_get(r->subprocess_env, "offline-interim-response");
            ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, "offline: HTTP: received interim %d response", r->status);
            if (!policy || !strcasecmp(policy, "RFC")) {
                ap_send_interim_response(r, 1);
            } else if (strcasecmp(policy, "Suppress")) {
                ap_log_rerror(APLOG_MARK, APLOG_WARNING, 0, r, "undefined offline interim response policy");
            }
        }
        r->sent_bodyct = 1;

        /* 需要有体的时候才发送体 */
        if ( !r->header_only && !interim_response && offline_status != HTTP_NO_CONTENT && offline_status != HTTP_NOT_MODIFIED ) {
            /* 伪装成请求头 */
            rp->headers_in = apr_table_copy(r->pool, r->headers_out);
            /* 对"Transfer-Encoding" 的特殊处理 */
            if (te && !apr_table_get(rp->headers_in, "Transfer-Encoding")) {
                apr_table_add(rp->headers_in, "Transfer-Encoding", te);
            }
            apr_table_unset(r->headers_out,"Transfer-Encoding");

            /* 开始读体，并且传给输出过滤器 */
            if ( !ap_is_HTTP_ERROR(offline_status) || offline_status == HTTP_NOT_FOUND ) {
                
                /* 注意:   此处换成阻塞模式读取 */
                apr_read_type_e mode = APR_BLOCK_READ;
                int finish = FALSE;

                /* 获取客户端连接对象 */
                client_socket = offline_get_client_socket(r);
                if ( !client_socket ) {
                    return HTTP_INTERNAL_SERVER_ERROR;
                }

                do {
                    apr_status_t rv;
                    /* 保留旧超时值*/
                    apr_interval_time_t old_inter, new_inter = -1;
                    
                    apr_socket_timeout_get(client_socket, &old_inter);
                    if ( APR_BLOCK_READ == mode ) {
                        apr_socket_timeout_set(client_socket, new_inter);
                    }

                    rv = ap_get_brigade(rp->input_filters, bb, AP_MODE_READBYTES, mode, OFFLINE_IO_BUFFER_SIZE);
                    if ( APR_STATUS_IS_EAGAIN(rv) || (rv == APR_SUCCESS && APR_BRIGADE_EMPTY(bb))) {
                        /* 将响应刷新给客户端，并且切换至阻塞模式 */
                        e = apr_bucket_flush_create(c->bucket_alloc);
                        APR_BRIGADE_INSERT_TAIL(bb, e);
                        
                        if (ap_pass_brigade(r->output_filters, bb) || c->aborted) {
                            break;
                        }
                        apr_brigade_cleanup(bb);
                        mode = APR_BLOCK_READ;

                        /* 恢复原超时值 */
                        apr_socket_timeout_set(client_socket, old_inter);
                        continue;
                    }  else if (rv == APR_EOF) {
                    
                        /* 恢复原超时值 */
                        apr_socket_timeout_set(client_socket, old_inter);
                        break;
                    } else if (rv != APR_SUCCESS) {
                        ap_log_cerror(APLOG_MARK, APLOG_WARNING, rv, c, "offline: error reading response");
                        offline_backend_broke(r, bb);
                        ap_pass_brigade(r->output_filters, bb);
                        backend_broke = 1;

                        /* 恢复原超时值 */
                        apr_socket_timeout_set(client_socket, old_inter);
                        break;
                    }

                    /* 注意:   此处换成阻塞模式读取 */
                    mode = APR_BLOCK_READ;
                    if (APR_BRIGADE_EMPTY(bb)) {
                        apr_brigade_cleanup(bb);
                        break;
                    }

                    /* Switch the allocator lifetime of the buckets */
                    offline_buckets_lifetime_transform(r, bb, pass_bb);

                    if (APR_BUCKET_IS_EOS(APR_BRIGADE_LAST(bb))) {
                        finish = TRUE;
                    }
                    
                    if (ap_pass_brigade(r->output_filters, pass_bb) != APR_SUCCESS || c->aborted) {
                        finish = TRUE;
                    }

                    apr_brigade_cleanup(bb);
                    apr_brigade_cleanup(pass_bb);

                } while (!finish);
            }
        } else if ( !interim_response ) {
            /* 不需要体 */
            ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server, "offline: header only interim_response(%d), offline_status(%d)", interim_response, offline_status);

            /* 直接传入结束标记 */
            e = apr_bucket_eos_create(c->bucket_alloc);
            APR_BRIGADE_INSERT_TAIL(bb, e);

            ap_pass_brigade(r->output_filters, bb);
            apr_brigade_cleanup(bb);
        }
    } while ( interim_response && (interim_response < OFFLINE_MAX_INTERIM_RESPONSES) );

    /* If our connection with the client is to be aborted, return DONE. */
    if (c->aborted || backend_broke) {
        return DONE;
    }

    return OK;
}

/* 离线库初始化 */
static int offline_open_logs(apr_pool_t *pconf, apr_pool_t *plog, apr_pool_t *ptemp, server_rec *s)
{
    int ret, i = 0;
#if  MIPS_WAF_DEVICE
    struct interface_bind_info_s bind_info;
#endif

    /* 终止化库 */
    apr_socket_terminate();

    offline_server_conf *psf = ap_get_module_config(s->module_config, &offline_module);
    if ( !psf || !psf->is_opened ) {
        ap_log_error(APLOG_MARK, APLOG_NOTICE, 0, s, "offline_open_logs DECLINED");
        return DECLINED;
    }

#if MIPS_WAF_DEVICE
    /* 初始化mips-libpcap */
    psf->fd = open("/dev/wafdev", O_RDONLY);
    if ( psf->fd < 0 ) {
        ap_log_error(APLOG_MARK, APLOG_CRIT, 0, s, "open pf_packet device failed!");
        return DECLINED;
    }
#endif
   
    /* 初始化库 */
    ret = apr_socket_initialize(psf->pkt_num, psf->mem_limit, psf->max_recv_len, psf->log_level, psf->log_limit, psf->log_name);
    if ( ret == APR_EGENERAL ) {
        ap_log_error(APLOG_MARK, APLOG_CRIT, 0, s, "apr_socket_initialize failed!");
        return DECLINED;
    } else if ( ret > 0 ) {
        //apr_socket_start_listen();
    }
    
    /* 设置标志 */
    apr_socket_set_offline_mode(1/* open it */);
    apr_pollset_set_offline_mode(1/* open it */); 
    
#if MIPS_WAF_DEVICE
    for ( i = 0; i < psf->devices->nelts; ++i ) {
        memset(&bind_info, 0, sizeof(bind_info));
        bind_info.ifx = atoi(APR_ARRAY_IDX(psf->devices, i, struct offline_net_device *)->ethname);
        ret = ioctl(psf->fd, LIBPCAP_BIND_INTERFACE, &bind_info);
        if (ret < 0) {
            close(psf->fd);
            return DECLINED;
        }
        apr_socket_add_device(bind_info.net_device_name);
    }
#else
    for ( i = 0; i < psf->devices->nelts; ++i ) {
        apr_socket_add_device(APR_ARRAY_IDX(psf->devices, i, struct offline_net_device *)->ethname);
    }
#endif
    
    return OK;
}

/* 离线处理器 */
static int offline_handler(request_rec *r)
{
    int rc;
    apr_status_t rv;
    struct ap_filter_t * f;
    apr_interval_time_t current_timeout;
    apr_bucket_alloc_t *bucket_alloc;
    apr_socket_t * client_socket;
    conn_rec * fake_conn;
    offline_server_conf * psf;
    conn_rec * real_conn = r->connection;

    /* 获取配置信息 */
    psf = ap_get_module_config(r->server->module_config, &offline_module);
    if ( !psf  || !psf->is_opened ) {
        ap_log_rerror(APLOG_MARK, APLOG_NOTICE, 0, r, "offline_handler DECLINED");
        return DECLINED;
    }

    if (r->proxy_request_time == 0) {
        r->proxy_request_time = apr_time_now();
    }
    
    /* 获取客户端连接对象 */
    client_socket = offline_get_client_socket(r);
    if ( !client_socket ) {
        return HTTP_INTERNAL_SERVER_ERROR;
    }
        
    /* 创建存储段组内存分配器 */
    if ( !real_conn->offline_conn ) {
        bucket_alloc = apr_bucket_alloc_create(real_conn->pool);

        /* 创建新的连接对象 */
        fake_conn = (conn_rec *)ap_run_create_connection(real_conn->pool, r->server, client_socket, 0, NULL, bucket_alloc);
        if (!fake_conn) {
            return HTTP_INTERNAL_SERVER_ERROR;
        }
        real_conn->offline_conn = fake_conn;

        /* 连接预处理*/
        apr_socket_timeout_get(client_socket, &current_timeout);
        rc = offline_run_pre_connection(fake_conn, client_socket);
        if (rc != OK && rc != DONE) {
            return HTTP_INTERNAL_SERVER_ERROR;
        }
        apr_socket_timeout_set(client_socket, current_timeout);
    } else {
        fake_conn = real_conn->offline_conn;
    }

    /* 开始对伪造请求进行处理 */
    rv = offline_http_process_response(r->pool, r, fake_conn, psf);

    /* 摘掉HTTP_IN 过滤器 */
    if ( fake_conn->input_filters ) {
        for ( f = fake_conn->input_filters; f != 0;  f = f->next ) {
            if ( ap_http_input_filter_handle == f->frec ) {
                ap_remove_input_filter(f);
                break ;
            }
        }
    }

    return rv;
}


/* 实现其指令 */
static const char * offline_set_ptk_num(cmd_parms *parms, void *dummy, const char *arg)
{
    int rv;

    ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, parms->server, "offline_set_ptk_num");
    
    offline_server_conf *psf = ap_get_module_config(parms->server->module_config, &offline_module);
    if ( !psf ) {
        return "offline_set_ptk_num psf is null!";
    }

    rv = atoi(arg);
    if ( rv > psf->pkt_num ) {
        psf->pkt_num = rv;
    }
    return NULL;
}

static const char * offline_set_mem_limit(cmd_parms *parms, void *dummy, const char *arg)
{
    int rv;
    
    ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, parms->server, "offline_set_mem_limit");
    
    offline_server_conf *psf = ap_get_module_config(parms->server->module_config, &offline_module);
    if ( !psf ) {
        return "offline_set_mem_limit psf is null!";
    }

    rv = atoi(arg);
    if ( rv > psf->mem_limit ) {
        psf->mem_limit = rv;
    }
    return NULL;
}

static const char * offline_set_max_recv_len(cmd_parms *parms, void *dummy, const char *arg)
{
    int rv;
    
    ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, parms->server, "offline_set_max_recv_len");
    
    offline_server_conf *psf = ap_get_module_config(parms->server->module_config, &offline_module);
    if ( !psf ) {
        return "offline_set_max_recv_len psf is null!";
    }

    rv = atoi(arg);
    if ( rv > psf->max_recv_len ) {
        psf->max_recv_len = rv;
    }
    return NULL;
}

static const char * offline_set_log_level(cmd_parms *parms, void *dummy, const char *arg)
{
    int rv = 0;
    
    ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, parms->server, "offline_set_log_level");
    
    offline_server_conf *psf = ap_get_module_config(parms->server->module_config, &offline_module);
    if ( !psf ) {
        return "offline_set_log_level psf is null!";
    }

    if ( !strcmp(arg, "debug") ) {
        rv = 0;
    } else if ( !strcmp(arg, "info") ) {
        rv = 1;
    } else if ( !strcmp(arg, "warn") ) {
        rv = 2;
    } else if ( !strcmp(arg, "fatal") ) {
        rv = 3;
    } else if ( !strcmp(arg, "stop") ) {
        rv = 4;
    }
    
    if ( rv > psf->log_level ) {
        psf->log_level = rv;
    }
    return NULL;
}

static const char * offline_set_log_limit(cmd_parms *parms, void *dummy, const char *arg)
{
    int rv;
    
    ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, parms->server, "offline_set_log_limit");
    
    offline_server_conf *psf = ap_get_module_config(parms->server->module_config, &offline_module);
    if ( !psf ) {
        return "offline_set_log_limit psf is null!";
    }

    rv = atoi(arg);
    if ( rv > psf->log_limit ) {
        psf->log_limit = rv;
    }
    return NULL;
}

static const char * offline_set_recv_timeout(cmd_parms *parms, void *dummy, const char *arg)
{
    int rv;
    
    ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, parms->server, "offline_set_recv_timeout");
    
    offline_server_conf *psf = ap_get_module_config(parms->server->module_config, &offline_module);
    if ( !psf ) {
        return "offline_set_recv_timeout psf is null!";
    }

    rv = atoi(arg);
    if ( rv > psf->recv_timeout ) {
        psf->recv_timeout = rv * 1000000;
    }
    return NULL;
}

static const char * offline_set_ethname(cmd_parms *parms, void *dummy, const char *arg)
{
    int i, to_add;
    struct offline_net_device * device, *current;
    
    ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, parms->server, "offline_set_ethname");
    
    offline_server_conf *psf = ap_get_module_config(parms->server->module_config, &offline_module);
    if ( !psf ) {
        return "offline_set_ethname psf is null!";
    }

    if ( !psf->devices ) {
        psf->devices = apr_array_make(psf->pool, 1,  sizeof(struct offline_net_device *));
        if ( !psf->devices ) {
            return "offline_set_ethname make new devices failed!";
        }
    }

    to_add = 1;
    for ( i = 0; i < psf->devices->nelts; ++i ) {
        current = (struct offline_net_device *)(psf->devices->elts) + i;
        if ( 0 == strcmp(arg,  current->ethname) ) {
            to_add = 0; break; 
        }
    }
    if ( to_add ) {
        device = apr_pcalloc(psf->pool, sizeof(struct offline_net_device));
        if ( !device ) {
            return "apr_pcalloc failed!";
        }
        if ( !strncpy(device->ethname, arg, sizeof(device->ethname) - 1) ) {
            return "ethname must be set!";
        }
        *((struct offline_net_device **)apr_array_push(psf->devices)) = device;
    }
    
    return NULL;
}

static const char * offline_set_log_name(cmd_parms *parms, void *dummy, const char *arg)
{    
    ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, parms->server, "offline_set_log_name");
    
    offline_server_conf *psf = ap_get_module_config(parms->server->module_config, &offline_module);
    if ( !psf ) {
        return "offline_set_log_name psf is null!";
    }

   memset(psf->log_name, 0, sizeof(psf->log_name));
    if ( !strncpy(psf->log_name, arg, sizeof(psf->log_name) - 1) ) {
        return "log_name must be set!";
    }
    
    return NULL;
}

static const char * offline_set_engine(cmd_parms *parms, void *dummy, const char *arg)
{    
    ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, parms->server, "offline_set_engine");
    
    offline_server_conf *psf = ap_get_module_config(parms->server->module_config, &offline_module);
    if ( !psf ) {
        return "offline_set_engine psf is null!";
    }

    if ( !strcmp("on", arg) || !strcmp("On", arg)  || !strcmp("ON", arg) ) {
        psf->is_opened = 1;
    } else {
        psf->is_opened = 0;
    }
    
    return NULL;
}

/* 实现其指令 */
static const command_rec offline_cmds[] =
{
    AP_INIT_TAKE1("OfflinePktNum", offline_set_ptk_num, NULL, RSRC_CONF, "pkt num ceiling in a message queue"),
    AP_INIT_TAKE1("OfflineMemLimit", offline_set_mem_limit, NULL, RSRC_CONF, "self mem pool ceiling"),
    AP_INIT_TAKE1("OfflineMaxRecvLen", offline_set_max_recv_len, NULL, RSRC_CONF, "sum of the pkts size in 1 direction"),
    AP_INIT_TAKE1("OfflineLogLevel", offline_set_log_level, NULL, RSRC_CONF, "log level"),
    AP_INIT_TAKE1("OfflineLogLimit", offline_set_log_limit, NULL, RSRC_CONF, "log file size ceiling"),
    AP_INIT_TAKE1("OfflineRecvTimeOut", offline_set_recv_timeout, NULL, RSRC_CONF, "time to wait for recv response very time"),
    AP_INIT_TAKE1("OfflineEthName", offline_set_ethname, NULL, RSRC_CONF, "which eth should be monitored"),
    AP_INIT_TAKE1("OfflineLogName", offline_set_log_name, NULL, RSRC_CONF, "where log should be putted"),
    AP_INIT_TAKE1("OfflineEngine", offline_set_engine, NULL, RSRC_CONF, "engine on or off"),
    {NULL}
};

static void offline_register_hooks(apr_pool_t *p)
{
    ap_hook_open_logs(offline_open_logs, NULL, NULL, APR_HOOK_BLOODY_FIRST);
    ap_hook_handler(offline_handler, NULL, NULL, APR_HOOK_MIDDLE);
}

/* Dispatch list for API hooks */
module AP_MODULE_DECLARE_DATA offline_module = {
    STANDARD20_MODULE_STUFF, 
    NULL,
    NULL,
    create_offline_config,
    merge_offline_config,
    offline_cmds,
    offline_register_hooks
};

