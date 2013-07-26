/*
 * $Id: pe_cli.c 2786 2013-07-09 16:42:55 FreeWAF Development Team $
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
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <fcntl.h>
#include <string.h>
#include <unistd.h>
#include "ap_config.h"
#include "httpd.h"
#include "http_main.h"
#include "http_log.h"
#include "cli_common.h"
#include "apr_pools.h"
#include "convert_rule.h"
#include "cparser.h"
#include "cparser_priv.h"
#include "cparser_token.h"
#include "global_root.h"
#include "cparser_show_tree.h"
#include "cparser_tree.h"
#include "pe_cli.h"

#define BUF_SIZE   4096

static const char *const cli_space_format[] = {"", "", " ", "  ", "   ", "    ", NULL};
cparser_t cli_parser;

static void printf_core(int flag, cparser_context_t *context, const char *format, va_list ap)
{
    char buf[BUF_SIZE] = {0x20};
    int pe_level;

    /* 2表示防护引擎模式到最顶层模式的层级 */
    pe_level = context->parser->root_level - 2;

    if (pe_level >= (sizeof(cli_space_format) / sizeof(cli_space_format[0]))) {
        printf("mode level has exceed.\n");
        return ;
    }

    strcat(buf, cli_space_format[pe_level]);
    vsnprintf(buf + pe_level, sizeof(buf) - pe_level, format, ap);
    if (flag) {
        cparser_printf(context, "%s", buf);
    } else {
        fprintf(context->parser->fp, "%s", buf);
    }
}

AP_DECLARE(void) cli_printf(cparser_context_t *context, const char *format, ...)
{
    va_list ap;

    va_start(ap, format);
    printf_core(1, context, format, ap);
    va_end(ap);
}

AP_DECLARE(void) cli_fprintf(cparser_context_t *context, const char *format, ...)
{
    va_list ap;

    va_start(ap, format);
    printf_core(0, context, format, ap);
    va_end(ap);
}

cparser_result_t cparser_cmd_enable(cparser_context_t *context)
{
    char prompt[CPARSER_MAX_PROMPT];
    char buf[COMMAND_LEN_MAX];

    if (context == NULL) {
        return CPARSER_NOT_OK;
    }
    
    if (context->parser->mode != CPARSER_MODE_CONFIG) {
        context->parser->root_level++;
        context->parser->root[context->parser->root_level] = context->parser->cur_node->children;
        cparser_walk(context->parser, cparser_running_conf_walker, NULL, NULL); 
        context->parser->root_level--;
        return CPARSER_OK;
    }

    snprintf(buf, COMMAND_LEN_MAX, "enable");
    admin_log_process(context, buf);
    snprintf(prompt, CPARSER_MAX_PROMPT, "%s#", g_cli_prompt);
    return cparser_submode_enter(context->parser, NULL, prompt);
}

cparser_result_t cparser_cmd_st_configure(cparser_context_t *context)
{
    char prompt[CPARSER_MAX_PROMPT];
    char buf[COMMAND_LEN_MAX];
    
    if (context == NULL) {
        return CPARSER_NOT_OK;
    }
    
    if (context->parser->mode != CPARSER_MODE_CONFIG) {
        context->parser->root_level++;
        context->parser->root[context->parser->root_level] = context->parser->cur_node->children;
        cparser_walk(context->parser, cparser_running_conf_walker, NULL, NULL); 
        context->parser->root_level--;
        return CPARSER_OK;
    }

    snprintf(buf, COMMAND_LEN_MAX, "configure");
    admin_log_process(context, buf);
    snprintf(prompt, CPARSER_MAX_PROMPT, "%s(config)#", g_cli_prompt);
    
    return cparser_submode_enter(context->parser, NULL, prompt);
}

/* clear log*/
cparser_result_t cparser_cmd_st_clear_log_log_type(cparser_context_t *context,
                    char **log_type_ptr)
{
    enum audit_flags log_type;
    char buf[COMMAND_LEN_MAX];

    if (context == NULL) {
        return CPARSER_NOT_OK;
    }

    if (context->parser->mode != CPARSER_MODE_CONFIG) {    
        return CPARSER_OK;
    } else {
        if (log_type_ptr == NULL || *log_type_ptr == NULL) {
            return CPARSER_NOT_OK;
        }
        
        log_type = ap_get_log_type(*log_type_ptr);
        switch (log_type) {
        case ACCESS_LOG:
            clear_accesslog_content();
            break;
        case ATTACK_LOG:   
            clear_attacklog_content();
            break;
        case ADMIN_LOG:
            clear_adminlog_content();
            break;
        case ALL_LOG:  
            clear_accesslog_content();
            clear_attacklog_content();
            clear_adminlog_content();
            break;
        default:
            break;
        }

        sprintf(buf, "clear log %s", *log_type_ptr);
        admin_log_process(context, buf);
        return CPARSER_OK;
    }
}

cparser_result_t cparser_cmd_st_write(cparser_context_t *context)
{
    FILE *fp;
    char buf[COMMAND_LEN_MAX];

    if (context == NULL) {
        return CPARSER_NOT_OK;
    }
    
    if (context->parser->mode != CPARSER_MODE_CONFIG) {
        return CPARSER_OK;
    }

    fp = fopen(context->parser->default_conf_file, "w");
    if (!fp) {
        cli_printf_info(context, "Fail to open %s.\n", context->parser->default_conf_file);
        return CPARSER_NOT_OK;
    }
    context->parser->fp = fp;

    cparser_write_cmd(context->parser);
    fclose(fp);

    snprintf(buf, COMMAND_LEN_MAX, "write");
    admin_log_process(context, buf);

    return CPARSER_OK;
}

cparser_result_t cparser_cmd_st_load(cparser_context_t *context)
{
    char buf[COMMAND_LEN_MAX];
    
    if (context == NULL) {
        return CPARSER_NOT_OK;
    }
    
    if (context->parser->mode != CPARSER_MODE_CONFIG) {
        return CPARSER_OK;
    }

    snprintf(buf, COMMAND_LEN_MAX, "load");
    admin_log_process(context, buf);
    return cparser_load_cmd(context->parser, context->parser->default_conf_file);
}

cparser_result_t cparser_cmd_show_running_config(cparser_context_t *context)
{    
    char buf[COMMAND_LEN_MAX];
    
    if (context == NULL) {
        return CPARSER_NOT_OK;
    }
    
    if (context->parser->mode != CPARSER_MODE_CONFIG) {        
        return CPARSER_OK;    
    }    

    snprintf(buf, COMMAND_LEN_MAX, "show running-config");
    admin_log_process(context, buf);
    return cparser_running_conf_cmd(context->parser);
}

/**
 * cli_thread -  cli线程
 * @param arg: NULL
 *
 * cli线程
 *
 * @returns
 *     失败: NULL
 */
AP_DECLARE(void *) ap_cli_thread(apr_thread_t *thd, void * dummy)
{
    char *config_file;
    int debug = 0;
    cli_thread_starter *cts = dummy;
    int cli_io_type = IO_SOCKET_UNIX;
    apr_pool_t *p;
    p = cts->pool;

    config_file = ap_server_root_relative(p, "conf/cli.conf");

    memset(&cli_parser, 0, sizeof(cli_parser));

    /* 挂show树到全局命令树中 */
    cparser_global_add_tree(&cparser_show_root);
    /* 挂全局命令树到主树中 */
    cparser_hang_global_tree(&cparser_root);

    cli_parser.cfg.root = &cparser_root;
    /* 命令辅助键（自动补充完整命令） */
    cli_parser.cfg.ch_complete = '\t';
    /*
     * Instead of making sure the terminal setting of the target and
     * the host are the same. ch_erase and ch_del both are treated
     * as backspace.
     */

    /* 定义删除键 */
    cli_parser.cfg.ch_erase = '\b';
    cli_parser.cfg.ch_del = 127;
    /* 定义帮助键 */
    cli_parser.cfg.ch_help = '?';
    /* cli parser测试专用 */
    cli_parser.cfg.flags = (debug ? CPARSER_FLAGS_DEBUG : 0);
    snprintf(cli_parser.cfg.prompt, CPARSER_MAX_PROMPT, "%s>", g_cli_prompt);
    /* 定义保存配置信息的默认文件 */
    strcpy(cli_parser.default_conf_file, config_file);
    /* 定义调试信息输出终端 */
    cli_parser.cfg.fd = STDOUT_FILENO;
    cli_parser.mode = 0;
    cli_parser.fp = NULL;
    
    if (PE_FOREGROUND_RUN && cli_io_type == IO_TERM) {
        /* IO_TERM 只支持前端运行 */
        cli_parser.cfg.io_type = cli_io_type;
    } else if (cli_io_type == IO_SOCKET_UNIX) {
        cli_parser.cfg.io_type = cli_io_type;
        /* 定义io类型为unixdomain通信时所用的套接字路径 */
        cli_parser.cfg.su_path = "/tmp/pe.socket";
        /* 定义io类型为unixdomain时，在cparser中写管理日志所用的接口函数 */
        cli_parser.cfg.admin_log_fn = admin_log_process;
    } else {
        ap_log_error(APLOG_MARK, APLOG_STARTUP |APLOG_ERR, 0, NULL, "Cli io type error!");
        return NULL;
    }

    /* 定义操作系统相关的IO接口 */
    cparser_io_config(&cli_parser);
    
    /* 初始化解析器 */
    if (CPARSER_OK != cparser_init(&cli_parser.cfg, &cli_parser)) {
        printf("Fail to initialize parser.\n");
        return NULL;
    }

    if (config_file && access(config_file, F_OK) == 0) {
        (void)cparser_load_cmd(&cli_parser, config_file);
    }
    
    /* 启动解析器 */
    fflush(stdin);
    cparser_run(&cli_parser);
    printf("cli done\n");
    
    return NULL;
}
