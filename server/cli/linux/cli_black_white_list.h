/*
 * $Id: cli_black_white_list.h 2786 2013-07-09 16:42:55 FreeWAF Development Team $
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
#define DYN_BLIST_DEFAULT_TIMEOUT      60

/* 该数据结构用来标识黑白名单的commit命令以及是否进入到模式中，用于show running-config */
typedef struct blackwhite_flag_t blackwhite_flag_t;
struct blackwhite_flag_t {
    int ipblack_flag;                   /* 用来标识是否进入到ip黑名单模式 */                   
    int ipwhite_flag;                   /* 用来标识是否进入到ip白名单模式 */
    int urlblack_flag;                  /* 用来标识是否进入到URL白名单模式 */
    int urlwhite_flag;                  /* 用来标识是否进入到URL黑名单模式 */
    int ipblack_commit_flag;            /* 用来标识是否在ip黑名单模式下输入commit命令 */        
    int ipwhite_commit_flag;            /* 用来标识是否在ip白名单模式下输入commit命令 */
    int urlblack_commit_flag;           /* 用来标识是否在url白名单模式下输入commit命令 */
    int urlwhite_commit_flag;           /* 用来标识是否在url黑名单模式下输入commit命令 */
};

