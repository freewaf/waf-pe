/* Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/**
 * @file worker/pod.h
 * @brief Worker MPM Pipe of Death
 *
 * @addtogroup APACHE_MPM_WORKER
 * @{
 */

#include "apr.h"
#include "apr_strings.h"
#define APR_WANT_STRFUNC
#include "apr_want.h"

#include "httpd.h"
#include "http_config.h"
#include "http_log.h"
#include "http_main.h"
#include "mpm.h"
#include "mpm_common.h"
#include "ap_mpm.h"
#include "ap_listen.h"
#include "mpm_default.h"

#define RESTART_CHAR          '$'
#define GRACEFUL_CHAR         '!'
#define CLI_CLEAR_OK_CHAR     'a'
#define PE_PRE_CONF_OK_CHAR   'b'
#define CLI_CONF_FAIL_CHAR    'c'
#define CLI_CONF_OK_CHAR      'd'
#define PE_FORK_OK_CHAR       'e'
#define PE_MAIN_LOOP_CHAR     'f'

#define AP_RESTART            0
#define AP_GRACEFUL           1
#define AP_CLI_CLEAR_OK       2
#define AP_PE_PRE_CONF_OK     3
#define AP_CLI_CONF_FAIL      4
#define AP_CLI_CONF_OK        5
#define AP_PE_FORK_OK         6
#define AP_PE_MAIN_LOOP_OK    7

typedef struct ap_pod_t ap_pod_t;

struct ap_pod_t {
    apr_file_t *pod_in;
    apr_file_t *pod_out;
    apr_pool_t *p;
};

AP_DECLARE(apr_status_t) ap_mpm_pod_open(apr_pool_t *p, ap_pod_t **pod);
AP_DECLARE(int) ap_mpm_pod_check(ap_pod_t *pod);
AP_DECLARE(apr_status_t) ap_mpm_pod_close(ap_pod_t *pod);
AP_DECLARE(apr_status_t) ap_mpm_pod_signal(ap_pod_t *pod, int graceful);
AP_DECLARE(void) ap_mpm_pod_killpg(ap_pod_t *pod, int num, int graceful);
/** @} */
