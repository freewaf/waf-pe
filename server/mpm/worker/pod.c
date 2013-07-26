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

#include "pod.h"

#if APR_HAVE_UNISTD_H
#include <unistd.h>
#endif

AP_DECLARE(apr_status_t) ap_mpm_pod_open(apr_pool_t *p, ap_pod_t **pod)
{
    apr_status_t rv;

    *pod = apr_palloc(p, sizeof(**pod));
    rv = apr_file_pipe_create(&((*pod)->pod_in), &((*pod)->pod_out), p);
    if (rv != APR_SUCCESS) {
        return rv;
    }
/*
    apr_file_pipe_timeout_set((*pod)->pod_in, 0);
*/
    (*pod)->p = p;

    /* close these before exec. */
    apr_file_inherit_unset((*pod)->pod_in);
    apr_file_inherit_unset((*pod)->pod_out);

    return APR_SUCCESS;
}

AP_DECLARE(int) ap_mpm_pod_check(ap_pod_t *pod)
{
    char c;
    apr_os_file_t fd;
    int rc;

    /* we need to surface EINTR so we'll have to grab the
     * native file descriptor and do the OS read() ourselves
     */
    apr_os_file_get(&fd, pod->pod_in);

    rc = read(fd, &c, 1);
    if (rc == 1) {
        switch(c) {
        case RESTART_CHAR:
            return AP_RESTART;
        case GRACEFUL_CHAR:
            return AP_GRACEFUL;
        }
    }

    return AP_NORESTART;
}

AP_DECLARE(int) ap_mpm_pod_wait(ap_pod_t *pod)
{
    char c;
    apr_os_file_t fd;
    int rc;

    /* we need to surface EINTR so we'll have to grab the
     * native file descriptor and do the OS read() ourselves
     */
    apr_os_file_get(&fd, pod->pod_in);

    while (1) {
        rc = read(fd, &c, 1);
        if (rc == 1) {
            switch(c) {
            case CLI_CLEAR_OK_CHAR:
                return AP_CLI_CLEAR_OK;
            case PE_PRE_CONF_OK_CHAR:
                return AP_PE_PRE_CONF_OK;
            case CLI_CONF_FAIL_CHAR:
                return AP_CLI_CONF_FAIL;
            case CLI_CONF_OK_CHAR:
                return AP_CLI_CONF_OK;
            case PE_FORK_OK_CHAR:
                return AP_PE_FORK_OK;
            case PE_MAIN_LOOP_CHAR:
                return AP_PE_MAIN_LOOP_OK;
            default:
                return -1;
            }
        } else if (rc == -1 && errno == EINTR) {
            continue;
        } else {
            return -1;
        }
    }
}

AP_DECLARE(apr_status_t) ap_mpm_pod_close(ap_pod_t *pod)
{
    apr_status_t rv;

    rv = apr_file_close(pod->pod_out);
    if (rv != APR_SUCCESS) {
        return rv;
    }

    rv = apr_file_close(pod->pod_in);
    if (rv != APR_SUCCESS) {
        return rv;
    }
    return rv;
}

static apr_status_t pod_signal_internal(ap_pod_t *pod, int msg)
{
    apr_status_t rv;
    char msg_char;
    apr_size_t one = 1;

    switch (msg) {
    case AP_RESTART:
        msg_char = RESTART_CHAR;
        break;
    case AP_GRACEFUL:
        msg_char = GRACEFUL_CHAR;
        break;
    case AP_CLI_CLEAR_OK:
        msg_char = CLI_CLEAR_OK_CHAR;
        break;
    case AP_PE_PRE_CONF_OK:
        msg_char = PE_PRE_CONF_OK_CHAR;
        break;
    case AP_CLI_CONF_FAIL:
        msg_char = CLI_CONF_FAIL_CHAR;
        break;
    case AP_CLI_CONF_OK:
        msg_char = CLI_CONF_OK_CHAR;
        break;
    case AP_PE_FORK_OK:
        msg_char = PE_FORK_OK_CHAR;
        break;
    case AP_PE_MAIN_LOOP_OK:
        msg_char = PE_MAIN_LOOP_CHAR;
        break;
    default:
        return -1;
    }
    
    rv = apr_file_write(pod->pod_out, &msg_char, &one);
    if (rv != APR_SUCCESS) {
        ap_log_error(APLOG_MARK, APLOG_WARNING, rv, ap_server_conf,
                     "write pipe_of_death char(%c)", msg_char);
    }
    return rv;
}

AP_DECLARE(apr_status_t) ap_mpm_pod_signal(ap_pod_t *pod, int msg)
{
    return pod_signal_internal(pod, msg);
}

AP_DECLARE(void) ap_mpm_pod_killpg(ap_pod_t *pod, int num, int graceful)
{
    int i;
    apr_status_t rv = APR_SUCCESS;

    for (i = 0; i < num && rv == APR_SUCCESS; i++) {
        rv = pod_signal_internal(pod, graceful);
    }
}

