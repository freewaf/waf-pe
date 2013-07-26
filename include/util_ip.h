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
 * @file  util_ip.h
 * @brief Apache ip location and isp search
 *
 * @defgroup APACHE_CORE_IP search functions
 * @ingroup  APACHE_CORE
 * @{
 */

#ifndef APACHE_UTIL_IP_H
#define APACHE_UTIL_IP_H

#include "apr.h"
#include "httpd.h"

#ifdef __cplusplus
extern "C" {
#endif

AP_DECLARE(ip_location_t *) ap_ip_load_location(apr_pool_t *p, const char *dir_name); 

AP_DECLARE(void) ap_ip_unload_location(ip_location_t *location); 

AP_DECLARE(void) ap_ip_get_country(ip_location_t *location, char *ip, char *country, int len); 

AP_DECLARE(void) ap_ip_get_province(ip_location_t *location, char *ip, char *province, int len); 

AP_DECLARE(void) ap_ip_get_city(ip_location_t *location, char *ip, char *city, int len); 

AP_DECLARE(void) ap_ip_get_isp(ip_location_t *location, char *ip, char *isp, int len); 

#ifdef __cplusplus
}
#endif

#endif  /* !APACHE_UTIL_IP_H */
/** @} */

