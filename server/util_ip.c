#define CORE_PRIVATE
#include <stdio.h>
#include <string.h>
#include <inttypes.h>
#include <sys/time.h>
#include <GeoIP.h>
#include <GeoIPCity.h>
#include "apr_thread_mutex.h"
#include "apr_strings.h"
#include "util_ip.h"
#include "http_log.h"
#include "http_config.h"

#define BE_32(x) ((((uint8_t*)(x))[0] << 24) | \
                  (((uint8_t*)(x))[1] << 16) | \
                  (((uint8_t*)(x))[2] << 8) | \
                  ((uint8_t*)(x))[3])

#define LE_32(x) ((((uint8_t*)(x))[3] << 24) | \
                  (((uint8_t*)(x))[2] << 16) | \
                  (((uint8_t*)(x))[1] << 8) | \
                  ((uint8_t*)(x))[0])

#define LE_24(x) ((((uint8_t*)(x))[2] << 16) | \
                  (((uint8_t*)(x))[1] << 8) | \
                  ((uint8_t*)(x))[0])

#define REDIRECT_TYPE_1 0x01
#define REDIRECT_TYPE_2 0x02

struct ip_location_s{
    FILE *isp_handle;
    GeoIP *city_handle;
    apr_thread_mutex_t *isp_mutex;
};
       
static uint32_t ip2long(char *ip) 
{
    uint32_t ip_long = 0;
    uint8_t ip_len = strlen(ip);
    uint32_t ip_sec = 0;
    int8_t ip_level = 3;
    uint8_t i,n;
    
    for (i = 0; i <= ip_len; i++) {
        if (i != ip_len && ip[i] != '.' && ip[i] < 48 || ip[i] > 57) {
            continue;
        }
        
        if (ip[i] == '.' || i == ip_len) {
            /* too many. */
            if (ip_level == -1) {
                return 0;
            }
            
            for (n = 0; n < ip_level; n++) {
                ip_sec *= 256;
            }
            
            ip_long += ip_sec;
            if (i == ip_len) {
                break;
            }
            ip_level--;
            ip_sec = 0;
        } else {
            /*char '0' == int 48*/
            ip_sec = ip_sec * 10 + (ip[i] - 48);
        }
    }
    
    return ip_long;
}

static uint32_t search_index(uint32_t ip, FILE *file_handle) 
{
    uint32_t index_ip;
    unsigned char head[8];
    unsigned char index_bytes[7];
    uint32_t index_start, index_end, index_mid;

    fread(head, 8, 1, file_handle);
    index_start = (uint32_t)LE_32(&head[0]);
    index_end = (uint32_t)LE_32(&head[4]);
     
    while (1) {
        if ((index_end - index_start) == 7) {
            break;
        }
        
        index_mid = index_end / 7 - index_start / 7;
        if (index_mid % 2 == 0) {
            index_mid = index_mid / 2;
        } else {
            index_mid = (index_mid + 1) / 2;
        }
        
        index_mid = index_start + index_mid * 7;
        fseek(file_handle, index_mid, SEEK_SET);
        fread(index_bytes, 7, 1, file_handle);
        index_ip = (uint32_t)LE_32(&index_bytes[0]);
        if (index_ip == ip) {
            break;
        } else if (index_ip < ip) {
            index_start = index_mid;
        } else {
            index_end = index_mid;
        }
    }
    
    if (index_ip > ip) {
        fseek(file_handle, index_start, SEEK_SET);
        fread(index_bytes, 7, 1, file_handle);
    }
    
    return (uint32_t)LE_24(&index_bytes[4]);
}

static int readOrJumpRead(char *location, int len, FILE *file_handle, uint32_t data_index) 
{
    unsigned char c;
    unsigned char data_index_bytes[3];
    uint32_t jump_data_index = 0;
    int tmp_len;
    
    if (data_index) {
        fseek(file_handle, data_index, SEEK_SET);
    }
    
    c = fgetc(file_handle);
    switch (c) {
    case REDIRECT_TYPE_2:
    case REDIRECT_TYPE_1:
        fread(data_index_bytes, 3, 1, file_handle);
        jump_data_index = LE_24(&data_index_bytes[0]);
        fseek(file_handle, jump_data_index, SEEK_SET);
        break;
    default:
        location[strlen(location)] = c;
        break;
    }
    
    while (c = fgetc(file_handle)) {
        tmp_len = strlen(location);
        if (tmp_len >= len - 1) {
            location[tmp_len] = '\0';
            break;
        }
        location[tmp_len] = c;
    }
    
    if (jump_data_index != 0) {
        fseek(file_handle, data_index + 4, SEEK_SET);
    }
    
    return 1;
}

static int is_cz88(char *str) 
{
    int i;
    int l = strlen(str) - 7;

    for (i=0; i<l; i++) {
        if (str[i] == 'C' 
            && str[i + 1] == 'Z'
            && str[i + 2] == '8'
            && str[i + 3] == '8'
            && str[i + 4] == '.'
            && str[i + 5] == 'N'
            && str[i + 6] == 'E'
            && str[i + 7] == 'T'
        ) {
            return 1;
        }
    }
    
    return 0;
}

int get_location_by_long(FILE *file_handle, uint32_t ip, char *country, int country_len, 
        char *area, int area_len) 
{
    unsigned char data_index_bytes[3];
    uint32_t data_index;
    uint32_t area_offset;
    unsigned char c;
    int len;

    fseek(file_handle, 0, SEEK_SET);
    data_index = search_index(ip, file_handle);
    
    fseek(file_handle, data_index + 4, SEEK_SET);
    switch (c = fgetc(file_handle)) {
    case REDIRECT_TYPE_1:
        fread(data_index_bytes, 3, 1, file_handle);
        data_index = LE_24(&data_index_bytes[0]);
        
        if (country) {
            readOrJumpRead(country, country_len, file_handle, data_index);
        }
        
        if (area) {
            readOrJumpRead(area, area_len, file_handle, 0);
        }
        break;
    case REDIRECT_TYPE_2:
        area_offset = data_index + 8;
        fread(data_index_bytes, 3, 1, file_handle);
        data_index = LE_24(&data_index_bytes[0]);
        fseek(file_handle, data_index, SEEK_SET);
        
        if (country) {
            while (c = fgetc(file_handle)) {
                len = strlen(country);
                if (len >= country_len - 1) {
                    country[len] = '\0';
                    break;
                }
                country[len] = c;
            }
        }
        
        if (area) {
            readOrJumpRead(area, area_len, file_handle, area_offset);
        }

        break;
    default:        
        /* 这个分支有bug，不同的数据库版本不一样 */
        break;
        
        if (country) {
            country[strlen(country)] = c;
            while (c = fgetc(file_handle)) {
                len = strlen(country);
                if (len >= country_len - 1) {
                    country[len] = '\0';
                    break;
                }
                country[len] = c;
            }
            country[strlen(country)] = '\0';
        }
        
        if (area) {
            while (c = fgetc(file_handle)) {
                len = strlen(area);
                if (len >= area_len - 1) {
                    area[len] = '\0';
                    break;
                }
                area[len] = c;
            }
            area[strlen(area)] = '\0';
        }
    }
    
    if (country && is_cz88(country)) {
        country[0] = '\0';
    }
    
    if (area && is_cz88(area)) {
        area[0] = '\0';
    }
    
    return 1;
} 

AP_DECLARE(ip_location_t *) ap_ip_load_location(apr_pool_t *p, const char *dir_name) 
{
    ip_location_t *location;
    char *file_path;
    char *dir_path;
    int rv;

    if (p == NULL || dir_name == NULL) {
        return NULL;
    }

    dir_path = ap_server_root_relative(p, dir_name);
    
    location = (ip_location_t *)malloc(sizeof(ip_location_t));
    if (!location) {
        return NULL;
    }
    
    file_path = apr_pstrcat(p, dir_path, "/GeoIsp.dat", NULL);
    location->isp_handle = fopen(file_path, "rb");
    if (!location->isp_handle) {
        free(location);
        return NULL;
    }

    file_path = apr_pstrcat(p, dir_path, "/GeoLiteCity.dat", NULL);
    location->city_handle = GeoIP_open(file_path, GEOIP_MEMORY_CACHE);
    if (!location->city_handle) {
        fclose(location->isp_handle);
        free(location);
        return NULL;
    }

    rv = apr_thread_mutex_create(&(location->isp_mutex), APR_THREAD_MUTEX_DEFAULT, p);
    if (rv != APR_SUCCESS) {
        fclose(location->isp_handle);
        GeoIP_delete(location->city_handle);
        free(location);
        return NULL;
    }

    return location;
}

AP_DECLARE(void) ap_ip_unload_location(ip_location_t *location) 
{
    if (location == NULL) {
        return;
    }
    
    GeoIP_delete(location->city_handle);
    fclose(location->isp_handle);
    apr_thread_mutex_destroy(location->isp_mutex);
    free(location);
}

AP_DECLARE(void) ap_ip_get_country(ip_location_t *location, char *ip, char *country, int len) 
{
    GeoIPRecord *gir;

    if (location == NULL || ip == NULL || country == NULL) {
        return;
    }

    gir = GeoIP_record_by_name(location->city_handle, ip);
    if (gir) {
        strncpy(country, ap_mk_geo_na(gir->country_code), len);
        GeoIPRecord_delete(gir);
    } else {
        strncpy(country, "LAN", len); 
    }
}

AP_DECLARE(void) ap_ip_get_province(ip_location_t *location, char *ip, char *province, int len) 
{
    GeoIPRecord *gir;

    if (location == NULL || ip == NULL || province == NULL) {
        return;
    }

    gir = GeoIP_record_by_name(location->city_handle, ip);
    if (gir) {
        strncpy(province, ap_mk_geo_na(GeoIP_region_name_by_code(gir->country_code, gir->region)), len); 
        GeoIPRecord_delete(gir);
    } else {
        strncpy(province, "LAN", len);    
    }
}

AP_DECLARE(void) ap_ip_get_city(ip_location_t *location, char *ip, char *city, int len) 
{
    GeoIPRecord *gir;

    if (location == NULL || ip == NULL || city == NULL) {
        return;
    }

    gir = GeoIP_record_by_name(location->city_handle, ip);
    if (gir) {
        strncpy(city, ap_mk_geo_na(gir->city), len);        
        GeoIPRecord_delete(gir);
    } else {
        strncpy(city, "LAN", len);  
    }
}

AP_DECLARE(void) ap_ip_get_isp(ip_location_t *location, char *ip, char *isp, int len) 
{
    char country[2048] = { 0 };

    if (location == NULL || ip == NULL || isp == NULL) {
        return;
    }

    apr_thread_mutex_lock(location->isp_mutex);
    get_location_by_long(location->isp_handle, ip2long(ip), country, 2048, isp, len);
    apr_thread_mutex_unlock(location->isp_mutex);
}

