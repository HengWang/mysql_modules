/*
 * Copyright (c) 2013, Heng Wang personal. All rights reserved.
 * 
 * Global exports header file.
 *
 * @Author:  Heng.Wang
 * @Date  :  12/24/2013
 * @Email :  wangheng.king@gmail.com
 *           king_wangheng@163.com
 * @Github:  https://github.com/HengWang/
 * @Blog  :  http://hengwang.blog.chinaunix.net
 * */

#ifndef __MYSQLD_PROTOCAL_H
#define __MYSQLD_PROTOCAL_H

#ifdef _WIN32
    /* mysql.h needs SOCKET defined */
    #include <winsock2.h>
#endif

#include <mysql.h>

#include "my_global_exports.h"
#include "network_packet.h"

/**
 * 4.0 is missing too many things for us to support it, so we have to error out.
 */
#if MYSQL_VERSION_ID < 41000
    #error You need at least MySQL 4.1 to compile this software. 
#endif
/**
 * 4.1 uses other defines
 *
 * this should be one step to get closer to backward-compatibility
 */
#if MYSQL_VERSION_ID < 50000
    #define COM_STMT_EXECUTE        COM_EXECUTE
    #define COM_STMT_PREPARE        COM_PREPARE
    #define COM_STMT_CLOSE          COM_CLOSE_STMT
    #define COM_STMT_SEND_LONG_DATA COM_LONG_DATA
    #define COM_STMT_RESET          COM_RESET_STMT
#endif

#define MYSQLD_PACKET_OK   (0)
#define MYSQLD_PACKET_RAW  (0xfa) /* used for proxy.response.type only */
#define MYSQLD_PACKET_NULL (0xfb) /* 0xfb */
                                  /* 0xfc */
                                  /* 0xfd */
#define MYSQLD_PACKET_EOF  (0xfe) /* 0xfe */
#define MYSQLD_PACKET_ERR  (0xff) /* 0xff */

#define PACKET_LEN_MAX     (0x00ffffff)

#define NET_HEADER_SIZE 

typedef enum {
	MYSQLD_LENENC_TYPE_INT,
	MYSQLD_LENENC_TYPE_NULL,
	MYSQLD_LENENC_TYPE_EOF,
	MYSQLD_LENENC_TYPE_ERR
} mysqld_lenenc_type;

MY_GLOBAL_API int mysqld_protocal_skip(network_packet *packet, size_t size);
MY_GLOBAL_API int mysqld_protocal_skip_network_header(network_packet *packet);

MY_GLOBAL_API int mysqld_protocal_get_int_len(network_packet *packet, unsigned long long *v, size_t size);

MY_GLOBAL_API int mysqld_protocal_get_int8(network_packet *packet, unsigned char *v);
MY_GLOBAL_API int mysqld_protocal_get_int16(network_packet *packet, unsigned short *v);
MY_GLOBAL_API int mysqld_protocal_get_int24(network_packet *packet, unsigned long *v);
MY_GLOBAL_API int mysqld_protocal_get_int32(network_packet *packet, unsigned long *v);
MY_GLOBAL_API int mysqld_protocal_get_int48(network_packet *packet, unsigned long long *v);
MY_GLOBAL_API int mysqld_protocal_get_int64(network_packet *packet, unsigned long long *v);

MY_GLOBAL_API int mysqld_protocal_peek_int_len(network_packet *packet, unsigned long long *v, size_t size);
MY_GLOBAL_API int mysqld_protocal_peek_int8(network_packet *packet, unsigned char *v);
MY_GLOBAL_API int mysqld_protocal_peek_int16(network_packet *packet, unsigned short *v);
MY_GLOBAL_API int mysqld_protocal_peek_int32(network_packet *packet, unsigned long *v);
MY_GLOBAL_API int mysqld_protocal_find_int8(network_packet *packet, unsigned char c, unsigned int *pos);

MY_GLOBAL_API int mysqld_protocal_append_int8(char *packet, unsigned char num);
MY_GLOBAL_API int mysqld_protocal_append_int16(char *packet, unsigned short num);
MY_GLOBAL_API int mysqld_protocal_append_int24(char *packet, unsigned long num);
MY_GLOBAL_API int mysqld_protocal_append_int32(char *packet, unsigned long num);
MY_GLOBAL_API int mysqld_protocal_append_int48(char *packet, unsigned long long num);
MY_GLOBAL_API int mysqld_protocal_append_int64(char *packet, unsigned long long num);


MY_GLOBAL_API int mysqld_protocal_get_lenenc_string(network_packet *packet, char **s, unsigned long long *_len);
MY_GLOBAL_API int mysqld_protocal_get_string_len(network_packet *packet, char **s, size_t len);
MY_GLOBAL_API int mysqld_protocal_get_string(network_packet *packet, char **s);

MY_GLOBAL_API int mysqld_protocal_get_lenenc_char(network_packet *packet, char *out);
MY_GLOBAL_API int mysqld_protocal_get_char_len(network_packet *packet, size_t len, char *out);
MY_GLOBAL_API int mysqld_protocal_get_char(network_packet *packet, char *out);

MY_GLOBAL_API int mysqld_protocal_peek_lenenc_type(network_packet *packet, mysqld_lenenc_type *type);
MY_GLOBAL_API int mysqld_protocal_get_lenenc_int(network_packet *packet, unsigned long long *v);

typedef MYSQL_FIELD field_def;
MY_GLOBAL_API field_def *mysqld_protocal_field_def_init(void);
MY_GLOBAL_API void mysqld_protocal_field_def_init(field_def *field_def);
MY_GLOBAL_API int mysqld_protocal_get_field_def(network_packet *packet, field_def *field, unsigned long capabilities);

typedef GPtrArray field_defs_t;
MY_GLOBAL_API field_defs_t *mysqld_protocal_field_defs_init(void);
MY_GLOBAL_API void mysqld_protocal_field_defs_uninit(field_defs_t *field_defs);

MY_GLOBAL_API unsigned long mysqld_protocal_get_packet_len(char *_header);
MY_GLOBAL_API unsigned char mysqld_protocal_get_packet_id(char *_header);
MY_GLOBAL_API int mysqld_protocal_append_packet_len(char *header, unsigned long len);
MY_GLOBAL_API int mysqld_protocal_append_packet_id(char *header, unsigned char id);
MY_GLOBAL_API int mysqld_protocal_set_packet_len(char *header, unsigned long len);
MY_GLOBAL_API int mysqld_protocal_set_packet_id(char *header, unsigned char id);

MY_GLOBAL_API int mysqld_protocal_append_lenenc_int(char *packet, unsigned long long len);
MY_GLOBAL_API int mysqld_protocal_append_lenenc_string_len(char *packet, const char *s, unsigned long long len);
MY_GLOBAL_API int mysqld_protocal_append_lenenc_string(char *packet, const char *s);

MY_GLOBAL_API int mysqld_protocal_password_hash(char *response,
		const char *password, size_t password_len);
MY_GLOBAL_API int mysqld_protocal_password_scramble(char *response,
		const char *challenge, size_t challenge_len,
		const char *hashed_password, size_t hashed_password_len);
MY_GLOBAL_API gboolean mysqld_protocal_password_check(
		const char *challenge, size_t challenge_len,
		const char *response, size_t response_len,
		const char *double_hashed, size_t double_hashed_len);
MY_GLOBAL_API int mysqld_protocal_password_unscramble(
		char *hashed_password,
		const char *challenge, size_t challenge_len,
		const char *response, size_t response_len,
		const char *double_hashed, size_t double_hashed_len);

#endif  //__MYSQLD_PROTOCAL_H
