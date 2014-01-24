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

#ifndef __MYSQLD_NETWORK_PACKET_H
#define __MYSQLD_NETWORK_PACKET_H

#include <glib.h>

#include "my_global_exports.h"

#include "mysqld_protocal.h"
#include "mysqld_network.h"

/**
 * mid-level protocol 
 *
 * the MySQL protocal is split up in three layers:
 *
 * - low-level (encoding of fields in a packet)
 * - mid-level (encoding of packets)
 * - high-level (grouping packets into a sequence)
 */

typedef enum {
	MYSQLD_NETWORK_PROTOCOL_VERSION_PRE41,
	MYSQLD_NETWORK_PROTOCOL_VERSION_41
} mysqld_network_protocol_t;

/**
 * tracking the state of the response of a COM_QUERY packet
 */
typedef struct {
	enum {
		PARSE_COM_QUERY_INIT,
		PARSE_COM_QUERY_FIELD,
		PARSE_COM_QUERY_RESULT,
		PARSE_COM_QUERY_LOCAL_INFILE_DATA,
		PARSE_COM_QUERY_LOCAL_INFILE_RESULT
	} state;

	unsigned short server_status;
	unsigned short warning_count;
	unsigned long long affected_rows;
	unsigned long long insert_id;

	bool was_resultset;
	bool binary_encoded;

	unsigned long long rows;
	unsigned long long bytes;

	unsigned char  query_status;
} mysqld_network_com_query_result_t;

MY_GLOBAL_API mysqld_network_com_query_result_t *mysqld_network_com_query_result_init(void);
MY_GLOBAL_API void mysqld_network_com_query_result_uninit(mysqld_network_com_query_result_t *udata);
MY_GLOBAL_API int mysqld_network_com_query_result_track_state(network_packet *packet, mysqld_network_com_query_result_t *udata) G_GNUC_DEPRECATED;
MY_GLOBAL_API bool mysqld_network_com_query_result_is_load_data(mysqld_network_com_query_result_t *udata) G_GNUC_DEPRECATED;
MY_GLOBAL_API bool mysqld_network_com_query_result_is_local_infile(mysqld_network_com_query_result_t *udata);
MY_GLOBAL_API int mysqld_network_proto_get_com_query_result(network_packet *packet, mysqld_network_com_query_result_t *udata, bool use_binary_row_data);

/**
 * tracking the response of a COM_STMT_PREPARE command
 *
 * depending on the kind of statement that was prepare we will receive 0-2 EOF packets
 */
typedef struct {
	bool first_packet;
	gint     want_eofs;
} mysqld_network_com_stmt_prepare_result_t;

MY_GLOBAL_API mysqld_network_com_stmt_prepare_result_t *mysqld_network_com_stmt_prepare_result_new(void);
MY_GLOBAL_API void mysqld_network_com_stmt_prepare_result_free(mysqld_network_com_stmt_prepare_result_t *udata);
MY_GLOBAL_API int mysqld_network_proto_get_com_stmt_prepare_result(network_packet *packet, mysqld_network_com_stmt_prepare_result_t *udata);

/**
 * tracking the response of a COM_INIT_DB command
 *
 * we have to track the default internally can only accept it
 * if the server side OK'ed it
 */
typedef struct {
	GString *db_name;
} mysqld_network_com_init_db_result_t;

MY_GLOBAL_API mysqld_network_com_init_db_result_t *mysqld_network_com_init_db_result_new(void);
MY_GLOBAL_API void mysqld_network_com_init_db_result_free(mysqld_network_com_init_db_result_t *com_init_db);
MY_GLOBAL_API int mysqld_network_com_init_db_result_track_state(network_packet *packet, mysqld_network_com_init_db_result_t *udata);
MY_GLOBAL_API int mysqld_network_proto_get_com_init_db_result(network_packet *packet, 
		mysqld_network_com_init_db_result_t *udata,
		mysqld_network_con *con
		);

MY_GLOBAL_API int mysqld_network_proto_get_query_result(network_packet *packet, mysqld_network_con *con);
MY_GLOBAL_API int mysqld_network_con_command_states_init(mysqld_network_con *con, network_packet *packet);

MY_GLOBAL_API GList *mysqld_network_proto_get_fielddefs(GList *chunk, GPtrArray *fields);

typedef struct {
	unsigned long long affected_rows;
	unsigned long long insert_id;
	unsigned short server_status;
	unsigned short warnings;

	gchar *msg;
} mysqld_network_ok_packet_t;

MY_GLOBAL_API mysqld_network_ok_packet_t *mysqld_network_ok_packet_new(void);
MY_GLOBAL_API void mysqld_network_ok_packet_free(mysqld_network_ok_packet_t *udata);

MY_GLOBAL_API int mysqld_network_proto_get_ok_packet(network_packet *packet, mysqld_network_ok_packet_t *ok_packet);
MY_GLOBAL_API int mysqld_network_proto_append_ok_packet(GString *packet, mysqld_network_ok_packet_t *ok_packet);

typedef struct {
	GString *errmsg;
	GString *sqlstate;

	unsigned short errcode;
	mysqld_network_protocol_t version;
} mysqld_network_err_packet_t;

MY_GLOBAL_API mysqld_network_err_packet_t *mysqld_network_err_packet_new(void);
MY_GLOBAL_API mysqld_network_err_packet_t *mysqld_network_err_packet_new_pre41(void);
MY_GLOBAL_API void mysqld_network_err_packet_free(mysqld_network_err_packet_t *udata);

MY_GLOBAL_API int mysqld_network_proto_get_err_packet(network_packet *packet, mysqld_network_err_packet_t *err_packet);
MY_GLOBAL_API int mysqld_network_proto_append_err_packet(GString *packet, mysqld_network_err_packet_t *err_packet);

typedef struct {
	unsigned short server_status;
	unsigned short warnings;
} mysqld_network_eof_packet_t;

MY_GLOBAL_API mysqld_network_eof_packet_t *mysqld_network_eof_packet_new(void);
MY_GLOBAL_API void mysqld_network_eof_packet_free(mysqld_network_eof_packet_t *udata);

MY_GLOBAL_API int mysqld_network_proto_get_eof_packet(network_packet *packet, mysqld_network_eof_packet_t *eof_packet);
MY_GLOBAL_API int mysqld_network_proto_append_eof_packet(GString *packet, mysqld_network_eof_packet_t *eof_packet);

struct mysqld_network_auth_challenge {
	guint8    protocol_version;
	gchar    *server_version_str;
	unsigned long   server_version;
	unsigned long   thread_id;
	GString  *auth_plugin_data;
	unsigned long   capabilities;
	guint8    charset;
	unsigned short   server_status;
	GString  *auth_plugin_name;
};

MY_GLOBAL_API mysqld_network_auth_challenge *mysqld_network_auth_challenge_new(void);
MY_GLOBAL_API void mysqld_network_auth_challenge_free(mysqld_network_auth_challenge *shake);
MY_GLOBAL_API int mysqld_network_proto_get_auth_challenge(network_packet *packet, mysqld_network_auth_challenge *shake);
MY_GLOBAL_API int mysqld_network_proto_append_auth_challenge(GString *packet, mysqld_network_auth_challenge *shake);
MY_GLOBAL_API void mysqld_network_auth_challenge_set_challenge(mysqld_network_auth_challenge *shake);
MY_GLOBAL_API mysqld_network_auth_challenge *mysqld_network_auth_challenge_copy(mysqld_network_auth_challenge *src);

struct mysqld_network_auth_response {
	unsigned long  client_capabilities;
	unsigned long  server_capabilities;
	unsigned long  max_packet_size;
	guint8   charset;
	GString *username;
	GString *auth_plugin_data;
	GString *database;
	GString *auth_plugin_name;
};

MY_GLOBAL_API mysqld_network_auth_response *mysqld_network_auth_response_new(guint server_capabilities);
MY_GLOBAL_API void mysqld_network_auth_response_free(mysqld_network_auth_response *auth);
MY_GLOBAL_API int mysqld_network_proto_append_auth_response(GString *packet, mysqld_network_auth_response *auth);
MY_GLOBAL_API int mysqld_network_proto_get_auth_response(network_packet *packet, mysqld_network_auth_response *auth);
MY_GLOBAL_API mysqld_network_auth_response *mysqld_network_auth_response_copy(mysqld_network_auth_response *src);

/* COM_STMT_* */

typedef struct {
	GString *stmt_text;
} mysqld_network_stmt_prepare_packet_t;

MY_GLOBAL_API mysqld_network_stmt_prepare_packet_t *mysqld_network_stmt_prepare_packet_new();
MY_GLOBAL_API void mysqld_network_stmt_prepare_packet_free(mysqld_network_stmt_prepare_packet_t *stmt_prepare_packet);
MY_GLOBAL_API int mysqld_network_proto_get_stmt_prepare_packet(network_packet *packet, mysqld_network_stmt_prepare_packet_t *stmt_prepare_packet);
MY_GLOBAL_API int mysqld_network_proto_append_stmt_prepare_packet(GString *packet, mysqld_network_stmt_prepare_packet_t *stmt_prepare_packet);

typedef struct {
	unsigned long stmt_id;
	unsigned short num_columns;
	unsigned short num_params;
	unsigned short warnings;
} mysqld_network_stmt_prepare_ok_packet_t;

MY_GLOBAL_API mysqld_network_stmt_prepare_ok_packet_t *mysqld_network_stmt_prepare_ok_packet_new(void);
MY_GLOBAL_API void mysqld_network_stmt_prepare_ok_packet_free(mysqld_network_stmt_prepare_ok_packet_t *stmt_prepare_ok_packet);
MY_GLOBAL_API int mysqld_network_proto_get_stmt_prepare_ok_packet(network_packet *packet, mysqld_network_stmt_prepare_ok_packet_t *stmt_prepare_ok_packet);
MY_GLOBAL_API int mysqld_network_proto_append_stmt_prepare_ok_packet(GString *packet, mysqld_network_stmt_prepare_ok_packet_t *stmt_prepare_ok_packet);

typedef struct {
	unsigned long stmt_id;
	guint8  flags;
	unsigned long iteration_count;
	guint8 new_params_bound;
	GPtrArray *params; /**< array<mysqld_network_type *> */
} mysqld_network_stmt_execute_packet_t;

MY_GLOBAL_API mysqld_network_stmt_execute_packet_t *mysqld_network_stmt_execute_packet_new(void);
MY_GLOBAL_API void mysqld_network_stmt_execute_packet_free(mysqld_network_stmt_execute_packet_t *stmt_execute_packet);
MY_GLOBAL_API int mysqld_network_proto_get_stmt_execute_packet(network_packet *packet, mysqld_network_stmt_execute_packet_t *stmt_execute_packet, guint param_count);
MY_GLOBAL_API int mysqld_network_proto_append_stmt_execute_packet(GString *packet, mysqld_network_stmt_execute_packet_t *stmt_execute_packet, guint param_count);
MY_GLOBAL_API int mysqld_network_proto_get_stmt_execute_packet_stmt_id(network_packet *packet, unsigned long *stmt_id);


typedef GPtrArray mysqld_network_resultset_row_t;

MY_GLOBAL_API mysqld_network_resultset_row_t *mysqld_network_resultset_row_new(void);
MY_GLOBAL_API void mysqld_network_resultset_row_free(mysqld_network_resultset_row_t *row);
MY_GLOBAL_API int mysqld_network_proto_get_binary_row(network_packet *packet, mysqld_network_proto_fielddefs_t *fields, mysqld_network_resultset_row_t *row);
MY_GLOBAL_API GList *mysqld_network_proto_get_next_binary_row(GList *chunk, mysqld_network_proto_fielddefs_t *fields, mysqld_network_resultset_row_t *row);

typedef struct {
	unsigned long stmt_id;
} mysqld_network_stmt_close_packet_t;

MY_GLOBAL_API mysqld_network_stmt_close_packet_t *mysqld_network_stmt_close_packet_new(void);
MY_GLOBAL_API void mysqld_network_stmt_close_packet_free(mysqld_network_stmt_close_packet_t *stmt_close_packet);
MY_GLOBAL_API int mysqld_network_proto_get_stmt_close_packet(network_packet *packet, mysqld_network_stmt_close_packet_t *stmt_close_packet);
MY_GLOBAL_API int mysqld_network_proto_append_stmt_close_packet(GString *packet, mysqld_network_stmt_close_packet_t *stmt_close_packet);

#endif  //__MYSQLD_NETWORK_PACKET_H
