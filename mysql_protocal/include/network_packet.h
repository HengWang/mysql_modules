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

#ifndef __NETWORK_PACKET_H
#define __NETWORK_PACKET_H

#include "my_global_exports.h"

typedef struct {
	char* data;

	unsigned int offset;
} network_packet_st;

typedef network_packet_st network_packet

MY_GLOBAL_API network_packet *network_packet_init(void);

MY_GLOBAL_API void network_packet_uninit(network_packet *packet);

MY_GLOBAL_API bool network_packet_has_more_data(network_packet *packet, size_t len);

MY_GLOBAL_API bool network_packet_skip(network_packet *packet, size_t len);

MY_GLOBAL_API bool network_packet_peek_data(network_packet *packet, void* dst, size_t len);

MY_GLOBAL_API bool network_packet_get_data(network_packet *packet, void* dst, size_t len);

#endif  //__NETWORK_PACKET_H
