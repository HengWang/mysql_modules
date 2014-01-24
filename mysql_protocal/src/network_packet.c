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

#include <glib.h>
#include <stdlib.h>
#include <string.h>

#include "my_malloc.h"
#include "network_packet.h"

network_packet* network_packet_init(void) {

	network_packet *packet;
	packet = my_malloc(1);

	return packet;
}

void network_packet_uninit(network_packet *packet) {

	if (!packet) return;
	my_free(packet);
}

bool network_packet_has_more_data(network_packet *packet, size_t len) {

    /* we are already out of bounds, shouldn't happen */
	if (packet->offset > packet->data->len) {
	
	    return FALSE; 
	}
	if (len > packet->data->len - packet->offset) {
	    return FALSE;
    }
	
	return TRUE;
}

bool network_packet_skip(network_packet *packet, size_t len) {

	if (!network_packet_has_more_data(packet, len)) {
	
		return FALSE;
	}

	packet->offset += len;
	
	return TRUE;
}

bool network_packet_peek_data(network_packet *packet, void* dst, size_t len) {

	if (!network_packet_has_more_data(packet, len)) {
	
	    return FALSE;
    }
	
	memcpy(dst, packet->data->str + packet->offset, len);

	return TRUE;
}


bool network_packet_get_data(network_packet *packet, void* dst, size_t len) {

	if (!network_packet_peek_data(packet, dst, len)) {
	
		return FALSE;
	}

	packet->offset += len;

	return TRUE;
}

