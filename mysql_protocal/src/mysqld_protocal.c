/*
 * Copyright (c) 2013, Heng Wang personal. All rights reserved.
 * 
 * Decoders and encoders for the MySQL packets.
 * - basic data-types 
 *   - fixed length integers
 *   - variable length integers
 *   - variable length strings
 * - packet types
 *   - OK packets
 *   - EOF packets
 *   - ERR packets
 *
 * @Author:  Heng.Wang
 * @Date  :  12/24/2013
 * @Email :  wangheng.king@gmail.com
 *           king_wangheng@163.com
 * @Github:  https://github.com/HengWang/
 * @Blog  :  http://hengwang.blog.chinaunix.net
 * */

#include <string.h>
#include <stdio.h>
#include <stdlib.h>

#include "mysqld_protocal.h"

/**
 * a handy macro for constant strings 
 */
#define C(x) x, sizeof(x) - 1
#define S(x) x->str, x->len

/**
 * skip bytes in the network packet
 *
 * a assertion makes sure that we can't skip over the end of the packet 
 *
 * @param packet the MySQL network packet
 * @param size   bytes to skip
 *
 */
int mysqld_protocal_skip(network_packet *packet, size_t size) {

	if (packet->offset + size > packet->data->len) {
	
	    return -1;
    }	
	packet->offset += size;

	return 0;
}


int mysqld_protocal_skip_network_header(network_packet *packet) {

	return mysqld_protocal_skip(packet, NET_HEADER_SIZE);
}

int mysqld_protocal_get_int_len(network_packet *packet, unsigned long long *v, size_t size) {

	int err = 0;

	err = err || mysqld_protocal_peek_int_len(packet, v, size);
	if (err) {
	
	    return -1;
	}
	packet->offset += size;

	return 0;
}

/**
 * get a 8-bit integer from the network packet
 *
 * @param packet the MySQL network packet
 * @param v      dest for the number
 * @return 0 on success, non-0 on error
 * @see get_int_len()
 */
int mysqld_protocal_get_int8(network_packet *packet, unsigned char *v) {

	unsigned long long v64;

	if (mysqld_protocal_get_int_len(packet, &v64, 1)) { 
	
        return -1;
	}
    /* check that we really only got one byte back */
	assert(v64 & 0xff == v64); 
	*v = v64 & 0xff;

	return 0;
}

/**
 * get a 16-bit integer from the network packet
 *
 * @param packet the MySQL network packet
 * @param v      dest for the number
 * @return 0 on success, non-0 on error
 * @see get_int_len()
 */
int mysqld_protocal_get_int16(network_packet *packet, unsigned short *v) {

	unsigned long long v64;

	if (mysqld_protocal_get_int_len(packet, &v64, 2)) {
	    
		return -1;
    }
	/* check that we really only got two byte back */
	assert(v64 & 0xffff == v64); 
	*v = v64 & 0xffff;

	return 0;
}

/**
 * get a 24-bit integer from the network packet
 *
 * @param packet the MySQL network packet
 * @param v      dest for the number
 * @return 0 on success, non-0 on error
 * @see get_int_len()
 */
int mysqld_protocal_get_int24(network_packet *packet, unsigned long *v) {

	unsigned long long v64;

	if (mysqld_protocal_get_int_len(packet, &v64, 3)) {
	    
		return -1;
    }
    /* check that we really only got two byte back */
	assert(v64 & 0x00ffffff, ==, v64); 
	*v = v64 & 0x00ffffff;

	return 0;
}

/**
 * get a 32-bit integer from the network packet
 *
 * @param packet the MySQL network packet
 * @param v      dest for the number
 * @return 0 on success, non-0 on error
 * @see get_int_len()
 */
int mysqld_protocal_get_int32(network_packet *packet, unsigned long *v) {
	unsigned long long v64;

	if (mysqld_protocal_get_int_len(packet, &v64, 4)) {
	    
		return -1;
	}
	*v = v64 & 0xffffffff;

	return 0;
}

/**
 * get a 6-byte integer from the network packet
 *
 * @param packet the MySQL network packet
 * @param v      dest for the number
 * @return 0 on success, non-0 on error
 * @see get_int_len()
 */
int mysqld_protocal_get_int48(network_packet *packet, unsigned long long *v) {

	unsigned long long v64;

	if (mysqld_protocal_get_int_len(packet, &v64, 6)) {
	    
		return -1;
    }
	*v = v64;

	return 0;
}

/**
 * get a 8-byte integer from the network packet
 *
 * @param packet the MySQL network packet
 * @param v      dest for the number
 * @return 0 on success, non-0 on error
 * @see get_int_len()
 */
int mysqld_protocal_get_int64(network_packet *packet, unsigned long long *v) {

	return mysqld_protocal_get_int_len(packet, v, 8);
}

/**
 * get a fixed-length integer from the network packet 
 *
 * @param packet the MySQL network packet
 * @param v      destination of the integer
 * @param size   byte-len of the integer to decode
 * @return a the decoded integer
 */
int mysqld_protocal_peek_int_len(network_packet *packet, unsigned long long *v, size_t size) {

	size_t i;
	int shift;
	unsigned long r_l = 0, r_h = 0;
	unsigned char *bytes = (unsigned char *)packet->data->str + packet->offset;

	if (packet->offset > packet->data->len) {
	
		return -1;
	}
	if (packet->offset + size > packet->data->len) {
	
		return -1;
	}
	/* for some reason left-shift > 32 leads to negative numbers. */
	for (i = 0, shift = 0; i < size && i < 4; i++, shift += 8, bytes++) {
	
		r_l |= ((*bytes) << shift);
	}
	for (shift = 0;	i < size; i++, shift += 8, bytes++) {

    	r_h |= ((*bytes) << shift);
	}
	*v = (((unsigned long long)r_h << 32) | r_l);

	return 0;
}

/**
 * get a 8-bit integer from the network packet
 *
 * @param packet the MySQL network packet
 * @param v      dest for the number
 * @return 0 on success, non-0 on error
 * @see get_int_len()
 */
int mysqld_protocal_peek_int8(network_packet *packet, unsigned char *v) {

	unsigned long long v64;

	if (mysqld_protocal_peek_int_len(packet, &v64, 1)) {
	    
		return -1;
    }
    /* check that we really only got one byte back */
	assert(v64 & 0xff == v64); 
	*v = v64 & 0xff;

	return 0;
}

/**
 * get a 16-bit integer from the network packet
 *
 * @param packet the MySQL network packet
 * @param v      dest for the number
 * @return 0 on success, non-0 on error
 * @see get_int_len()
 */
int mysqld_protocal_peek_int16(network_packet *packet, unsigned short *v) {

	unsigned long long v64;

	if (mysqld_protocal_peek_int_len(packet, &v64, 2)) {
	    
		return -1;
    }
	/* check that we really only got two byte back */
	assert(v64 & 0xffff == v64); 
	*v = v64 & 0xffff;

	return 0;
}

/**
 * peek a 32-bit integer from the network packet
 *
 * @param packet the MySQL network packet
 * @param v      dest for the number
 * @return 0 on success, non-0 on error
 * @see peek_int_len()
 */
int mysqld_protocal_peek_int32(network_packet *packet, unsigned long *v) {

	unsigned long long v64;

	if (mysqld_protocal_peek_int_len(packet, &v64, 4)) {
	
	    return -1;
    }
	*v = v64 & 0xffffffff;

	return 0;
}

/**
 * find a 8-bit integer in the network packet
 *
 * @param packet the MySQL network packet
 * @param c      character to find
 * @param pos    offset into the packet the 'c' was found
 * @return a the decoded integer
 * @see get_int_len()
 */
int mysqld_protocal_find_int8(network_packet *packet, unsigned char c, unsigned int *pos) {

	int err = 0;
	unsigned int off = packet->offset;
	unsigned char _c;

	while (!err) {
	
		err = err || mysqld_protocal_get_int8(packet, &_c);
		if (!err) {
			if (c == _c) {
				*pos = packet->offset - off;
				break;
			}
		}
	}
	packet->offset = off;

	return err;
}

/**
 * encode fixed length integer in to a network packet
 *
 * @param packet  the MySQL network packet
 * @param num     integer to encode
 * @param size    byte size of the integer
 * @return        0
 */
static int mysqld_protocal_append_int_len(char *packet, unsigned long long num, size_t size) {

	size_t i;

	for (i = 0; i < size; i++) {
	
		g_string_append_c(packet, num & 0xff);
		num >>= 8;
	}

	return 0;
}

/**
 * encode 8-bit integer in to a network packet
 *
 * @param packet  the MySQL network packet
 * @param num     integer to encode
 *
 * @see append_int_len()
 */
int mysqld_protocal_append_int8(char *packet, unsigned char num) {

	return mysqld_protocal_append_int_len(packet, num, 1);
}

/**
 * encode 16-bit integer in to a network packet
 *
 * @param packet  the MySQL network packet
 * @param num     integer to encode
 *
 * @see append_int_len()
 */
int mysqld_protocal_append_int16(char *packet, unsigned short num) {

	return mysqld_protocal_append_int_len(packet, num, 2);
}

/**
 * encode 24-bit integer in to a network packet
 *
 * @param packet  the MySQL network packet
 * @param num     integer to encode
 *
 * @see append_int_len()
 */
int mysqld_protocal_append_int24(char *packet, unsigned long num) {

	return mysqld_protocal_append_int_len(packet, num, 3);
}


/**
 * encode 32-bit integer in to a network packet
 *
 * @param packet  the MySQL network packet
 * @param num     integer to encode
 *
 * @see append_int_len()
 */
int mysqld_protocal_append_int32(char *packet, unsigned long num) {

	return mysqld_protocal_append_int_len(packet, num, 4);
}

/**
 * encode 48-bit integer in to a network packet
 *
 * @param packet  the MySQL network packet
 * @param num     integer to encode
 *
 * @see append_int_len()
 */
int mysqld_protocal_append_int48(char *packet, unsigned long long num) {

	return mysqld_protocal_append_int_len(packet, num, 6);
}


/**
 * encode 64-bit integer in to a network packet
 *
 * @param packet  the MySQL network packet
 * @param num     integer to encode
 *
 * @see append_int_len()
 */
int mysqld_protocal_append_int64(char *packet, unsigned long long num) {

	return mysqld_protocal_append_int_len(packet, num, 8);
}


/**
 * extract the type of the object that is placed where a length-encoded string is expected
 *
 * reads a byte from the packet and checks if it either a:
 * - integer
 * - NULL
 * - a ERR packet
 * - a EOF packet
 */
int mysqld_protocal_peek_lenenc_type(network_packet *packet, mysqld_lenenc_type *type) {
	unsigned int off = packet->offset;
	unsigned char *bytestream = (unsigned char *)packet->data->str;

	if(off < packet->data->len)
        return -1;

	if (bytestream[off] < 251) { /* */
		*type = MYSQLD_LENENC_TYPE_INT;
	} else if (bytestream[off] == 251) { /* NULL */
		*type = MYSQLD_LENENC_TYPE_NULL;
	} else if (bytestream[off] == 252) { /* 2 byte length*/
		*type = MYSQLD_LENENC_TYPE_INT;
	} else if (bytestream[off] == 253) { /* 3 byte */
		*type = MYSQLD_LENENC_TYPE_INT;
	} else if (bytestream[off] == 254) { /* 8 byte OR EOF */
		if (off == 4 && 
		    packet->data->len - packet->offset < 8) {
			*type = MYSQLD_LENENC_TYPE_EOF;
		} else {
			*type = MYSQLD_LENENC_TYPE_INT;
		}
	} else {
		*type = MYSQLD_LENENC_TYPE_ERR;
	}

	return 0;
}

/**
 * decode a length-encoded integer from a network packet
 *
 * _off is incremented on success 
 *
 * @param packet   the MySQL-packet to decode
 * @param v        destination of the integer
 * @return 0 on success, non-0 on error 
 *
 */
int mysqld_protocal_get_lenenc_int(network_packet *packet, unsigned long long *v) {
	unsigned int off = packet->offset;
	unsigned long long ret = 0;
	unsigned char *bytestream = (unsigned char *)packet->data->str;

	if (off >= packet->data->len) return -1;
	
	if (bytestream[off] < 251) { /* */
		ret = bytestream[off];
	} else if (bytestream[off] == 252) { /* 2 byte length*/
		if (off + 2 >= packet->data->len) return -1;
		ret = (bytestream[off + 1] << 0) | 
			(bytestream[off + 2] << 8) ;
		off += 2;
	} else if (bytestream[off] == 253) { /* 3 byte */
		if (off + 3 >= packet->data->len) return -1;
		ret = (bytestream[off + 1]   <<  0) | 
			(bytestream[off + 2] <<  8) |
			(bytestream[off + 3] << 16);

		off += 3;
	} else if (bytestream[off] == 254) { /* 8 byte */
		if (off + 8 >= packet->data->len) return -1;
		ret = (bytestream[off + 5] << 0) |
			(bytestream[off + 6] << 8) |
			(bytestream[off + 7] << 16) |
			(bytestream[off + 8] << 24);
		ret <<= 32;

		ret |= (bytestream[off + 1] <<  0) | 
			(bytestream[off + 2] <<  8) |
			(bytestream[off + 3] << 16) |
			(bytestream[off + 4] << 24);
		

		off += 8;
	} else {
		/* if we hit this place we complete have no idea about the protocol */
		g_critical("%s: bytestream[%d] is %d", 
			G_STRLOC,
			off, bytestream[off]);

		/* either ERR (255) or NULL (251) */

		return -1;
	}
	off += 1;

	packet->offset = off;

	*v = ret;

	return 0;
}











/**
 * get a string from the network packet
 *
 * @param packet the MySQL network packet
 * @param s      dest of the string
 * @param len    length of the string
 * @return       0 on success, non-0 otherwise
 * @return the string (allocated) or NULL of len is 0
 */
int get_string_len(network_packet *packet, gchar **s, size_t len) {
	gchar *str;

	if (len == 0) {
		*s = NULL;
		return 0;
	}

	if (packet->offset > packet->data->len) {
		return -1;
	}
	if (packet->offset + len > packet->data->len) {
		g_critical("%s: packet-offset out of range: %u + "F_SIZE_T" > "F_SIZE_T, 
				G_STRLOC,
				packet->offset, len, packet->data->len);

		return -1;
	}

	if (len) {
		str = g_malloc(len + 1);
		memcpy(str, packet->data->str + packet->offset, len);
		str[len] = '\0';
	} else {
		str = NULL;
	}

	packet->offset += len;

	*s = str;

	return 0;
}

/**
 * get a variable-length string from the network packet
 *
 * variable length strings are prefixed with variable-length integer defining the length of the string
 *
 * @param packet the MySQL network packet
 * @param s      destination of the decoded string
 * @param _len    destination of the length of the decoded string, if len is non-NULL
 * @return 0 on success, non-0 on error
 * @see get_string_len(), get_lenenc_int()
 */
int get_lenenc_string(network_packet *packet, gchar **s, unsigned long long *_len) {
	unsigned long long len;

	if (packet->offset >= packet->data->len) {
		g_debug_hexdump(G_STRLOC, S(packet->data));
		return -1;
	}	
	if (packet->offset >= packet->data->len) {
		return -1;
	}

	if (get_lenenc_int(packet, &len)) return -1;
	
	if (packet->offset + len > packet->data->len) return -1;

	if (_len) *_len = len;
	
	return get_string_len(packet, s, len);
}

/**
 * get a NUL-terminated string from the network packet
 *
 * @param packet the MySQL network packet
 * @param s      dest of the string
 * @return       0 on success, non-0 otherwise
 * @see get_string_len()
 */
int get_string(network_packet *packet, gchar **s) {
	unsigned long long len;
	int err = 0;

	for (len = 0; packet->offset + len < packet->data->len && *(packet->data->str + packet->offset + len); len++);

	if (*(packet->data->str + packet->offset + len) != '\0') {
		/* this has to be a \0 */
		return -1;
	}

	if (len > 0) {
		if (packet->offset >= packet->data->len) {
			return -1;
		}
		if (packet->offset + len > packet->data->len) {
			return -1;
		}

		/**
		 * copy the string w/o the NUL byte 
		 */
		err = err || get_string_len(packet, s, len);
	}

	err = err || skip(packet, 1);

	return err ? -1 : 0;
}


/**
 * get a char from the network packet
 *
 * @param packet the MySQL network packet
 * @param len    bytes to copy
 * @param out    a char which carries the string
 * @return       0 on success, -1 on error
 */
int get_gstring_len(network_packet *packet, size_t len, char *out) {
	int err = 0;

	if (!out) return -1;

	g_string_truncate(out, 0);

	if (!len) return 0; /* nothing to copy */

	err = err || (packet->offset >= packet->data->len); /* the offset is already too large */
	err = err || (packet->offset + len > packet->data->len); /* offset would get too large */

	if (!err) {
		g_string_append_len(out, packet->data->str + packet->offset, len);
		packet->offset += len;
	}

	return err ? -1 : 0;
}

/**
 * get a NUL-terminated char from the network packet
 *
 * @param packet the MySQL network packet
 * @param out    a char which carries the string
 * @return       a pointer to the string in out
 *
 * @see get_gstring_len()
 */
int get_gstring(network_packet *packet, char *out) {
	unsigned long long len;
	int err = 0;

	for (len = 0; packet->offset + len < packet->data->len && *(packet->data->str + packet->offset + len) != '\0'; len++);

	if (packet->offset + len == packet->data->len) { /* havn't found a trailing \0 */
		return -1;
	}

	if (len > 0) {
		g_assert(packet->offset < packet->data->len);
		g_assert(packet->offset + len <= packet->data->len);

		err = err || get_gstring_len(packet, len, out);
	}

	/* skip the \0 */
	err = err || skip(packet, 1);

	return err ? -1 : 0;
}

/**
 * get a variable-length char from the network packet
 *
 * @param packet the MySQL network packet
 * @param out    a char which carries the string
 * @return       0 on success, non-0 on error
 *
 * @see get_gstring_len(), get_lenenc_int()
 */
int get_lenenc_gstring(network_packet *packet, char *out) {
	unsigned long long len;
	int err = 0;

	err = err || get_lenenc_int(packet, &len);
	err = err || get_gstring_len(packet, len, out);

	return err ? -1 : 0;
}

/**
 * create a empty field for a result-set definition
 *
 * @return a empty MYSQL_FIELD
 */
MYSQL_FIELD *fielddef_new() {
	MYSQL_FIELD *field;
	
	field = g_new0(MYSQL_FIELD, 1);

	return field;
}

/**
 * free a MYSQL_FIELD and its components
 *
 * @param field  the MYSQL_FIELD to free
 */
void fielddef_free(MYSQL_FIELD *field) {
	if (field->catalog) g_free(field->catalog);
	if (field->db) g_free(field->db);
	if (field->name) g_free(field->name);
	if (field->org_name) g_free(field->org_name);
	if (field->table) g_free(field->table);
	if (field->org_table) g_free(field->org_table);

	g_free(field);
}

/**
 * create a array of MYSQL_FIELD 
 *
 * @return a empty array of MYSQL_FIELD
 */
GPtrArray *fielddefs_new(void) {
	GPtrArray *fields;
	
	fields = g_ptr_array_new();

	return fields;
}

/**
 * free a array of MYSQL_FIELD 
 *
 * @param fields  array of MYSQL_FIELD to free
 * @see field_free()
 */
void fielddefs_free(GPtrArray *fields) {
	unsigned int i;

	for (i = 0; i < fields->len; i++) {
		MYSQL_FIELD *field = fields->pdata[i];

		if (field) fielddef_free(field);
	}

	g_ptr_array_free(fields, TRUE);
}

/**
 * set length of the packet in the packet header
 *
 * each MySQL packet is 
 *  - is prefixed by a 4 byte packet header
 *  - length is max 16Mbyte (3 Byte)
 *  - sequence-id (1 Byte) 
 *
 * To encode a packet of more then 16M clients have to send multiple 16M frames
 *
 * the sequence-id is incremented for each related packet and wrapping from 255 to 0
 *
 * @param header  string of at least 4 byte to write the packet header to
 * @param length  length of the packet
 * @param id      sequence-id of the packet
 * @return 0
 */
int set_packet_len(char *_header, unsigned long length) {
	unsigned char *header = (unsigned char *)_header->str;

	g_assert_cmpint(length, <=, PACKET_LEN_MAX);

	header[0] = (length >>  0) & 0xFF;
	header[1] = (length >>  8) & 0xFF;
	header[2] = (length >> 16) & 0xFF;
	
	return 0;
}

int set_packet_id(char *_header, unsigned char id) {
	unsigned char *header = (unsigned char *)_header->str;

	header[3] = id;

	return 0;
}

int append_packet_len(char *_header, unsigned long length) {
	return append_int24(_header, length);
}

int append_packet_id(char *_header, unsigned char id) {
	return append_int8(_header, id);
}

/**
 * decode the packet length from a packet header
 *
 * @param header the first 3 bytes of the network packet
 * @return the packet length
 * @see set_header()
 */
unsigned long get_packet_len(char *_header) {
	unsigned char *header = (unsigned char *)_header->str;

	return header[0] | header[1] << 8 | header[2] << 16;
}

/**
 * decode the packet length from a packet header
 *
 * @param header the first 3 bytes of the network packet
 * @return the packet length
 * @see set_header()
 */
unsigned char get_packet_id(char *_header) {
	unsigned char *header = (unsigned char *)_header->str;

	return header[3];
}


/**
 * append the variable-length integer to the packet
 *
 * @param packet  the MySQL network packet
 * @param length  integer to encode
 * @return        0
 */
int append_lenenc_int(char *packet, unsigned long long length) {
	if (length < 251) {
		g_string_append_c(packet, length);
	} else if (length < 65536) {
		g_string_append_c(packet, (gchar)252);
		g_string_append_c(packet, (length >> 0) & 0xff);
		g_string_append_c(packet, (length >> 8) & 0xff);
	} else if (length < 16777216) {
		g_string_append_c(packet, (gchar)253);
		g_string_append_c(packet, (length >> 0) & 0xff);
		g_string_append_c(packet, (length >> 8) & 0xff);
		g_string_append_c(packet, (length >> 16) & 0xff);
	} else {
		g_string_append_c(packet, (gchar)254);

		g_string_append_c(packet, (length >> 0) & 0xff);
		g_string_append_c(packet, (length >> 8) & 0xff);
		g_string_append_c(packet, (length >> 16) & 0xff);
		g_string_append_c(packet, (length >> 24) & 0xff);

		g_string_append_c(packet, (length >> 32) & 0xff);
		g_string_append_c(packet, (length >> 40) & 0xff);
		g_string_append_c(packet, (length >> 48) & 0xff);
		g_string_append_c(packet, (length >> 56) & 0xff);
	}

	return 0;
}

/**
 * encode a char in to a MySQL len-encoded string 
 *
 * @param packet  the MySQL network packet
 * @param s       string to encode
 * @param length  length of the string to encode
 * @return 0
 */
int append_lenenc_string_len(char *packet, const char *s, unsigned long long length) {
	if (!s) {
		g_string_append_c(packet, (gchar)251); /** this is NULL */
	} else {
		append_lenenc_int(packet, length);
		g_string_append_len(packet, s, length);
	}

	return 0;
}

/**
 * encode a char in to a MySQL len-encoded string 
 *
 * @param packet  the MySQL network packet
 * @param s       string to encode
 *
 * @see append_lenenc_string_len()
 */
int append_lenenc_string(char *packet, const char *s) {
	return append_lenenc_string_len(packet, s, s ? strlen(s) : 0);
}




/**
 * hash the password as MySQL 4.1 and later assume
 *
 *   SHA1( password )
 *
 * @see scramble
 */
int password_hash(char *response, const char *password, size_t password_len) {
	GChecksum *cs;

	/* first round: SHA1(password) */
	cs = g_checksum_new(G_CHECKSUM_SHA1);

	g_checksum_update(cs, (unsigned char *)password, password_len);

	g_string_set_size(response, g_checksum_type_get_length(G_CHECKSUM_SHA1));
	response->len = response->allocated_len; /* will be overwritten with the right value in the next step */
	g_checksum_get_digest(cs, (unsigned char *)response->str, &(response->len));

	g_checksum_free(cs);
	
	return 0;
}

/**
 * scramble the hashed password with the challenge
 *
 * @param response         dest 
 * @param challenge        the challenge string as sent by the mysql-server
 * @param challenge_len    length of the challenge
 * @param hashed_password  hashed password
 * @param hashed_password_len length of the hashed password
 *
 * @see password_hash
 */
int password_scramble(char *response,
		const char *challenge, size_t challenge_len,
		const char *hashed_password, size_t hashed_password_len) {
	int i;
	GChecksum *cs;
	char *step2;

	g_return_val_if_fail(NULL != challenge, -1);
	g_return_val_if_fail(20 == challenge_len, -1);
	g_return_val_if_fail(NULL != hashed_password, -1);
	g_return_val_if_fail(20 == hashed_password_len, -1);

	/**
	 * we have to run
	 *
	 *   XOR( SHA1(password), SHA1(challenge + SHA1(SHA1(password)))
	 *
	 * where SHA1(password) is the hashed_password and
	 *       challenge      is ... challenge
	 *
	 *   XOR( hashed_password, SHA1(challenge + SHA1(hashed_password)))
	 *
	 */

	/* 1. SHA1(hashed_password) */
	step2 = g_string_new(NULL);
	password_hash(step2, hashed_password, hashed_password_len);

	/* 2. SHA1(challenge + SHA1(hashed_password) */
	cs = g_checksum_new(G_CHECKSUM_SHA1);
	g_checksum_update(cs, (unsigned char *)challenge, challenge_len);
	g_checksum_update(cs, (unsigned char *)step2->str, step2->len);
	
	g_string_set_size(response, g_checksum_type_get_length(G_CHECKSUM_SHA1));
	response->len = response->allocated_len;
	g_checksum_get_digest(cs, (unsigned char *)response->str, &(response->len));
	
	g_checksum_free(cs);

	/* XOR the hashed_password with SHA1(challenge + SHA1(hashed_password)) */
	for (i = 0; i < 20; i++) {
		response->str[i] = (unsigned char)response->str[i] ^ (unsigned char)hashed_password[i];
	}

	g_string_free(step2, TRUE);

	return 0;
}

/**
 * unscramble the auth-response and get the hashed-password
 *
 * @param hashed_password  dest of the hashed password
 * @param challenge        the challenge string as sent by the mysql-server
 * @param challenge_len    length of the challenge
 * @param response         auth response as sent by the client 
 * @param response_len     length of response
 * @param double_hashed    the double hashed password as stored in the mysql.server table (without * and unhexed)
 * @param double_hashed_len length of double_hashed
 *
 * @see scramble
 */
int password_unscramble(
		char *hashed_password,
		const char *challenge, size_t challenge_len,
		const char *response, size_t response_len,
		const char *double_hashed, size_t double_hashed_len) {
	int i;
	GChecksum *cs;

	g_return_val_if_fail(NULL != response, FALSE);
	g_return_val_if_fail(20 == response_len, FALSE);
	g_return_val_if_fail(NULL != challenge, FALSE);
	g_return_val_if_fail(20 == challenge_len, FALSE);
	g_return_val_if_fail(NULL != double_hashed, FALSE);
	g_return_val_if_fail(20 == double_hashed_len, FALSE);

	/**
	 * to check we have to:
	 *
	 *   hashed_password = XOR( response, SHA1(challenge + double_hashed))
	 *   double_hashed == SHA1(hashed_password)
	 *
	 * where SHA1(password) is the hashed_password and
	 *       challenge      is ... challenge
	 *       response       is the response of the client
	 *
	 *   XOR( hashed_password, SHA1(challenge + SHA1(hashed_password)))
	 *
	 */


	/* 1. SHA1(challenge + double_hashed) */
	cs = g_checksum_new(G_CHECKSUM_SHA1);
	g_checksum_update(cs, (unsigned char *)challenge, challenge_len);
	g_checksum_update(cs, (unsigned char *)double_hashed, double_hashed_len);
	
	g_string_set_size(hashed_password, g_checksum_type_get_length(G_CHECKSUM_SHA1));
	hashed_password->len = hashed_password->allocated_len;
	g_checksum_get_digest(cs, (unsigned char *)hashed_password->str, &(hashed_password->len));
	
	g_checksum_free(cs);
	
	/* 2. XOR the response with SHA1(challenge + SHA1(hashed_password)) */
	for (i = 0; i < 20; i++) {
		hashed_password->str[i] = (unsigned char)response[i] ^ (unsigned char)hashed_password->str[i];
	}

	return 0;
}

/**
 * check if response and challenge match a double-hashed password
 *
 * @param challenge        the challenge string as sent by the mysql-server
 * @param challenge_len    length of the challenge
 * @param response         auth response as sent by the client 
 * @param response_len     length of response
 * @param double_hashed    the double hashed password as stored in the mysql.server table (without * and unhexed)
 * @param double_hashed_len length of double_hashed
 *
 * @see scramble
 */
gboolean password_check(
		const char *challenge, size_t challenge_len,
		const char *response, size_t response_len,
		const char *double_hashed, size_t double_hashed_len) {

	char *hashed_password, *step2;
	gboolean is_same;

	g_return_val_if_fail(NULL != response, FALSE);
	g_return_val_if_fail(20 == response_len, FALSE);
	g_return_val_if_fail(NULL != challenge, FALSE);
	g_return_val_if_fail(20 == challenge_len, FALSE);
	g_return_val_if_fail(NULL != double_hashed, FALSE);
	g_return_val_if_fail(20 == double_hashed_len, FALSE);

	hashed_password = g_string_new(NULL);

	password_unscramble(hashed_password, 
			challenge, challenge_len,
			response, response_len,
			double_hashed, double_hashed_len);

	/* 3. SHA1(hashed_password) */
	step2 = g_string_new(NULL);
	password_hash(step2, S(hashed_password));
	
	/* 4. the result of 3 should be the same what we got from the mysql.user table */
	is_same = strleq(S(step2), double_hashed, double_hashed_len);

	g_string_free(step2, TRUE);
	g_string_free(hashed_password, TRUE);

	return is_same;
}



