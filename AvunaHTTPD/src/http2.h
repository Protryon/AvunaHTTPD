/*
 * http2.h
 *
 *  Created on: Dec 13, 2015
 *      Author: root
 */

#ifndef HTTP2_H_
#define HTTP2_H_

#include <stdint.h>

#define FRAME_DATA_ID 0
#define FRAME_HEADERS_ID 1
#define FRAME_PRIORITY_ID 2
#define FRAME_RST_STREAM_ID 3
#define FRAME_SETTINGS_ID 4
#define FRAME_PUSH_PROMISE_ID 5
#define FRAME_PING_ID 6
#define FRAME_GOAWAY_ID 7
#define FRAME_WINDOW_UPDATE_ID 8
#define FRAME_CONTINUATION_ID 9

#define ERROR_NO_ERROR 0
#define ERROR_PROTOCOL_ERROR 1
#define ERROR_INTERNAL_ERROR 2
#define ERROR_FLOW_CONTROL_ERROR 3
#define ERROR_SETTINGS_TIMEOUT 4
#define ERROR_STREAM_CLOSED 5
#define ERROR_FRAME_SIZE_ERROR 6
#define ERROR_REFUSED_STREAM 7
#define ERROR_CANCEL 8
#define ERROR_COMPRESSION_ERROR 9
#define ERROR_CONNECT_ERROR 10
#define ERROR_ENHANCE_YOUR_CALM 11
#define ERROR_INADEQUATE_SECURITY 12;
#define ERROR_HTTP_1_1_REQUIRED 13;
//
//struct frame_data {
//		unsigned char* data;
//};
//
//struct frame_headers {
//		uint32_t stream_dep;
//		unsigned char weight;
//		unsigned char* data;
//};
//
//struct frame_priority {
//		uint32_t stream_dep;
//		unsigned char weight;
//};
//
//struct frame_rst_stream {
//		uint32_t errorCode;
//};
//
//struct frame_settings {
//		int settings_count;
//		uint16_t* setting_keys;
//		uint32_t* setting_values;
//};
//
//struct frame_push_promise {
//		uint32_t streamID;
//		unsigned char* data;
//};
//
//struct frame_ping {
//		uint64_t data;
//};
//
//struct frame_goaway {
//		uint32_t lastStreamID;
//		uint32_t errorCode;
//		unsigned char* data;
//};
//
//struct frame_window_update {
//		uint32_t increment;
//};
//
//struct frame_continuation {
//		unsigned char* data;
//};
//
//union uframe {
//		struct frame_data data;
//		struct frame_headers headers;
//		struct frame_priority priority;
//		struct frame_rst_stream rst_stream;
//		struct frame_settings settings;
//		struct frame_push_promise push_promise;
//		struct frame_ping ping;
//		struct frame_goaway goaway;
//		struct frame_window_update window_update;
//		struct frame_continuation continuation;
//};

struct frame {
		size_t length;
		unsigned char type;
		unsigned char flags;
		uint32_t stream;
		struct http2_stream* strobj;
		unsigned char* uf;
};

#endif /* HTTP2_H_ */
