#pragma once

#include <glib.h>
#include <sys/types.h>

enum PacketColumns {
  COL_NO,
  COL_TIME,
  COL_SOURCE,
  COL_DEST,
  COL_PROTOCOL,
  COL_LEN,
  COL_INFO,
  COL_INDEX,
  NUM_COLS
};

typedef struct {
  int no;
  int id;
  float time;
  int len;
  char *src_ip;
  char *dst_ip;
  int ttl;
  int tos;
  char *protocol;
  char *info;
  int raw_len;
  u_char *raw;
} PacketInfo;

void packet_info_free(gpointer data);
