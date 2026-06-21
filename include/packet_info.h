#pragma once

#include <glib.h>
#include <sys/types.h>

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
