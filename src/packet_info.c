#include "packet_info.h"

void packet_info_free(gpointer data) {
  PacketInfo *info = data;
  if (info) {
    g_free(info->src_ip);
    g_free(info->dst_ip);
    g_free(info->protocol);
    g_free(info->info);
    g_free(info->raw);
    g_free(info);
  }
}
