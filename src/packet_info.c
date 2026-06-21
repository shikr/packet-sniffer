#include "packet_info.h"

void packet_info_free(gpointer data) {
  PacketInfo *info = data;
  if (info) {
    g_free(info->src);
    g_free(info->dst);
    g_free(info->protocol);
    g_free(info->info);
    g_ptr_array_free(info->layers, TRUE);
    g_free(info->raw);
    g_free(info);
  }
}
