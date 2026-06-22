#include "packet_info.h"
#include <glib.h>
#include <stddef.h>
#include <string.h>

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

gboolean packet_info_match_filter(PacketInfo *info, const gchar *filter) {
  if (!filter || filter[0] == '\0') {
    return TRUE;
  }

  size_t filter_len = strlen(filter);
  size_t i = 0;

  while (i < filter_len) {
    while (i < filter_len && g_ascii_isspace(filter[i])) {
      i++;
    }
    if (i >= filter_len) {
      break;
    }

    const char *start = &filter[i];
    while (i < filter_len && !g_ascii_isspace(filter[i])) {
      i++;
    }
    size_t token_len = &filter[i] - start;

    if (token_len > 0) {
      char *token = g_strndup(start, token_len);
      if (strncmp(token, "src:", 4) == 0) {
        char *src_filter = token + 4;
        if (strcmp(info->src, src_filter) != 0)
          goto no_match;
      } else if (strncmp(token, "dst:", 4) == 0) {
        char *dst_filter = token + 4;
        if (strcmp(info->dst, dst_filter) != 0)
          goto no_match;
      } else if (strncmp(token, "proto:", 6) == 0) {
        char *proto_filter = token + 6;
        if (strcmp(info->protocol, proto_filter) != 0)
          goto no_match;
      } else if (strncmp(token, "info:", 5) == 0) {
        char *info_filter = token + 5;
        if (!g_strstr_len(info->info, -1, info_filter))
          goto no_match;
      }

      g_free(token);
      continue;

    no_match:
      g_free(token);
      return FALSE;
    }
  }

  return TRUE;
}
