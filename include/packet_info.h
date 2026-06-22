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
  int id;
  gdouble time;
  char *src;
  char *dst;
  char *protocol;
  guint len;
  char *info;

  GPtrArray *layers;

  guint8 *raw;
  guint raw_len;
} PacketInfo;

void packet_info_free(gpointer data);

gboolean packet_info_match_filter(PacketInfo *info, const gchar *filter);
