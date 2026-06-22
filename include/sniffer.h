#pragma once

#include "packet_info.h"
#include <glib-object.h>

G_BEGIN_DECLS

#define APP_TYPE_SNIFFER (app_sniffer_get_type())
G_DECLARE_FINAL_TYPE(AppSniffer, app_sniffer, APP, SNIFFER, GObject)

AppSniffer *app_sniffer_new();

void app_sniffer_start(AppSniffer *self, const char *device,
                       const char *filter);
void app_sniffer_stop(AppSniffer *self);

PacketInfo *app_sniffer_get_packet(AppSniffer *self, guint index);
guint app_sniffer_packets_len(AppSniffer *self);
gdouble app_sniffer_get_relative_time(AppSniffer *self,
                                      const struct timeval *ts);

void app_sniffer_queue_packet(AppSniffer *self, PacketInfo *pkt_info);

guint app_sniffer_start_timer(AppSniffer *self);

G_END_DECLS
