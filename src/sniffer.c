#include "sniffer.h"
#include "packet_info.h"
#include <capture.h>
#include <glib.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <pcap.h>

struct _AppSniffer {
  GObject parent;
  pcap_t *handle;
  GPtrArray *packets;
  GAsyncQueue *queue;
  GMutex mutex;
  GThread *thread;
  struct timeval first_ts;
};

enum { SIG_CAPTURED, N_SIGNALS };

static guint signals[N_SIGNALS];

G_DEFINE_TYPE(AppSniffer, app_sniffer, G_TYPE_OBJECT)

static void app_sniffer_init(AppSniffer *self) {
  self->handle = NULL;
  self->packets = g_ptr_array_new_with_free_func(packet_info_free);
  self->queue = g_async_queue_new();
  g_mutex_init(&self->mutex);
  self->thread = NULL;
  self->first_ts.tv_sec = 0;
}

static void app_sniffer_finalize(GObject *object) {
  AppSniffer *self = APP_SNIFFER(object);
  if (self->handle) {
    pcap_breakloop(self->handle);
  }
  g_ptr_array_free(self->packets, TRUE);
  g_async_queue_unref(self->queue);
  if (self->thread) {
    g_thread_join(self->thread);
    self->thread = NULL;
  }
  g_mutex_clear(&self->mutex);
  G_OBJECT_CLASS(app_sniffer_parent_class)->finalize(object);
}

static void app_sniffer_class_init(AppSnifferClass *klass) {
  GObjectClass *object_class = G_OBJECT_CLASS(klass);
  object_class->finalize = app_sniffer_finalize;
  signals[SIG_CAPTURED] =
      g_signal_new("captured", G_TYPE_FROM_CLASS(klass), G_SIGNAL_RUN_FIRST, 0,
                   NULL, NULL, NULL, G_TYPE_NONE, 1, G_TYPE_UINT);
}

AppSniffer *app_sniffer_new() {
  AppSniffer *self = g_object_new(APP_TYPE_SNIFFER, NULL);
  return self;
}

void app_sniffer_add_packet(AppSniffer *self, PacketInfo *pkt_info) {
  int index;
  g_mutex_lock(&self->mutex);
  g_ptr_array_add(self->packets, pkt_info);
  index = self->packets->len - 1;
  g_mutex_unlock(&self->mutex);
  g_signal_emit(self, signals[SIG_CAPTURED], 0, index);
}

void app_sniffer_check_time(AppSniffer *self, const struct timeval ts) {
  if (!self->first_ts.tv_sec && !self->first_ts.tv_usec)
    self->first_ts = ts;
}

gdouble app_sniffer_get_relative_time(AppSniffer *self,
                                      const struct timeval *ts) {
  gint64 ts_us = (gint64)ts->tv_sec * G_GINT64_CONSTANT(1000000) + ts->tv_usec;
  gint64 first_us = (gint64)self->first_ts.tv_sec * G_GINT64_CONSTANT(1000000) +
                    self->first_ts.tv_usec;
  return (ts_us - first_us) / 1e6;
}

void app_sniffer_queue_packet(AppSniffer *self, PacketInfo *pkt_info) {
  g_async_queue_push(self->queue, pkt_info);
}

typedef struct {
  AppSniffer *sniffer;
  char *device;
  char *filter;
} CaptureThreadData;

static gpointer capture_thread(gpointer user_data) {
  CaptureThreadData *data = user_data;
  AppSniffer *self = data->sniffer;
  char errbuf[PCAP_ERRBUF_SIZE];

  self->handle = pcap_open_live(data->device, BUFSIZ, 1, 100, errbuf);
  if (!self->handle) {
    g_warning("Could not open device %s: %s", data->device, errbuf);
    g_object_unref(self);
    return NULL;
  }
  struct bpf_program fp;

  if (pcap_datalink(self->handle) != DLT_EN10MB) {
    g_warning("Device %s does not support Ethernet headers", data->device);
    g_object_unref(self);
    return NULL;
  }

  if (data->filter && data->filter[0] != '\0') {
    if (pcap_compile(self->handle, &fp, data->filter, 0,
                     PCAP_NETMASK_UNKNOWN) == -1) {
      g_warning("Could not parse filter %s: %s", data->filter,
                pcap_geterr(self->handle));
      g_object_unref(self);
      return NULL;
    }
    if (pcap_setfilter(self->handle, &fp) == -1) {
      g_warning("Could not install filter %s: %s", data->filter,
                pcap_geterr(self->handle));
      g_object_unref(self);
      return NULL;
    }
  }

  pcap_loop(self->handle, -1, capture_handler, (u_char *)self);

  pcap_close(self->handle);
  self->handle = NULL;
  g_free(data->device);
  g_free(data->filter);
  g_free(data);
  return NULL;
}

void app_sniffer_start(AppSniffer *self, const char *device,
                       const char *filter) {
  g_return_if_fail(APP_IS_SNIFFER(self));

  g_ptr_array_remove_range(self->packets, 0, self->packets->len);

  self->first_ts.tv_sec = 0;
  self->first_ts.tv_usec = 0;

  while (g_async_queue_try_pop(self->queue))
    ;

  if (!self->thread && !self->handle) {
    CaptureThreadData *data = g_new(CaptureThreadData, 1);
    data->sniffer = self;
    data->device = g_strdup(device);
    data->filter = g_strdup(filter);
    self->thread = g_thread_new("capture_thread", capture_thread, data);
  }
}

void app_sniffer_stop(AppSniffer *self) {
  g_return_if_fail(APP_IS_SNIFFER(self));
  if (self->handle) {
    pcap_breakloop(self->handle);
  }

  if (self->thread) {
    g_thread_join(self->thread);
    g_thread_unref(self->thread);
    self->thread = NULL;
  }
}

PacketInfo *app_sniffer_get_packet(AppSniffer *self, guint index) {
  g_return_val_if_fail(APP_IS_SNIFFER(self), NULL);
  g_return_val_if_fail(index < self->packets->len, NULL);

  g_mutex_lock(&self->mutex);
  PacketInfo *pkt_info = NULL;
  pkt_info = g_ptr_array_index(self->packets, index);
  g_mutex_unlock(&self->mutex);
  return pkt_info;
}

guint app_sniffer_packets_len(AppSniffer *self) {
  g_return_val_if_fail(APP_IS_SNIFFER(self), 0);

  g_mutex_lock(&self->mutex);
  guint len = self->packets->len;
  g_mutex_unlock(&self->mutex);

  return len;
}

gboolean update_packets_from_queue(gpointer user_data) {
  AppSniffer *self = user_data;
  PacketInfo *pkt_info;
  int count = 0;

  while (count < 50 && (pkt_info = g_async_queue_try_pop(self->queue))) {
    app_sniffer_add_packet(self, pkt_info);
    count++;
  }

  return G_SOURCE_CONTINUE;
}

guint app_sniffer_start_timer(AppSniffer *self) {
  return g_timeout_add(100, update_packets_from_queue, self);
}
