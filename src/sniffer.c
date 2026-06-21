#include "sniffer.h"
#include "packet_info.h"
#include <glib.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <pcap.h>
#include <string.h>

struct _AppSniffer {
  GObject parent;
  pcap_t *handle;
  GPtrArray *packets;
  GAsyncQueue *queue;
  GMutex mutex;
  GThread *thread;
  struct timeval first_ts;
  char *device;
  char *filter;
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
  g_free(self->device);
  g_free(self->filter);
  G_OBJECT_CLASS(app_sniffer_parent_class)->finalize(object);
}

static void app_sniffer_class_init(AppSnifferClass *klass) {
  GObjectClass *object_class = G_OBJECT_CLASS(klass);
  object_class->finalize = app_sniffer_finalize;
  signals[SIG_CAPTURED] =
      g_signal_new("captured", G_TYPE_FROM_CLASS(klass), G_SIGNAL_RUN_FIRST, 0,
                   NULL, NULL, NULL, G_TYPE_NONE, 1, G_TYPE_UINT);
}

AppSniffer *app_sniffer_new(char *device, char *filter) {
  AppSniffer *self = g_object_new(APP_TYPE_SNIFFER, NULL);
  self->device = g_strdup(device);
  self->filter = g_strdup(filter);
  return self;
}

void app_sniffer_add_packet(AppSniffer *self, PacketInfo *pkt_info) {
  g_mutex_lock(&self->mutex);
  g_ptr_array_add(self->packets, pkt_info);
  g_mutex_unlock(&self->mutex);
  g_signal_emit(self, signals[SIG_CAPTURED], 0, self->packets->len - 1);
}

void capture_handler(u_char *user, const struct pcap_pkthdr *pkthdr,
                     const u_char *packetd_ptr) {
  AppSniffer *self = (AppSniffer *)user;
  int link_hdr_length = 14; // Assuming Ethernet

  const u_char *pkt_start = packetd_ptr;
  if (pkthdr->caplen <
      (unsigned int)(link_hdr_length + (int)sizeof(struct ip))) {
    return;
  }

  PacketInfo *pkt_info = g_new0(PacketInfo, 1);

  if (!self->first_ts.tv_sec) {
    self->first_ts = pkthdr->ts;
  }

  pkt_info->time = (pkthdr->ts.tv_sec - self->first_ts.tv_sec) +
                   (pkthdr->ts.tv_usec - self->first_ts.tv_usec) / 1000000.0f;

  packetd_ptr += link_hdr_length;
  struct ip *ip_hdr = (struct ip *)packetd_ptr;

  pkt_info->no = self->packets->len + 1;
  pkt_info->src_ip = g_strdup(inet_ntoa(ip_hdr->ip_src));
  pkt_info->dst_ip = g_strdup(inet_ntoa(ip_hdr->ip_dst));
  pkt_info->id = ntohs(ip_hdr->ip_id);
  pkt_info->ttl = ip_hdr->ip_ttl;
  pkt_info->tos = ip_hdr->ip_tos;
  pkt_info->len = ntohs(ip_hdr->ip_len);
  pkt_info->protocol = g_strdup("OTHER");
  pkt_info->info = g_strdup("");
  pkt_info->raw_len = pkthdr->caplen;
  pkt_info->raw = g_malloc(pkt_info->raw_len + 1);
  memcpy(pkt_info->raw, pkt_start, pkt_info->raw_len);

  int packet_hlen = ip_hdr->ip_hl * 4;
  if (packet_hlen < 20 ||
      pkthdr->caplen < (unsigned int)(link_hdr_length + packet_hlen)) {
    packet_info_free(pkt_info);
    return;
  }

  packetd_ptr += packet_hlen;
  int protocol_type = ip_hdr->ip_p;
  unsigned int transport_len = pkthdr->caplen - link_hdr_length - packet_hlen;

  struct tcphdr *tcp_header;
  struct udphdr *udp_header;
  struct icmp *icmp_header;
  int src_port, dst_port;

  // printf("************************************"
  //        "**************************************\n");
  // printf("ID: %d | SRC: %s | DST: %s | TOS: 0x%x | TTL: %d\n", pkt_info.id,
  //        pkt_info.src_ip, pkt_info.dst_ip, pkt_info.tos, pkt_info.ttl);

  switch (protocol_type) {
  case IPPROTO_TCP:
    if (transport_len < sizeof(struct tcphdr)) {
      pkt_info->protocol = g_strdup("TCP");
      pkt_info->info = g_strdup("TRUNCATED");
      break;
    }
    tcp_header = (struct tcphdr *)packetd_ptr;
    src_port = ntohs(tcp_header->th_sport);
    dst_port = ntohs(tcp_header->th_dport);
    pkt_info->protocol = g_strdup("TCP");
    char flags[8];
    snprintf(flags, sizeof(flags), "%c%c%c",
             (tcp_header->th_flags & TH_SYN ? 'S' : '-'),
             (tcp_header->th_flags & TH_ACK ? 'A' : '-'),
             (tcp_header->th_flags & TH_URG ? 'U' : '-'));
    asprintf(&pkt_info->info, "%d -> %d [%s]", src_port, dst_port, flags);
    // printf("PROTO: TCP | FLAGS: %c/%c/%c | SPORT: %d | DPORT: %d |\n",
    //        (tcp_header->th_flags & TH_SYN ? 'S' : '-'),
    //        (tcp_header->th_flags & TH_ACK ? 'A' : '-'),
    //        (tcp_header->th_flags & TH_URG ? 'U' : '-'), src_port, dst_port);
    break;
  case IPPROTO_UDP: {
    if (transport_len < sizeof(struct udphdr)) {
      pkt_info->protocol = g_strdup("UDP");
      pkt_info->info = g_strdup("TRUNCATED");
      break;
    }
    udp_header = (struct udphdr *)packetd_ptr;
    src_port = ntohs(udp_header->uh_sport);
    dst_port = ntohs(udp_header->uh_dport);
    pkt_info->protocol = g_strdup("UDP");
    asprintf(&pkt_info->info, "%d -> %d", src_port, dst_port);
    // printf("PROTO: UDP | SPORT: %d | DPORT: %d |\n", src_port, dst_port);
    break;
  }
  case IPPROTO_ICMP:
    if (transport_len < sizeof(struct icmp)) {
      pkt_info->protocol = g_strdup("ICMP");
      pkt_info->info = g_strdup("TRUNCATED");
      break;
    }
    icmp_header = (struct icmp *)packetd_ptr;
    // int icmp_type = icmp_header->icmp_type;
    // int icmp_type_code = icmp_header->icmp_code;
    pkt_info->protocol = g_strdup("ICMP");
    asprintf(&pkt_info->info, "type=%d code=%d", icmp_header->icmp_type,
             icmp_header->icmp_code);
    // printf("PROTO: ICMP | TYPE: %d | CODE: %d |\n", icmp_type,
    // icmp_type_code);
    break;

  default:
    pkt_info->protocol = g_strdup("OTHER");
    pkt_info->info = g_strdup("");
    break;
  }

  // save
  g_async_queue_push(self->queue, pkt_info);
}

gpointer capture_thread(gpointer user_data) {
  AppSniffer *self = (AppSniffer *)user_data;
  char errbuf[PCAP_ERRBUF_SIZE];

  self->handle = pcap_open_live(self->device, BUFSIZ, 1, 100, errbuf);
  if (!self->handle) {
    g_warning("Could not open device %s: %s", self->device, errbuf);
    g_object_unref(self);
    return NULL;
  }
  struct bpf_program fp;

  if (pcap_datalink(self->handle) != DLT_EN10MB) {
    g_warning("Device %s does not support Ethernet headers", self->device);
    g_object_unref(self);
    return NULL;
  }

  if (self->filter) {
    if (pcap_compile(self->handle, &fp, self->filter, 0,
                     PCAP_NETMASK_UNKNOWN) == -1) {
      g_warning("Could not parse filter %s: %s", self->filter,
                pcap_geterr(self->handle));
      g_object_unref(self);
      return NULL;
    }
    if (pcap_setfilter(self->handle, &fp) == -1) {
      g_warning("Could not install filter %s: %s", self->filter,
                pcap_geterr(self->handle));
      g_object_unref(self);
      return NULL;
    }
  }

  pcap_loop(self->handle, -1, capture_handler, (u_char *)self);

  pcap_close(self->handle);
  self->handle = NULL;
  return NULL;
}

void app_sniffer_start(AppSniffer *self) {
  g_return_if_fail(APP_IS_SNIFFER(self));
  if (!self->thread && !self->handle) {
    self->thread = g_thread_new("capture_thread", capture_thread, self);
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

void app_sniffer_start_timer(AppSniffer *self) {
  g_timeout_add(100, update_packets_from_queue, self);
}
