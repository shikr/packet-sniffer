#include "capture.h"
#include "packet_info.h"
#include "proto_node.h"
#include "sniffer.h"
#include <arpa/inet.h>
#include <glib.h>
#include <net/ethernet.h>
#include <netinet/icmp6.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/ip_icmp.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <string.h>

// --- Helpers ---

static ProtoNode *parse_ethernet(const u_char *data, guint len,
                                 guint16 *eth_type_out);
static ProtoNode *parse_ipv4(const u_char *data, guint len, guint8 *proto_out,
                             guint *ip_hlen_out, char *src_out, char *dst_out,
                             char *proto_str_out);
static ProtoNode *parse_ipv6(const u_char *data, guint len, guint8 *proto_out,
                             char *src_out, char *dst_out, char *proto_str_out);
static ProtoNode *parse_tcp(const u_char *data, guint len, char *info_out);
static ProtoNode *parse_udp(const u_char *data, guint len, char *info_out);
static ProtoNode *parse_icmp(const u_char *data, guint len, char *info_out);
static ProtoNode *parse_icmp6(const u_char *data, guint len, char *info_out);
static ProtoNode *parse_dns(const u_char *data, guint len, char *info_out);
static ProtoNode *parse_http(const u_char *data, guint len, char *info_out);
static ProtoNode *parse_arp(const u_char *data, guint len, char *info_out);

static const char *tcp_flags_str(u_int8_t flags, char *buf, gsize buf_size) {
  g_snprintf(buf, buf_size, "%s%s%s%s%s%s", flags & TH_SYN ? "SYN " : "",
             flags & TH_ACK ? "ACK " : "", flags & TH_FIN ? "FIN " : "",
             flags & TH_RST ? "RST " : "", flags & TH_PUSH ? "PSH " : "",
             flags & TH_URG ? "URG " : "");
  // quitar espacio final
  gsize l = strlen(buf);
  if (l > 0 && buf[l - 1] == ' ')
    buf[l - 1] = '\0';
  return buf;
}

static const char *icmp_type_str(guint8 type) {
  switch (type) {
  case ICMP_ECHO:
    return "Echo Request";
  case ICMP_ECHOREPLY:
    return "Echo Reply";
  case ICMP_DEST_UNREACH:
    return "Destination Unreachable";
  case ICMP_TIME_EXCEEDED:
    return "Time Exceeded";
  case ICMP_REDIRECT:
    return "Redirect";
  default:
    return "Unknown";
  }
}

static const char *icmp6_type_str(guint8 type) {
  switch (type) {
  case ICMP6_ECHO_REQUEST:
    return "Echo Request";
  case ICMP6_ECHO_REPLY:
    return "Echo Reply";
  case ND_NEIGHBOR_SOLICIT:
    return "Neighbor Solicitation";
  case ND_NEIGHBOR_ADVERT:
    return "Neighbor Advertisement";
  case ND_ROUTER_SOLICIT:
    return "Router Solicitation";
  case ND_ROUTER_ADVERT:
    return "Router Advertisement";
  case ICMP6_DST_UNREACH:
    return "Destination Unreachable";
  case ICMP6_TIME_EXCEEDED:
    return "Time Exceeded";
  default:
    return "Unknown";
  }
}

// --- Parsers ---

static ProtoNode *parse_ethernet(const u_char *data, guint len,
                                 guint16 *eth_type_out) {
  if (len < sizeof(struct ether_header))
    return NULL;
  const struct ether_header *eth = (const struct ether_header *)data;

  guint16 eth_type = ntohs(eth->ether_type);
  if (eth_type_out)
    *eth_type_out = eth_type;

  ProtoNode *node = proto_node_new("Ethernet II");

  proto_node_add_child(
      node, g_strdup_printf("Dst: %02x:%02x:%02x:%02x:%02x:%02x",
                            eth->ether_dhost[0], eth->ether_dhost[1],
                            eth->ether_dhost[2], eth->ether_dhost[3],
                            eth->ether_dhost[4], eth->ether_dhost[5]));
  proto_node_add_child(
      node, g_strdup_printf("Src: %02x:%02x:%02x:%02x:%02x:%02x",
                            eth->ether_shost[0], eth->ether_shost[1],
                            eth->ether_shost[2], eth->ether_shost[3],
                            eth->ether_shost[4], eth->ether_shost[5]));
  proto_node_add_child(
      node, g_strdup_printf("Type: 0x%04x (%s)", eth_type,
                            eth_type == ETHERTYPE_IP     ? "IPv4"
                            : eth_type == ETHERTYPE_IPV6 ? "IPv6"
                            : eth_type == ETHERTYPE_ARP  ? "ARP"
                                                         : "Unknown"));

  return node;
}

static ProtoNode *parse_arp(const u_char *data, guint len, char *info_out) {
  // ARP header mínimo: 28 bytes para IPv4
  if (len < 28)
    return NULL;

  guint16 op = ntohs(*(guint16 *)(data + 6));
  char sender_ip[INET_ADDRSTRLEN], target_ip[INET_ADDRSTRLEN];
  inet_ntop(AF_INET, data + 14, sender_ip, sizeof(sender_ip));
  inet_ntop(AF_INET, data + 24, target_ip, sizeof(target_ip));

  const u_char *sender_mac = data + 8;
  const u_char *target_mac = data + 18;

  if (info_out)
    g_snprintf(info_out, 128, "%s %s -> %s", op == 1 ? "Who has" : "Reply",
               sender_ip, target_ip);

  ProtoNode *node = proto_node_new("Address Resolution Protocol");
  proto_node_add_child(
      node,
      g_strdup_printf("Operation: %s (%d)", op == 1 ? "Request" : "Reply", op));
  proto_node_add_child(
      node, g_strdup_printf("Sender MAC: %02x:%02x:%02x:%02x:%02x:%02x",
                            sender_mac[0], sender_mac[1], sender_mac[2],
                            sender_mac[3], sender_mac[4], sender_mac[5]));
  proto_node_add_child(node, g_strdup_printf("Sender IP: %s", sender_ip));
  proto_node_add_child(
      node, g_strdup_printf("Target MAC: %02x:%02x:%02x:%02x:%02x:%02x",
                            target_mac[0], target_mac[1], target_mac[2],
                            target_mac[3], target_mac[4], target_mac[5]));
  proto_node_add_child(node, g_strdup_printf("Target IP: %s", target_ip));

  return node;
}

static ProtoNode *parse_ipv4(const u_char *data, guint len, guint8 *proto_out,
                             guint *ip_hlen_out, char *src_out, char *dst_out,
                             char *proto_str_out) {
  if (len < sizeof(struct ip))
    return NULL;
  const struct ip *iph = (const struct ip *)data;

  guint hlen = iph->ip_hl * 4;
  if (hlen < 20 || len < hlen)
    return NULL;

  char src[INET_ADDRSTRLEN], dst[INET_ADDRSTRLEN];
  inet_ntop(AF_INET, &iph->ip_src, src, sizeof(src));
  inet_ntop(AF_INET, &iph->ip_dst, dst, sizeof(dst));

  if (src_out)
    g_strlcpy(src_out, src, INET_ADDRSTRLEN);
  if (dst_out)
    g_strlcpy(dst_out, dst, INET_ADDRSTRLEN);
  if (proto_out)
    *proto_out = iph->ip_p;
  if (ip_hlen_out)
    *ip_hlen_out = hlen;

  const char *proto_name = iph->ip_p == IPPROTO_TCP    ? "TCP"
                           : iph->ip_p == IPPROTO_UDP  ? "UDP"
                           : iph->ip_p == IPPROTO_ICMP ? "ICMP"
                                                       : "Other";
  if (proto_str_out)
    g_strlcpy(proto_str_out, proto_name, 16);

  ProtoNode *node = proto_node_new("Internet Protocol Version 4");
  proto_node_add_child(node, g_strdup_printf("Version: 4"));
  proto_node_add_child(node, g_strdup_printf("Header length: %u bytes", hlen));
  proto_node_add_child(node, g_strdup_printf("TOS: 0x%02x", iph->ip_tos));
  proto_node_add_child(node,
                       g_strdup_printf("Total length: %u", ntohs(iph->ip_len)));
  proto_node_add_child(
      node,
      g_strdup_printf("ID: 0x%04x (%u)", ntohs(iph->ip_id), ntohs(iph->ip_id)));
  proto_node_add_child(
      node,
      g_strdup_printf("Flags: %s%s", ntohs(iph->ip_off) & IP_DF ? "DF " : "",
                      ntohs(iph->ip_off) & IP_MF ? "MF " : ""));
  proto_node_add_child(node, g_strdup_printf("Fragment offset: %u",
                                             ntohs(iph->ip_off) & IP_OFFMASK));
  proto_node_add_child(node, g_strdup_printf("TTL: %u", iph->ip_ttl));
  proto_node_add_child(
      node, g_strdup_printf("Protocol: %s (%u)", proto_name, iph->ip_p));
  proto_node_add_child(node,
                       g_strdup_printf("Checksum: 0x%04x", ntohs(iph->ip_sum)));
  proto_node_add_child(node, g_strdup_printf("Src: %s", src));
  proto_node_add_child(node, g_strdup_printf("Dst: %s", dst));

  return node;
}

static ProtoNode *parse_ipv6(const u_char *data, guint len, guint8 *proto_out,
                             char *src_out, char *dst_out,
                             char *proto_str_out) {
  if (len < sizeof(struct ip6_hdr))
    return NULL;
  const struct ip6_hdr *ip6 = (const struct ip6_hdr *)data;

  char src[INET6_ADDRSTRLEN], dst[INET6_ADDRSTRLEN];
  inet_ntop(AF_INET6, &ip6->ip6_src, src, sizeof(src));
  inet_ntop(AF_INET6, &ip6->ip6_dst, dst, sizeof(dst));

  if (src_out)
    g_strlcpy(src_out, src, INET6_ADDRSTRLEN);
  if (dst_out)
    g_strlcpy(dst_out, dst, INET6_ADDRSTRLEN);
  if (proto_out)
    *proto_out = ip6->ip6_nxt;

  const char *proto_name = ip6->ip6_nxt == IPPROTO_TCP      ? "TCP"
                           : ip6->ip6_nxt == IPPROTO_UDP    ? "UDP"
                           : ip6->ip6_nxt == IPPROTO_ICMPV6 ? "ICMPv6"
                                                            : "Other";
  if (proto_str_out)
    g_strlcpy(proto_str_out, proto_name, 16);

  guint32 flow = ntohl(ip6->ip6_flow);

  ProtoNode *node = proto_node_new("Internet Protocol Version 6");
  proto_node_add_child(node, g_strdup_printf("Version: 6"));
  proto_node_add_child(
      node, g_strdup_printf("Traffic class: 0x%02x", (flow >> 20) & 0xff));
  proto_node_add_child(node,
                       g_strdup_printf("Flow label: 0x%05x", flow & 0xfffff));
  proto_node_add_child(
      node, g_strdup_printf("Payload length: %u", ntohs(ip6->ip6_plen)));
  proto_node_add_child(
      node, g_strdup_printf("Next header: %s (%u)", proto_name, ip6->ip6_nxt));
  proto_node_add_child(node, g_strdup_printf("Hop limit: %u", ip6->ip6_hlim));
  proto_node_add_child(node, g_strdup_printf("Src: %s", src));
  proto_node_add_child(node, g_strdup_printf("Dst: %s", dst));

  return node;
}

static ProtoNode *parse_tcp(const u_char *data, guint len, char *info_out) {
  if (len < sizeof(struct tcphdr))
    return NULL;
  const struct tcphdr *tcp = (const struct tcphdr *)data;

  guint16 sport = ntohs(tcp->th_sport);
  guint16 dport = ntohs(tcp->th_dport);
  guint hlen = tcp->th_off * 4;
  char flags_str[32];
  tcp_flags_str(tcp->th_flags, flags_str, sizeof(flags_str));

  if (info_out)
    g_snprintf(info_out, 128, "%u → %u [%s] Seq=%u Ack=%u Win=%u", sport, dport,
               flags_str, ntohl(tcp->th_seq), ntohl(tcp->th_ack),
               ntohs(tcp->th_win));

  ProtoNode *node = proto_node_new("Transmission Control Protocol");
  proto_node_add_child(node, g_strdup_printf("Src port: %u", sport));
  proto_node_add_child(node, g_strdup_printf("Dst port: %u", dport));
  proto_node_add_child(node, g_strdup_printf("Seq: %u", ntohl(tcp->th_seq)));
  proto_node_add_child(node, g_strdup_printf("Ack: %u", ntohl(tcp->th_ack)));
  proto_node_add_child(node, g_strdup_printf("Header length: %u bytes", hlen));
  proto_node_add_child(
      node, g_strdup_printf("Flags: %s (0x%02x)", flags_str, tcp->th_flags));
  proto_node_add_child(node, g_strdup_printf("Window: %u", ntohs(tcp->th_win)));
  proto_node_add_child(node,
                       g_strdup_printf("Checksum: 0x%04x", ntohs(tcp->th_sum)));
  proto_node_add_child(
      node, g_strdup_printf("Urgent pointer: %u", ntohs(tcp->th_urp)));

  // Payload
  guint payload_len = len - hlen;
  if (hlen <= len && payload_len > 0)
    proto_node_add_child(node,
                         g_strdup_printf("Payload: %u bytes", payload_len));

  return node;
}

static ProtoNode *parse_udp(const u_char *data, guint len, char *info_out) {
  if (len < sizeof(struct udphdr))
    return NULL;
  const struct udphdr *udp = (const struct udphdr *)data;

  guint16 sport = ntohs(udp->uh_sport);
  guint16 dport = ntohs(udp->uh_dport);
  guint16 ulen = ntohs(udp->uh_ulen);

  if (info_out)
    g_snprintf(info_out, 128, "%u → %u Len=%u", sport, dport, ulen);

  ProtoNode *node = proto_node_new("User Datagram Protocol");
  proto_node_add_child(node, g_strdup_printf("Src port: %u", sport));
  proto_node_add_child(node, g_strdup_printf("Dst port: %u", dport));
  proto_node_add_child(node, g_strdup_printf("Length: %u", ulen));
  proto_node_add_child(node,
                       g_strdup_printf("Checksum: 0x%04x", ntohs(udp->uh_sum)));

  guint payload_len = ulen > 8 ? ulen - 8 : 0;
  if (payload_len > 0)
    proto_node_add_child(node,
                         g_strdup_printf("Payload: %u bytes", payload_len));

  return node;
}

static ProtoNode *parse_icmp(const u_char *data, guint len, char *info_out) {
  if (len < sizeof(struct icmp))
    return NULL;
  const struct icmp *icmp = (const struct icmp *)data;

  if (info_out)
    g_snprintf(info_out, 128, "%s (type=%u code=%u)",
               icmp_type_str(icmp->icmp_type), icmp->icmp_type,
               icmp->icmp_code);

  ProtoNode *node = proto_node_new("Internet Control Message Protocol");
  proto_node_add_child(node, g_strdup_printf("Type: %u (%s)", icmp->icmp_type,
                                             icmp_type_str(icmp->icmp_type)));
  proto_node_add_child(node, g_strdup_printf("Code: %u", icmp->icmp_code));
  proto_node_add_child(
      node, g_strdup_printf("Checksum: 0x%04x", ntohs(icmp->icmp_cksum)));

  if (icmp->icmp_type == ICMP_ECHO || icmp->icmp_type == ICMP_ECHOREPLY) {
    proto_node_add_child(node, g_strdup_printf("ID: %u", ntohs(icmp->icmp_id)));
    proto_node_add_child(node,
                         g_strdup_printf("Seq: %u", ntohs(icmp->icmp_seq)));
  }

  return node;
}

static ProtoNode *parse_icmp6(const u_char *data, guint len, char *info_out) {
  if (len < sizeof(struct icmp6_hdr))
    return NULL;
  const struct icmp6_hdr *icmp6 = (const struct icmp6_hdr *)data;

  if (info_out)
    g_snprintf(info_out, 128, "%s (type=%u code=%u)",
               icmp6_type_str(icmp6->icmp6_type), icmp6->icmp6_type,
               icmp6->icmp6_code);

  ProtoNode *node = proto_node_new("Internet Control Message Protocol v6");
  proto_node_add_child(node,
                       g_strdup_printf("Type: %u (%s)", icmp6->icmp6_type,
                                       icmp6_type_str(icmp6->icmp6_type)));
  proto_node_add_child(node, g_strdup_printf("Code: %u", icmp6->icmp6_code));
  proto_node_add_child(
      node, g_strdup_printf("Checksum: 0x%04x", ntohs(icmp6->icmp6_cksum)));

  if (icmp6->icmp6_type == ICMP6_ECHO_REQUEST ||
      icmp6->icmp6_type == ICMP6_ECHO_REPLY) {
    proto_node_add_child(node,
                         g_strdup_printf("ID: %u", ntohs(icmp6->icmp6_id)));
    proto_node_add_child(node,
                         g_strdup_printf("Seq: %u", ntohs(icmp6->icmp6_seq)));
  }

  return node;
}

static ProtoNode *parse_dns(const u_char *data, guint len, char *info_out) {
  if (len < 12)
    return NULL;

  guint16 id = ntohs(*(guint16 *)(data + 0));
  guint16 flags = ntohs(*(guint16 *)(data + 2));
  guint16 qdcount = ntohs(*(guint16 *)(data + 4));
  guint16 ancount = ntohs(*(guint16 *)(data + 6));
  gboolean is_response = (flags >> 15) & 1;

  if (info_out)
    g_snprintf(info_out, 128, "%s id=0x%04x questions=%u answers=%u",
               is_response ? "Response" : "Query", id, qdcount, ancount);

  ProtoNode *node = proto_node_new("Domain Name System");
  proto_node_add_child(node, g_strdup_printf("ID: 0x%04x", id));
  proto_node_add_child(
      node, g_strdup_printf("Type: %s", is_response ? "Response" : "Query"));
  proto_node_add_child(node, g_strdup_printf("Questions: %u", qdcount));
  proto_node_add_child(node, g_strdup_printf("Answer RRs: %u", ancount));
  proto_node_add_child(node, g_strdup_printf("Authority RRs: %u",
                                             ntohs(*(guint16 *)(data + 8))));
  proto_node_add_child(node, g_strdup_printf("Additional RRs: %u",
                                             ntohs(*(guint16 *)(data + 10))));
  return node;
}

static ProtoNode *parse_http(const u_char *data, guint len, char *info_out) {
  if (len == 0)
    return NULL;

  // Verificar que sea texto HTTP
  const char *text = (const char *)data;
  gboolean is_http =
      g_str_has_prefix(text, "GET ") || g_str_has_prefix(text, "POST ") ||
      g_str_has_prefix(text, "PUT ") || g_str_has_prefix(text, "DELETE ") ||
      g_str_has_prefix(text, "HEAD ") || g_str_has_prefix(text, "HTTP/");

  if (!is_http)
    return NULL;

  // Extraer primera línea
  char first_line[256] = {0};
  const char *newline = memchr(text, '\n', MIN(len, 256));
  gsize line_len = newline ? (gsize)(newline - text) : MIN(len, 255);
  memcpy(first_line, text, line_len);
  first_line[line_len] = '\0';
  // quitar \r si existe
  if (line_len > 0 && first_line[line_len - 1] == '\r')
    first_line[line_len - 1] = '\0';

  if (info_out)
    g_snprintf(info_out, 128, "%s", first_line);

  ProtoNode *node = proto_node_new("Hypertext Transfer Protocol");
  proto_node_add_child(node, g_strdup(first_line));

  return node;
}

// --- Handler principal ---

void capture_handler(u_char *user, const struct pcap_pkthdr *pkthdr,
                     const u_char *packet_ptr) {
  AppSniffer *self = (AppSniffer *)user;
  const guint caplen = pkthdr->caplen;
  const u_char *ptr = packet_ptr;
  const guint ETH_LEN = sizeof(struct ether_header);

  if (caplen < ETH_LEN)
    return;

  // --- Tiempo relativo ---
  app_sniffer_check_time(self, pkthdr->ts);

  gdouble time_rel = app_sniffer_get_relative_time(self, &pkthdr->ts);

  // --- PacketInfo ---
  PacketInfo *pkt = g_new0(PacketInfo, 1);
  pkt->time = time_rel;
  pkt->len = pkthdr->len;
  pkt->raw_len = caplen;
  pkt->raw = g_memdup2(packet_ptr, caplen);
  pkt->layers = g_ptr_array_new_with_free_func((GDestroyNotify)proto_node_free);

  char src[INET6_ADDRSTRLEN] = "N/A";
  char dst[INET6_ADDRSTRLEN] = "N/A";
  char proto_str[16] = "ETH";
  char info[128] = "";

  // --- Ethernet ---
  guint16 eth_type = 0;
  ProtoNode *eth_node = parse_ethernet(ptr, caplen, &eth_type);
  if (!eth_node)
    goto done;
  g_ptr_array_add(pkt->layers, eth_node);
  ptr += ETH_LEN;
  guint remaining = caplen - ETH_LEN;

  // --- Capa de red ---
  guint8 transport_proto = 0;
  guint net_hlen = 0;

  if (eth_type == ETHERTYPE_IP) {
    ProtoNode *ip_node = parse_ipv4(ptr, remaining, &transport_proto, &net_hlen,
                                    src, dst, proto_str);
    if (!ip_node)
      goto done;
    g_ptr_array_add(pkt->layers, ip_node);
    ptr += net_hlen;
    remaining -= net_hlen;

  } else if (eth_type == ETHERTYPE_IPV6) {
    ProtoNode *ip6_node =
        parse_ipv6(ptr, remaining, &transport_proto, src, dst, proto_str);
    if (!ip6_node)
      goto done;
    g_ptr_array_add(pkt->layers, ip6_node);
    net_hlen = sizeof(struct ip6_hdr);
    ptr += net_hlen;
    remaining -= net_hlen;

  } else if (eth_type == ETHERTYPE_ARP) {
    g_strlcpy(proto_str, "ARP", sizeof(proto_str));
    ProtoNode *arp_node = parse_arp(ptr, remaining, info);
    if (arp_node)
      g_ptr_array_add(pkt->layers, arp_node);
    goto done;

  } else {
    g_snprintf(proto_str, sizeof(proto_str), "0x%04x", eth_type);
    goto done;
  }

  // --- Capa de transporte ---
  ProtoNode *transport_node = NULL;

  switch (transport_proto) {
  case IPPROTO_TCP: {
    if (remaining < sizeof(struct tcphdr))
      break;
    transport_node = parse_tcp(ptr, remaining, info);
    if (!transport_node)
      break;
    g_ptr_array_add(pkt->layers, transport_node);

    // Payload TCP
    const struct tcphdr *tcp = (const struct tcphdr *)ptr;
    guint tcp_hlen = tcp->th_off * 4;
    guint payload_len = remaining > tcp_hlen ? remaining - tcp_hlen : 0;

    if (payload_len > 0) {
      const u_char *payload = ptr + tcp_hlen;
      guint16 dport = ntohs(tcp->th_dport);
      guint16 sport = ntohs(tcp->th_sport);

      // HTTP
      if (dport == 80 || sport == 80 || dport == 8080 || sport == 8080) {
        ProtoNode *http = parse_http(payload, payload_len, info);
        if (http) {
          g_strlcpy(proto_str, "HTTP", sizeof(proto_str));
          g_ptr_array_add(pkt->layers, http);
        }
      }
    }
    break;
  }

  case IPPROTO_UDP: {
    if (remaining < sizeof(struct udphdr))
      break;
    transport_node = parse_udp(ptr, remaining, info);
    if (!transport_node)
      break;
    g_ptr_array_add(pkt->layers, transport_node);

    const struct udphdr *udp = (const struct udphdr *)ptr;
    guint16 dport = ntohs(udp->uh_dport);
    guint16 sport = ntohs(udp->uh_sport);
    guint payload_len = remaining > 8 ? remaining - 8 : 0;

    if (payload_len > 0) {
      const u_char *payload = ptr + sizeof(struct udphdr);

      // DNS
      if (dport == 53 || sport == 53) {
        ProtoNode *dns = parse_dns(payload, payload_len, info);
        if (dns) {
          g_strlcpy(proto_str, "DNS", sizeof(proto_str));
          g_ptr_array_add(pkt->layers, dns);
        }
      }
    }
    break;
  }

  case IPPROTO_ICMP: {
    ProtoNode *icmp_node = parse_icmp(ptr, remaining, info);
    if (icmp_node)
      g_ptr_array_add(pkt->layers, icmp_node);
    break;
  }

  case IPPROTO_ICMPV6: {
    ProtoNode *icmp6_node = parse_icmp6(ptr, remaining, info);
    if (icmp6_node)
      g_ptr_array_add(pkt->layers, icmp6_node);
    break;
  }

  default:
    g_snprintf(info, sizeof(info), "Protocol %u", transport_proto);
    break;
  }

done:
  pkt->src = g_strdup(src);
  pkt->dst = g_strdup(dst);
  pkt->protocol = g_strdup(proto_str);
  pkt->info = g_strdup(info);

  app_sniffer_queue_packet(self, pkt);
}
