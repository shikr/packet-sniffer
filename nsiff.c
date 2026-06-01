#include <net/ethernet.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <pcap/pcap.h>
#include <pthread.h>
#include <raylib.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// gcc -Wall nsiff.c -o build/monitor -lraylib -lGL -lpthread -ldl -lrt -lX11
// -lpcap

#define INFO_BUFFER_SIZE 22
#define PROTOCOL_BUFFER_SIZE 6

#define MAX_PACKETS 10
#define DEVICE "wlan0"

#define WIN_WIDTH 1920
#define WIN_HEIGHT 1080

int link_hdr_length = 0;

float scroll_list = 0;
float scroll_info = 0;
float scroll_mem = 0;
float scroll_hex = 0;

// ventanas
Rectangle Packet_list = {10, 100, 1900, 500};
Rectangle Packet_info = {10, 650, 570, 300};
Rectangle packet_raw_mem = {600, 650, 700, 300};
Rectangle packet_raw_hex = {1320, 650, 570, 300};

// funciones
void DrawPanel(Rectangle r);
void ClampScroll(float *scroll, int items, float itemHeight, float panelHeight);
void draw_packet_list();
void draw_simple_panel(Rectangle r, float scroll, const char *prefix);
void draw_titles();

typedef struct {
  int id;
  int len;
  char src_ip[INET_ADDRSTRLEN];
  char dst_ip[INET6_ADDRSTRLEN];
  int ttl;
  int tos;
  char protocol[PROTOCOL_BUFFER_SIZE];
  char info[INFO_BUFFER_SIZE];
} packet_info;

typedef struct {
  packet_info packets[MAX_PACKETS];
  int count;
  pthread_mutex_t mutex;
} packet_buffer;

packet_buffer pkt_buffer = {.count = 0};

void call_me(u_char *user, const struct pcap_pkthdr *pkthdr,
             const u_char *packetd_ptr) {
  packet_info pkt_info;
  struct ether_header *eth_hdr = (struct ether_header *)packetd_ptr;
  packetd_ptr += link_hdr_length;
  struct ip *ip_hdr = (struct ip *)packetd_ptr;

  strcpy(pkt_info.src_ip, inet_ntoa(ip_hdr->ip_src));
  strcpy(pkt_info.dst_ip, inet_ntoa(ip_hdr->ip_dst));
  pkt_info.id = ntohs(ip_hdr->ip_id);
  pkt_info.ttl = ip_hdr->ip_ttl;
  pkt_info.tos = ip_hdr->ip_tos;
  pkt_info.len = ntohs(ip_hdr->ip_len);

  int packet_hlen = ip_hdr->ip_hl;

  packetd_ptr += 4 * packet_hlen;
  int protocol_type = ip_hdr->ip_p;

  struct tcphdr *tcp_header;
  struct udphdr *udp_header;
  struct icmp *icmp_header;
  // int src_port, dst_port;

  // printf("************************************"
  //        "**************************************\n");
  // printf("ID: %d | SRC: %s | DST: %s | TOS: 0x%x | TTL: %d\n", pkt_info.id,
  //        pkt_info.src_ip, pkt_info.dst_ip, pkt_info.tos, pkt_info.ttl);

  switch (protocol_type) {
  case IPPROTO_TCP:
    tcp_header = (struct tcphdr *)packetd_ptr;
    // src_port = tcp_header->th_sport;
    // dst_port = tcp_header->th_dport;
    strcpy(pkt_info.protocol, "TCP");
    snprintf(pkt_info.info, INFO_BUFFER_SIZE, "FLAGS: %c/%c/%c",
             (tcp_header->th_flags & TH_SYN ? 'S' : '-'),
             (tcp_header->th_flags & TH_ACK ? 'A' : '-'),
             (tcp_header->th_flags & TH_URG ? 'U' : '-'));
    // printf("PROTO: TCP | FLAGS: %c/%c/%c | SPORT: %d | DPORT: %d |\n",
    //        (tcp_header->th_flags & TH_SYN ? 'S' : '-'),
    //        (tcp_header->th_flags & TH_ACK ? 'A' : '-'),
    //        (tcp_header->th_flags & TH_URG ? 'U' : '-'), src_port, dst_port);
    break;
  case IPPROTO_UDP:
    udp_header = (struct udphdr *)packetd_ptr;
    // src_port = udp_header->uh_sport;
    // dst_port = udp_header->uh_dport;
    strcpy(pkt_info.protocol, "UDP");
    snprintf(pkt_info.info, INFO_BUFFER_SIZE, "SPORT: %d | DPORT: %d",
             udp_header->uh_sport, udp_header->uh_dport);
    // printf("PROTO: UDP | SPORT: %d | DPORT: %d |\n", src_port, dst_port);
    break;
  case IPPROTO_ICMP:
    icmp_header = (struct icmp *)packetd_ptr;
    // int icmp_type = icmp_header->icmp_type;
    // int icmp_type_code = icmp_header->icmp_code;
    strcpy(pkt_info.protocol, "ICMP");
    snprintf(pkt_info.info, INFO_BUFFER_SIZE, "TYPE: %d | CODE: %d",
             icmp_header->icmp_type, icmp_header->icmp_code);
    // printf("PROTO: ICMP | TYPE: %d | CODE: %d |\n", icmp_type,
    // icmp_type_code);
    break;

  default:
    goto end;
  }

  pthread_mutex_lock(&pkt_buffer.mutex);
  if (pkt_buffer.count < MAX_PACKETS) {
    pkt_buffer.packets[pkt_buffer.count++] = pkt_info;
  }
  pthread_mutex_unlock(&pkt_buffer.mutex);

end:;
}

void *capture_thread(void *arg) {
  pcap_t *handle = (pcap_t *)arg;
  pcap_loop(handle, MAX_PACKETS, call_me, NULL);
  return NULL;
}

int main(int argc, char **argv) {
  char error_buffer[PCAP_ERRBUF_SIZE];

  pcap_t *capdev = pcap_open_live(DEVICE, BUFSIZ, 0, -1, error_buffer);

  if (capdev == NULL) {
    printf("ERR: pcap_open_live() %s\n", error_buffer);
    exit(1);
  }

  struct bpf_program bpf;
  bpf_u_int32 netmask;

  if (argc > 1) {
    if (pcap_compile(capdev, &bpf, argv[1], 0, netmask) == PCAP_ERROR) {
      printf("ERR: pcap_compile() %s", pcap_geterr(capdev));
      // exit(1);
    }

    if (pcap_setfilter(capdev, &bpf) == PCAP_ERROR) {
      printf("ERR: pcap_setfilter() %s", pcap_geterr(capdev));
      // exit(1);
    }
  }

  int link_hdr_type = pcap_datalink(capdev);

  switch (link_hdr_type) {
  case DLT_NULL:
    link_hdr_length = 4;
    break;
  case DLT_EN10MB:
    link_hdr_length = 14;
    break;
  default:
    link_hdr_length = 0;
  }

  pthread_mutex_init(&pkt_buffer.mutex, NULL);
  pthread_t thread_id;
  pthread_create(&thread_id, NULL, capture_thread, (void *)capdev);

  InitWindow(WIN_WIDTH, WIN_HEIGHT, "Packet Sniffer");
  SetTargetFPS(60);

  while (!WindowShouldClose()) {
    Vector2 mouse = GetMousePosition();
    float wheel = GetMouseWheelMove() * 20;

    // scroll solo si el raton esta encima
    if (CheckCollisionPointRec(mouse, Packet_list)) {
      scroll_list += wheel;
    }
    if (CheckCollisionPointRec(mouse, Packet_info)) {
      scroll_info += wheel;
    }
    if (CheckCollisionPointRec(mouse, packet_raw_mem)) {
      scroll_mem += wheel;
    }
    if (CheckCollisionPointRec(mouse, packet_raw_hex)) {
      scroll_hex += wheel;
    }

    pthread_mutex_lock(&pkt_buffer.mutex);
    // limitar el scroll
    ClampScroll(&scroll_list, pkt_buffer.count, 30, Packet_list.height);
    ClampScroll(&scroll_info, 20, 25, Packet_info.height);
    ClampScroll(&scroll_mem, 20, 25, packet_raw_mem.height);
    ClampScroll(&scroll_hex, 20, 25, packet_raw_hex.height);

    // dibujar ventanitas
    BeginDrawing();
    ClearBackground(BLACK);

    draw_titles();

    draw_packet_list();
    draw_simple_panel(Packet_info, scroll_info, "-INFO");
    draw_simple_panel(packet_raw_mem, scroll_mem, "-MEM");
    draw_simple_panel(packet_raw_hex, scroll_hex, "-HEX");

    pthread_mutex_unlock(&pkt_buffer.mutex);

    EndDrawing();
  }

  pcap_breakloop(capdev);
  pthread_join(thread_id, NULL);
  pcap_close(capdev);
  pthread_mutex_destroy(&pkt_buffer.mutex);

  return 0;
}

void DrawPanel(Rectangle r) { DrawRectangleLinesEx(r, 1, GREEN); }

void ClampScroll(float *scroll, int items, float itemHeight,
                 float panelHeight) {
  float maxScroll = (items * itemHeight) - panelHeight;
  if (maxScroll < 0) {
    maxScroll = 0;
  }
  if (*scroll > 0) {
    *scroll = 0;
  }
  if (*scroll < -maxScroll) {
    *scroll = -maxScroll;
  }
}

void draw_packet_list() {
  DrawPanel(Packet_list);
  BeginScissorMode(Packet_list.x, Packet_list.y, Packet_list.width,
                   Packet_list.height);

  float itemHeight = 30;

  for (size_t i = 0; i < pkt_buffer.count; i++) {
    char buffer[256];
    snprintf(buffer, sizeof(buffer), "%d   %s   %s   %s   %d   %s",
             pkt_buffer.packets[i].id, pkt_buffer.packets[i].src_ip,
             pkt_buffer.packets[i].dst_ip, pkt_buffer.packets[i].protocol,
             pkt_buffer.packets[i].len, pkt_buffer.packets[i].info);

    DrawText(buffer, Packet_list.x + 10,
             Packet_list.y + 10 + i * itemHeight + scroll_list, 18, GREEN);
  }

  EndScissorMode();
}

void draw_simple_panel(Rectangle r, float scroll, const char *prefix) {
  DrawPanel(r);
  BeginScissorMode(r.x, r.y, r.width, r.height);

  for (int i = 0; i < 20; i++) {
    char buffer[64];
    snprintf(buffer, sizeof(buffer), "%s %d", prefix, i);

    DrawText(buffer, r.x + 10, r.y + 10 + i * 25 + scroll, 18, GREEN);
  }

  EndScissorMode();
}

void draw_titles() {
  const char *titles[] = {"No",       "SOURCE", "DESTINATION",
                          "PROTOCOL", "LENGTH", "INFO"};

  int x = 20;
  for (int i = 0; i < 6; i++) {
    DrawText(titles[i], x, 80, 20, GREEN);
    x += 275;
  }
}
