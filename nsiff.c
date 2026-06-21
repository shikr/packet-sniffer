#define _DEFAULT_SOURCE

#include <arpa/inet.h>
#include <ctype.h>
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
#include <time.h>

//gcc -Wall -Wextra nsiff.c -o sniff -lraylib -lpcap -lGL -lm -lpthread -ldl -lrt -lX11
//sudo setcap cap_net_raw=+ep ./sniff
//./sniff
#define MAX_DEVICES 32 //Para enlistar los adaptadores

#define INFO_BUFFER_SIZE 64
#define PROTOCOL_BUFFER_SIZE 8
#define RAW_BUFFER_SIZE 1024

#define MAX_PACKETS 1024
#define DEVICE "wlo1" // wlan0

#define WIN_WIDTH 1920
#define WIN_HEIGHT 1080

int link_hdr_length = 0;
int packet_counter = 0;
struct timeval first_ts;
int have_first_ts = 0;

float scroll_list = 0;
float scroll_info = 0;
float scroll_mem = 0;
float scroll_hex = 0;

int auto_scroll_list = 1;
int selected_index = -1;
char filter_buf[256] = "";
int filter_active = 0;
int capture_paused = 0;

// ventanas
Rectangle Btn_stop = {520, 42, 80, 28};
Rectangle Btn_save = {612, 42, 110, 28};
Rectangle Btn_live = {734, 42, 55, 28};
Rectangle Packet_list = {10, 120, 1900, 500};
Rectangle Packet_info = {10, 650, 570, 300};
Rectangle packet_raw_mem = {600, 650, 700, 300};
Rectangle packet_raw_hex = {1320, 650, 570, 300};
Rectangle Filter_input = {100, 42, 400, 28};

typedef struct packet_info packet_info;

// funciones
void DrawPanel(Rectangle r);
void ClampScroll(float *scroll, int items, float itemHeight, float panelHeight);
void draw_packet_list();
void draw_info_panel();
void draw_mem_panel();
void draw_hex_panel();
void draw_filter_input();
void draw_buttons();
void draw_button(Rectangle button, const char *text, Color border_color,Color text_color, int text_x_offset);
void draw_titles();
void save_to_file();
int filter_match(const packet_info *pkt);
int count_filtered();
void copy_lower(char *dst, const char *src, size_t dst_size);
int contains_text(const char *text, const char *query);
void *capture_thread(void *arg);
void guardarArchivo();
void start_capture_session(pcap_t **capdev, pthread_t *thread_id, const char *device_name);




struct packet_info
{
  char src_mac[18];
  char dts_mac[18];
  int no;
  int id;
  float time;
  int len;
  char src_ip[INET_ADDRSTRLEN];
  char dst_ip[INET_ADDRSTRLEN];
  int ttl;
  int tos;
  char protocol[PROTOCOL_BUFFER_SIZE];
  char info[INFO_BUFFER_SIZE];
  int raw_len;
  __u_char raw[RAW_BUFFER_SIZE];

  //TCP
  char flags[3];
  uint32_t seq_num; 
  uint32_t ack_num; 
  uint16_t win_size;

  //UDP
  uint16_t payload;
  uint16_t check;

  //ICMP
  uint8_t type;
  uint8_t code;
  //uint16_t id;

};

typedef struct
{
  packet_info packets[MAX_PACKETS];
  int count;
  pthread_mutex_t mutex;
} packet_buffer;

typedef enum {
    STATE_SELECT_DEVICE,
    STATE_SNIFFING
} AppState;

AppState current_state = STATE_SELECT_DEVICE;
char selected_device_name[64] = "";

typedef struct {
    char names[MAX_DEVICES][64];
    int count;
} DeviceList;

DeviceList get_available_devices(void);
void handle_device_selection_clicks(Vector2 mouse, DeviceList list, pcap_t **capdev, pthread_t *thread_id);
void draw_device_selection_screen(DeviceList list);



packet_buffer pkt_buffer = {.count = 0};

//-------------------------------------------------------------------------------------------------------------------//
int main(int argc, char **argv)
{
 

  char error_buffer[PCAP_ERRBUF_SIZE];

  pcap_t *capdev = NULL;// Se inicializa despues de seleccionar el dispositivo // el -1 lleva el consumo del procesador a 100%
    pthread_t thread_id=0;

  /*
 
*/
  struct bpf_program bpf;
  bpf_u_int32 netmask = 0;
  bpf_u_int32 netp = 0;

  if (argc > 1)
  {
    if (pcap_lookupnet(DEVICE, &netp, &netmask, error_buffer) == PCAP_ERROR)
    {
      netmask = 0;
    }

    if (pcap_compile(capdev, &bpf, argv[1], 0, netmask) == PCAP_ERROR)
    {
      printf("ERR: pcap_compile() %s", pcap_geterr(capdev));
      // exit(1);
    }
    else
    {
      if (pcap_setfilter(capdev, &bpf) == PCAP_ERROR)
      {
        printf("ERR: pcap_setfilter() %s", pcap_geterr(capdev));
        // exit(1);
      }
      pcap_freecode(&bpf);
    }
  }


  pthread_mutex_init(&pkt_buffer.mutex, NULL);
  

  InitWindow(WIN_WIDTH, WIN_HEIGHT, "Packet Sniffer");
  SetTargetFPS(20);

  int last_packet_count = 0;

  DeviceList dev_list = get_available_devices(); 
    current_state = STATE_SELECT_DEVICE;

  while (!WindowShouldClose())
  {
    Vector2 mouse = GetMousePosition();

     if (current_state == STATE_SELECT_DEVICE) {
        Vector2 mouse = GetMousePosition();

    if (IsMouseButtonPressed(MOUSE_LEFT_BUTTON)) {
        handle_device_selection_clicks(mouse, dev_list, &capdev, &thread_id);
    }
    BeginDrawing();
    ClearBackground(BLACK);
    draw_device_selection_screen(dev_list);
    EndDrawing();
} else {
   if (capdev == NULL)
  {
    printf("ERR: pcap_open_live() %s\n", error_buffer);
    exit(1);
  }

    if (IsMouseButtonPressed(MOUSE_LEFT_BUTTON))
    {
      if (CheckCollisionPointRec(mouse, Filter_input))
      {
        filter_active = 1;
      }
      else if (!CheckCollisionPointRec(mouse, Packet_list) && !CheckCollisionPointRec(mouse, Btn_stop) && !CheckCollisionPointRec(mouse, Btn_save) && !CheckCollisionPointRec(mouse, Btn_live))
      {
        filter_active = 0;
      }

      if (CheckCollisionPointRec(mouse, Btn_stop))
      {
        pthread_mutex_lock(&pkt_buffer.mutex);
        capture_paused = !capture_paused;
        pthread_mutex_unlock(&pkt_buffer.mutex);
      }

      if (CheckCollisionPointRec(mouse, Btn_save))
      {
        save_to_file();
        guardarArchivo();
      }

      if (CheckCollisionPointRec(mouse, Btn_live))
      {
        pthread_mutex_lock(&pkt_buffer.mutex);
        int visible = count_filtered();
        float max_scroll = visible * 30 - Packet_list.height;
        scroll_list = (max_scroll > 0) ? -max_scroll : 0;
        auto_scroll_list = 1;
        pthread_mutex_unlock(&pkt_buffer.mutex);
      }

      if (CheckCollisionPointRec(mouse, Packet_list))
      {
        pthread_mutex_lock(&pkt_buffer.mutex);
        int rel_y = mouse.y - Packet_list.y - 10 - scroll_list;
        int idx = rel_y / 30;
        int visible_row = 0;
        selected_index = -1;

        if (rel_y >= 0)
        {
          for (int i = 0; i < pkt_buffer.count; i++)
          {
            if (!filter_match(&pkt_buffer.packets[i]))
            {
              continue;
            }

            if (visible_row == idx)
            {
              selected_index = i;
              break;
            }
            visible_row++;
          }
        }
        pthread_mutex_unlock(&pkt_buffer.mutex);
      }
    }

    if (filter_active)
    {
      int ch = GetCharPressed();
      while (ch > 0)
      {
        int len = strlen(filter_buf);
        if (len < (int)sizeof(filter_buf) - 1 && ch >= 32 && ch < 127)
        {
          filter_buf[len] = (char)ch;
          filter_buf[len + 1] = '\0';
        }
        ch = GetCharPressed();
      }

      if (IsKeyPressed(KEY_BACKSPACE) && strlen(filter_buf) > 0)
      {
        filter_buf[strlen(filter_buf) - 1] = '\0';
      }
      if (IsKeyPressed(KEY_ESCAPE))
      {
        filter_buf[0] = '\0';
        filter_active = 0;
      }
      if (IsKeyPressed(KEY_ENTER))
      {
        filter_active = 0;
      }
    }

    float wheel = GetMouseWheelMove() * 20;

    // scroll solo si el raton esta encima
    if (CheckCollisionPointRec(mouse, Packet_list))
    {
      if (wheel > 0)
      {
        auto_scroll_list = 0;
      }
      scroll_list += wheel;
    }
    if (CheckCollisionPointRec(mouse, Packet_info))
    {
      scroll_info += wheel;
    }
    if (CheckCollisionPointRec(mouse, packet_raw_mem))
    {
      scroll_mem += wheel;
    }
    if (CheckCollisionPointRec(mouse, packet_raw_hex))
    {
      scroll_hex += wheel;
    }

    pthread_mutex_lock(&pkt_buffer.mutex);
    int visible = count_filtered();

    if (auto_scroll_list && pkt_buffer.count > last_packet_count)
    {
      float max_scroll = visible * 30 - Packet_list.height;
      scroll_list = (max_scroll > 0) ? -max_scroll : 0;
    }
    last_packet_count = pkt_buffer.count;

    int raw_lines = 1;
    if (selected_index >= 0 && selected_index < pkt_buffer.count)
    {
      raw_lines = (pkt_buffer.packets[selected_index].raw_len + 15) / 16;
      if (raw_lines < 1)
      {
        raw_lines = 1;
      }
    }

    // limitar el scroll
    ClampScroll(&scroll_list, visible, 30, Packet_list.height);
    ClampScroll(&scroll_info, 20, 25, Packet_info.height);
    ClampScroll(&scroll_mem, raw_lines, 16, packet_raw_mem.height);
    ClampScroll(&scroll_hex, raw_lines, 16, packet_raw_hex.height);

    float max_scroll = visible * 30 - Packet_list.height;
    if (max_scroll < 0)
    {
      max_scroll = 0;
    }
    if (scroll_list <= -max_scroll + 5)
    {
      auto_scroll_list = 1;
    }

    // dibujar ventanitas
    BeginDrawing();
    ClearBackground(BLACK);

    draw_filter_input();
    draw_buttons();
    draw_titles();

    draw_packet_list();
    draw_info_panel();
    draw_mem_panel();
    draw_hex_panel();

    pthread_mutex_unlock(&pkt_buffer.mutex);

    EndDrawing();
  }
  }  
  if(capdev!=NULL){
    pcap_breakloop(capdev);
    pthread_join(thread_id, NULL);
    pcap_close(capdev);
  }
 
  pthread_mutex_destroy(&pkt_buffer.mutex);
  CloseWindow();
  guardarArchivo();

  
  
  return 0;
}
//-------------------------------------------------------------------------------------------------------------------//
void call_me(u_char *user, const struct pcap_pkthdr *pkthdr,const u_char *packetd_ptr)
{
  (void)user;

  pthread_mutex_lock(&pkt_buffer.mutex);
  if (capture_paused)
  {
    pthread_mutex_unlock(&pkt_buffer.mutex);
    return;
  }
  pthread_mutex_unlock(&pkt_buffer.mutex);

  const u_char *pkt_start = packetd_ptr;
  if (pkthdr->caplen < (unsigned int)(link_hdr_length + (int)sizeof(struct ip)))
  {
    return;
  }

  packet_info pkt_info;
  memset(&pkt_info, 0, sizeof(pkt_info));

  if (!have_first_ts)
  {
    first_ts = pkthdr->ts;
    have_first_ts = 1;
  }

  pkt_info.time = (pkthdr->ts.tv_sec - first_ts.tv_sec) + (pkthdr->ts.tv_usec - first_ts.tv_usec) / 1000000.0f;
  struct ether_header *eth = (struct ether_header *)packetd_ptr;

  packetd_ptr += link_hdr_length;
  struct ip *ip_hdr = (struct ip *)packetd_ptr;

  //capturar la info que los paquetes tienen en comun
  strcpy(pkt_info.src_ip, inet_ntoa(ip_hdr->ip_src));
  strcpy(pkt_info.dst_ip, inet_ntoa(ip_hdr->ip_dst));
  snprintf(pkt_info.src_mac, sizeof(pkt_info.src_mac),"%02X:%02X:%02X:%02X:%02X:%02X",eth->ether_shost[0],eth->ether_shost[1],eth->ether_shost[2],eth->ether_shost[3],eth->ether_shost[4],eth->ether_shost[5]);
  snprintf(pkt_info.dts_mac, sizeof(pkt_info.dts_mac),"%02X:%02X:%02X:%02X:%02X:%02X",eth->ether_dhost[0],eth->ether_dhost[1],eth->ether_dhost[2],eth->ether_dhost[3],eth->ether_dhost[4],eth->ether_dhost[5]);
  pkt_info.id = ntohs(ip_hdr->ip_id);
  pkt_info.ttl = ip_hdr->ip_ttl;
  pkt_info.tos = ip_hdr->ip_tos;
  pkt_info.len = ntohs(ip_hdr->ip_len);

  int packet_hlen = ip_hdr->ip_hl * 4;
  if (packet_hlen < 20 || pkthdr->caplen < (unsigned int)(link_hdr_length + packet_hlen))
  {
    return;
  }

  packetd_ptr += packet_hlen;
  int protocol_type = ip_hdr->ip_p;
  unsigned int transport_len = pkthdr->caplen - link_hdr_length - packet_hlen;

  struct tcphdr *tcp_header;
  struct udphdr *udp_header;
  struct icmp *icmp_header;
  int src_port, dst_port;

  //dependiendo del tipo de protocolo
  switch (protocol_type)
  {
  case IPPROTO_TCP:
    if (transport_len < sizeof(struct tcphdr))
    {
      strcpy(pkt_info.protocol, "TCP");
      strcpy(pkt_info.info, "TRUNCATED");
      break;
    }
    tcp_header = (struct tcphdr *)packetd_ptr;
    src_port = ntohs(tcp_header->th_sport);
    dst_port = ntohs(tcp_header->th_dport);
    pkt_info.seq_num = ntohl(tcp_header->th_seq);
    pkt_info.ack_num = ntohl(tcp_header->th_ack);
    pkt_info.win_size = ntohs(tcp_header->th_win);
    strcpy(pkt_info.protocol, "TCP");
    snprintf(pkt_info.info, INFO_BUFFER_SIZE, "%d -> %d [%c%c%c] Seq=%u - Ack=%u", src_port,dst_port,(tcp_header->th_flags & TH_SYN ? 'S': '-'),(tcp_header->th_flags & TH_ACK ? 'A' : '-'),(tcp_header->th_flags & TH_URG ? 'U': '-'),pkt_info.seq_num, pkt_info.ack_num);
   
    //capturar al flag para mostrarla en la ventana de info
    pkt_info.flags[0] = '\0';

    if (tcp_header->th_flags & TH_SYN)
    {
      strcat(pkt_info.flags, "SYN ");
    }
    if (tcp_header->th_flags & TH_ACK)
    {
      strcat(pkt_info.flags, "ACK ");
    }
    if (tcp_header->th_flags & TH_URG)
    {
      strcat(pkt_info.flags, "URG ");
    }
    break;
  case IPPROTO_UDP:
    if (transport_len < sizeof(struct udphdr))
    {
      strcpy(pkt_info.protocol, "UDP");
      strcpy(pkt_info.info, "TRUNCATED");
      break;
    }
    udp_header = (struct udphdr *)packetd_ptr;
    src_port = ntohs(udp_header->uh_sport);
    dst_port = ntohs(udp_header->uh_dport);
    strcpy(pkt_info.protocol, "UDP");
    pkt_info.payload = ntohs(udp_header->uh_ulen)-sizeof(struct udphdr);
    pkt_info.check = ntohs(udp_header->check);
    snprintf(pkt_info.info, INFO_BUFFER_SIZE, "%d -> %d Len =  %u", src_port, dst_port,pkt_info.payload);
    break;
  case IPPROTO_ICMP:
    if (transport_len < sizeof(struct icmp))
    {
      strcpy(pkt_info.protocol, "ICMP");
      strcpy(pkt_info.info, "TRUNCATED");
      break;
    }
    icmp_header = (struct icmp *)packetd_ptr;
    pkt_info.type = icmp_header->icmp_type;
    pkt_info.code = icmp_header->icmp_code;
    pkt_info.check = ntohs(icmp_header->icmp_cksum);
    pkt_info.id = ntohs(icmp_header->icmp_hun.ih_idseq.icd_id);
    pkt_info.seq_num = ntohs(icmp_header->icmp_hun.ih_idseq.icd_seq);
    strcpy(pkt_info.protocol, "ICMP");
    snprintf(pkt_info.info, INFO_BUFFER_SIZE, "code = %d type = %d [%s] ID = 0x%04x Seq = %u", pkt_info.code, pkt_info.type,(pkt_info.type == 8 ? "reguest":"reply"),pkt_info.id,pkt_info.seq_num);
    break;

  default:
    strcpy(pkt_info.protocol, "OTHER");
    strcpy(pkt_info.info, "");
    break;
  }

  pkt_info.raw_len = pkthdr->caplen;
  if (pkt_info.raw_len > RAW_BUFFER_SIZE)
  {
    pkt_info.raw_len = RAW_BUFFER_SIZE;
  }
  memcpy(pkt_info.raw, pkt_start, pkt_info.raw_len);

  pthread_mutex_lock(&pkt_buffer.mutex);
  if (pkt_buffer.count < MAX_PACKETS)
  {
    pkt_info.no = ++packet_counter;
    pkt_buffer.packets[pkt_buffer.count++] = pkt_info;
  }
  pthread_mutex_unlock(&pkt_buffer.mutex);
}
//-------------------------------------------------------------------------------------------------------------------//
void *capture_thread(void *arg)
{
  pcap_t *handle = (pcap_t *)arg;
  pcap_loop(handle, -1, call_me, NULL);
  return NULL;
}
//-------------------------------------------------------------------------------------------------------------------//
void DrawPanel(Rectangle r) 
{ 
  DrawRectangleLinesEx(r, 1, GREEN); 
}
//-------------------------------------------------------------------------------------------------------------------//
void ClampScroll(float *scroll, int items, float itemHeight, float panelHeight)
{
  float maxScroll = (items * itemHeight) - panelHeight;
  if (maxScroll < 0)
  {
    maxScroll = 0;
  }
  if (*scroll > 0)
  {
    *scroll = 0;
  }
  if (*scroll < -maxScroll)
  {
    *scroll = -maxScroll;
  }
}
//-------------------------------------------------------------------------------------------------------------------//
void draw_packet_list()
{
  DrawPanel(Packet_list);
  BeginScissorMode(Packet_list.x, Packet_list.y, Packet_list.width, Packet_list.height);

  float itemHeight = 30;
  int col_x[] = {20, 80, 295, 570, 845, 1120, 1350};

  int visible_row = 0;
  for (int i = 0; i < pkt_buffer.count; i++)
  {
    if (!filter_match(&pkt_buffer.packets[i]))
    {
      continue;
    }

    int y = Packet_list.y + 10 + visible_row * itemHeight + scroll_list;
    visible_row++;

    Color color = (i == selected_index) ? YELLOW : GREEN;
    char buffer[128];

    snprintf(buffer, sizeof(buffer), "%d", pkt_buffer.packets[i].no);
    DrawText(buffer, col_x[0], y, 20, color);

    snprintf(buffer, sizeof(buffer), "%.2f", pkt_buffer.packets[i].time);
    DrawText(buffer, col_x[1], y, 20, color);

    DrawText(pkt_buffer.packets[i].src_ip, col_x[2], y, 20, color);
    DrawText(pkt_buffer.packets[i].dst_ip, col_x[3], y, 20, color);
    DrawText(pkt_buffer.packets[i].protocol, col_x[4], y, 20, color);

    snprintf(buffer, sizeof(buffer), "%d", pkt_buffer.packets[i].len);
    DrawText(buffer, col_x[5], y, 20, color);

    DrawText(pkt_buffer.packets[i].info, col_x[6], y, 20, color);
  }

  EndScissorMode();
}
//-------------------------------------------------------------------------------------------------------------------//
void draw_info_panel()
{
  DrawPanel(Packet_info);
  BeginScissorMode(Packet_info.x, Packet_info.y, Packet_info.width,Packet_info.height);

  if (selected_index >= 0 && selected_index < pkt_buffer.count)
  {
    packet_info *pkt = &pkt_buffer.packets[selected_index];
    char buffer[256];
    int x = Packet_info.x + 10;
    int y = Packet_info.y + 10 + scroll_info;

    snprintf(buffer, sizeof(buffer), "Packet %d", pkt->no);
    DrawText(buffer, x, y, 20, GREEN);
    y += 24;
    snprintf(buffer, sizeof(buffer), "IP ID:   %d", pkt->id);
    DrawText(buffer, x, y, 20, GREEN);
    y += 24;
    snprintf(buffer, sizeof(buffer), "Time:    %.2fs", pkt->time);
    DrawText(buffer, x, y, 20, GREEN);
    y += 24;
    snprintf(buffer, sizeof(buffer), "Source:  %s", pkt->src_ip);
    DrawText(buffer, x, y, 20, GREEN);
    y += 24;
    snprintf(buffer, sizeof(buffer), "Dest:    %s", pkt->dst_ip);
    DrawText(buffer, x, y, 20, GREEN);
    y += 24;
    snprintf(buffer, sizeof(buffer), "MAC source: %s", pkt->src_mac);
    DrawText(buffer, x, y, 20, GREEN);
    y += 24;
    snprintf(buffer, sizeof(buffer), "MAC dest: %s", pkt->dts_mac);
    DrawText(buffer, x, y, 20, GREEN);
    y += 24;
    snprintf(buffer, sizeof(buffer), "Proto:   %s", pkt->protocol);
    DrawText(buffer, x, y, 20, GREEN);
    y += 24;
    snprintf(buffer, sizeof(buffer), "Length:  %d bytes", pkt->len);
    DrawText(buffer, x, y, 20, GREEN);
    y += 24;
    snprintf(buffer, sizeof(buffer), "TTL:  %d", pkt->ttl);
    DrawText(buffer, x, y, 20, GREEN);
    y += 24;
    snprintf(buffer, sizeof(buffer), "TOS:  0x%x",pkt->tos);
    DrawText(buffer, x, y, 20, GREEN);
    y += 24;
    snprintf(buffer, sizeof(buffer), "Raw:  %d bytes", pkt->raw_len);
    DrawText(buffer, x, y, 20, GREEN);
    y += 24;

    if (strcmp(pkt->protocol,"TCP") == 0)
    {
      snprintf(buffer, sizeof(buffer), "Flags:  %s", pkt->flags);
      DrawText(buffer, x, y, 20, GREEN);
      y += 24;
      snprintf(buffer, sizeof(buffer), "Seq num:  %u", pkt->seq_num);
      DrawText(buffer, x, y, 20, GREEN);
      y += 24;
      snprintf(buffer, sizeof(buffer), "Ack num:  %u", pkt->ack_num);
      DrawText(buffer, x, y, 20, GREEN);
      y += 24;
      snprintf(buffer, sizeof(buffer), "Win size:  %u", pkt->win_size);
      DrawText(buffer, x, y, 20, GREEN);
      y += 24;
    }

    if (strcmp(pkt->protocol,"UDP") == 0)
    {
      snprintf(buffer, sizeof(buffer), "Payload:  %u", pkt->payload);
      DrawText(buffer, x, y, 20, GREEN);
      y += 24;
      if (pkt->check == 0)
      {
        snprintf(buffer, sizeof(buffer), "Check:  DISABLED");
      }
      else
      {
        snprintf(buffer, sizeof(buffer), "Check:  0x%04x", pkt->check);
      }
      DrawText(buffer, x, y, 20, GREEN);
      y += 24;
    }
    
    if (strcmp(pkt->protocol,"ICMP") == 0)
    {
      if (pkt->type == 8)
      {
        snprintf(buffer, sizeof(buffer), "Type:  %d (request)", pkt->type);
      }
      else
      {
        snprintf(buffer, sizeof(buffer), "Type:  %d (reply)", pkt->type);
      }
      DrawText(buffer, x, y, 20, GREEN);
      y += 24;
      snprintf(buffer, sizeof(buffer), "Code:  %d", pkt->code);
      DrawText(buffer, x, y, 20, GREEN);
      y += 24;
      snprintf(buffer, sizeof(buffer), "Payload:  %u", pkt->payload);
      DrawText(buffer, x, y, 20, GREEN);
      y += 24;
    }
  }
  else
  {
    DrawText("Click a packet to view info", Packet_info.x + 10, Packet_info.y + 10 + scroll_info, 25, ORANGE);
  }

  EndScissorMode();
}
//-------------------------------------------------------------------------------------------------------------------//
void draw_mem_panel()
{
  DrawPanel(packet_raw_mem);
  BeginScissorMode(packet_raw_mem.x, packet_raw_mem.y, packet_raw_mem.width, packet_raw_mem.height);

  if (selected_index >= 0 && selected_index < pkt_buffer.count)
  {
    packet_info *pkt = &pkt_buffer.packets[selected_index];
    int y = packet_raw_mem.y + 10 + scroll_mem;
    char line[160];

    for (int offset = 0; offset < pkt->raw_len; offset += 16)
    {
      int pos = snprintf(line, sizeof(line), "%04x  ", offset);

      for (int j = 0; j < 16; j++)
      {
        if (offset + j < pkt->raw_len)
        {
          pos += snprintf(line + pos, sizeof(line) - pos, "%02x ", pkt->raw[offset + j]);
        }
        else
        {
          pos += snprintf(line + pos, sizeof(line) - pos, "   ");
        }
        if (j == 7)
        {
          pos += snprintf(line + pos, sizeof(line) - pos, " ");
        }
      }

      pos += snprintf(line + pos, sizeof(line) - pos, " |");
      for (int j = 0; j < 16 && offset + j < pkt->raw_len; j++)
      {
        u_char c = pkt->raw[offset + j];
        pos += snprintf(line + pos, sizeof(line) - pos, "%c", (c >= 32 && c < 127) ? c : '.');
      }
      snprintf(line + pos, sizeof(line) - pos, "|");

      DrawText(line, packet_raw_mem.x + 10, y, 19, WHITE);
      y += 16;
    }
  }
  else
  {
    DrawText("Click a packet to view memory", packet_raw_mem.x + 10, packet_raw_mem.y + 10 + scroll_mem, 25, ORANGE);
  }

  EndScissorMode();
}
//-------------------------------------------------------------------------------------------------------------------//
void draw_hex_panel()
{
  DrawPanel(packet_raw_hex);
  BeginScissorMode(packet_raw_hex.x, packet_raw_hex.y, packet_raw_hex.width, packet_raw_hex.height);

  if (selected_index >= 0 && selected_index < pkt_buffer.count)
  {
    packet_info *pkt = &pkt_buffer.packets[selected_index];
    int y = packet_raw_hex.y + 10 + scroll_hex;
    char line[128];

    for (int offset = 0; offset < pkt->raw_len; offset += 16)
    {
      int pos = 0;
      for (int j = 0; j < 16 && offset + j < pkt->raw_len; j++)
      {
        pos += snprintf(line + pos, sizeof(line) - pos, "%02x ", pkt->raw[offset + j]);
      }

      DrawText(line, packet_raw_hex.x + 10, y, 19, WHITE);
      y += 16;
    }
  }
  else
  {
    DrawText("Click a packet to view hex", packet_raw_hex.x + 10, packet_raw_hex.y + 10 + scroll_hex, 25, ORANGE);
  }

  EndScissorMode();
}
//-------------------------------------------------------------------------------------------------------------------//
void save_to_file()
{
  time_t now = time(NULL);
  struct tm tm_info;
  localtime_r(&now, &tm_info);

  char fname[256];
  snprintf(fname, sizeof(fname), "sniff_%04d%02d%02d_%02d%02d%02d.txt", tm_info.tm_year + 1900, tm_info.tm_mon + 1, tm_info.tm_mday, tm_info.tm_hour, tm_info.tm_min, tm_info.tm_sec);

  FILE *file = fopen(fname, "w");
  if (file == NULL)
  {
    return;
  }

  pthread_mutex_lock(&pkt_buffer.mutex);
  int saved_count = pkt_buffer.count;
  fprintf(file, "Packet Sniffer session - %04d-%02d-%02d %02d:%02d:%02d\n", tm_info.tm_year + 1900, tm_info.tm_mon + 1, tm_info.tm_mday, tm_info.tm_hour, tm_info.tm_min, tm_info.tm_sec);
  fprintf(file, "Total packets: %d\n\n", saved_count);

  for (int i = 0; i < saved_count; i++)
  {
    packet_info *pkt = &pkt_buffer.packets[i];
    fprintf(file, "%d  %.2f  %s  %s  %s  %d", pkt->no, pkt->time, pkt->src_ip, pkt->dst_ip, pkt->protocol, pkt->len);
    if (pkt->info[0] != '\0')
    {
      fprintf(file, "  %s", pkt->info);
    }
    fprintf(file, "\n");
  }
  pthread_mutex_unlock(&pkt_buffer.mutex);

  fclose(file);
  TraceLog(LOG_INFO, "Saved %d packets to %s", saved_count, fname);
}
//-------------------------------------------------------------------------------------------------------------------//
void draw_button(Rectangle button, const char *text, Color border_color, Color text_color, int text_x_offset)
{
  DrawRectangleRec(button, (Color){20, 20, 20, 255});
  DrawRectangleLinesEx(button, 1, border_color);
  DrawText(text, button.x + text_x_offset, button.y + 5, 17, text_color);
}
//-------------------------------------------------------------------------------------------------------------------//
void draw_buttons()
{
  Color stop_color = capture_paused ? (Color){0, 180, 0, 255} : RED;
  const char *stop_text = capture_paused ? "RESUME" : "STOP";

  draw_button(Btn_stop, stop_text, stop_color, stop_color, 8);
  draw_button(Btn_save, "GUARDAR", DARKGREEN, GREEN, 10);
  draw_button(Btn_live, "LIVE", GREEN, GREEN, 8);

  char count_text[64];
  snprintf(count_text, sizeof(count_text), "Packets: %d", pkt_buffer.count);
  DrawText(count_text, 805, 48, 20, GREEN);
}
//-------------------------------------------------------------------------------------------------------------------//
void draw_filter_input()
{
  DrawText("Filter:", 20, 50, 20, GREEN);
  DrawRectangleLinesEx(Filter_input, 1, GREEN);
  DrawText(filter_buf, Filter_input.x + 5, Filter_input.y + 5, 20, GREEN);

  if (filter_active)
  {
    int text_width = MeasureText(filter_buf, 20);
    float t = GetTime();
    if (((int)(t * 2)) % 2 == 0)
    {
      DrawText("_", Filter_input.x + 5 + text_width, Filter_input.y + 5, 20, GREEN);
    }
  }
  else if (filter_buf[0] == '\0')
  {
    DrawText("filtrar...", Filter_input.x + 5, Filter_input.y + 5, 20, DARKGREEN);
  }

  DrawText("src:x  dst:x  tcp/udp/icmp", Filter_input.x + 5, Filter_input.y + 28, 14, DARKGREEN);
}
//-------------------------------------------------------------------------------------------------------------------//
void copy_lower(char *dst, const char *src, size_t dst_size)
{
  if (dst_size == 0)
  {
    return;
  }

  size_t i = 0;
  for (; i + 1 < dst_size && src[i] != '\0'; i++)
  {
    dst[i] = (char)tolower((unsigned char)src[i]);
  }
  dst[i] = '\0';
}
//-------------------------------------------------------------------------------------------------------------------//
int contains_text(const char *text, const char *query)
{
  char lower_text[256];
  char lower_query[256];

  copy_lower(lower_text, text, sizeof(lower_text));
  copy_lower(lower_query, query, sizeof(lower_query));

  return strstr(lower_text, lower_query) != NULL;
}
//-------------------------------------------------------------------------------------------------------------------//
int filter_match(const packet_info *pkt)
{
  char filter[256];

  if (filter_buf[0] == '\0')
  {
    return 1;
  }

  copy_lower(filter, filter_buf, sizeof(filter));

  if (strncmp(filter, "src:", 4) == 0)
  {
    return contains_text(pkt->src_ip, filter + 4);
  }
  if (strncmp(filter, "dst:", 4) == 0)
  {
    return contains_text(pkt->dst_ip, filter + 4);
  }

  return contains_text(pkt->src_ip, filter) || contains_text(pkt->dst_ip, filter) || contains_text(pkt->protocol, filter);
}
//-------------------------------------------------------------------------------------------------------------------//
int count_filtered()
{
  int count = 0;

  for (int i = 0; i < pkt_buffer.count; i++)
  {
    if (filter_match(&pkt_buffer.packets[i]))
    {
      count++;
    }
  }

  return count;
}
//-------------------------------------------------------------------------------------------------------------------//
void draw_titles()
{
  const char *titles[] = {"No", "TIME", "SOURCE", "DESTINATION", "PROTOCOL", "LENGTH", "INFO"};
  int col_x[] = {20, 80, 295, 570, 845, 1120, 1350};//1395

  for (int i = 0; i < 7; i++)
  {
    DrawText(titles[i], col_x[i], 90, 20, GREEN);
  }
}
//-------------------------------------------------------------------------------------------------------------------//
void guardarArchivo(){

    time_t now = time(NULL);
  struct tm tm_info;
  localtime_r(&now, &tm_info);

  char fname[256];
  snprintf(fname, sizeof(fname), "Captura de paquetes_%04d-%02d-%02d_%02d-%02d-%02d.csv", tm_info.tm_year + 1900, tm_info.tm_mon + 1, tm_info.tm_mday, tm_info.tm_hour, tm_info.tm_min, tm_info.tm_sec);
  FILE *archivo = fopen(fname,"w");
  if(archivo ==NULL){
    printf("Hubo un error al abrir el archivo");
    return;
  }
  //columnas
fprintf(archivo, "no;id;time;lenght;srcip;destip;ttl;tos;protocol;info;rawLength;raw\n"); 
 for (int i= 0; i<pkt_buffer.count;i++){
   packet_info p = pkt_buffer.packets[i];
 fprintf(archivo, "%d ;%d ;%.6f;%d; %s ; %s ;%d;%d; %s;%s ; %d ; ",
    p.no,          
    p.id,
    p.time,
    p.len,
    p.src_ip,
    p.dst_ip,
    p.ttl,
    p.tos,
    p.protocol,
    p.info,
    p.raw_len
    );
    for (int j = 0; j < p.raw_len; j++) {
      fprintf(archivo, "%02x", p.raw[j]);
    }
    fprintf(archivo, "\n");

  }
  
  fclose(archivo);
}

DeviceList get_available_devices(void) {
    DeviceList list = { .count = 0 };
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_if_t *alldevs, *d;

    if (pcap_findalldevs(&alldevs, errbuf) != -1) {
        for (d = alldevs; d != NULL && list.count < MAX_DEVICES; d = d->next) {
            strncpy(list.names[list.count], d->name, 63);
            list.names[list.count][63] = '\0'; // Ensure null-termination
            list.count++;
        }
        pcap_freealldevs(alldevs);
    } else {
        printf("Error running pcap_findalldevs: %s\n", errbuf);
    }
    return list;
}

void start_capture_session(pcap_t **capdev, pthread_t *thread_id, const char *device_name) {
    char error_buffer[PCAP_ERRBUF_SIZE];

    *capdev = pcap_open_live(device_name, BUFSIZ, 0, 100, error_buffer);
    if (*capdev == NULL) {
        printf("ERR: pcap_open_live() failed for %s: %s\n", device_name, error_buffer);
        exit(1);
    }

    //movido aqui
    int link_hdr_type = pcap_datalink(*capdev);
    switch (link_hdr_type) {
        case DLT_NULL:    link_hdr_length = 4;  break;
        case DLT_EN10MB:  link_hdr_length = 14; break;
        default:          link_hdr_length = 0;
    }

    // Initialize mutex and boot background thread processing loop
    pthread_create(thread_id, NULL, capture_thread, (void *)*capdev);
}

void draw_device_selection_screen(DeviceList list) {
    DrawText("Seleccione una interfaz de red para comenzar a analizar", 50, 50, 28, GREEN);
    DrawLine(50, 95, WIN_WIDTH - 50, 95, DARKGREEN);

    int start_x = 100;
    int start_y = 150;
    int row_height = 45;
    Vector2 mouse = GetMousePosition();

    for (int i = 0; i < list.count; i++) {
        Rectangle item_rec = { start_x, start_y + (i * row_height), 400, 35 };
        bool is_hovered = CheckCollisionPointRec(mouse, item_rec);
        
        // Highlight row box backgrounds dynamically
        Color bg_color = is_hovered ? (Color){30, 80, 30, 255} : (Color){15, 15, 15, 255};
        Color border_color = is_hovered ? GREEN : DARKGREEN;
        Color text_color = is_hovered ? YELLOW : GREEN;

        DrawRectangleRec(item_rec, bg_color);
        DrawRectangleLinesEx(item_rec, 1, border_color);
        DrawText(list.names[i], item_rec.x + 15, item_rec.y + 7, 20, text_color);
    }
}

void handle_device_selection_clicks(Vector2 mouse, DeviceList list, pcap_t **capdev, pthread_t *thread_id) {
    int start_x = 100;
    int start_y = 150;
    int row_height = 45;

    for (int i = 0; i < list.count; i++) {
        Rectangle item_rec = { start_x, start_y + (i * row_height), 400, 35 };
        
        if (CheckCollisionPointRec(mouse, item_rec)) {
            strncpy(selected_device_name, list.names[i], sizeof(selected_device_name) - 1);
            start_capture_session(capdev, thread_id, selected_device_name);
            
            // Cambia de estado
            current_state = STATE_SNIFFING;
            return;
        }
    }
}