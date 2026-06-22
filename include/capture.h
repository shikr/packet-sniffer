#pragma once

#include <pcap.h>
#include <sys/types.h>

void capture_handler(u_char *user, const struct pcap_pkthdr *pkthdr,
                     const u_char *packetd_ptr);
