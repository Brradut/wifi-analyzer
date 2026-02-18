#include <pcap/pcap.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/types.h>
#include "packet-sniffer.h"

struct ethernet_header {
  u_int8_t dest[6];
  u_int8_t src[6];
  u_int16_t type;
};

struct ipv6_info {
  char src_ip[40];
  char dest_ip[40];
};

struct ipv4_info {
  char src_ip[16];
  char dest_ip[16];
};

struct tcp_info{
  u_int16_t src_port;
  u_int16_t dest_port;

  char* payload;
};

struct packet_info {
  char src_mac[18];
  char dest_mac[18];
  char eth_type[15];
  
  struct ipv6_info ipv6;
  struct ipv4_info ipv4;
  struct tcp_info tcp;
};


struct packet_info get_packet_info(const u_char* packet, int length) {
  struct packet_info info;
  memset(&info, 0, sizeof(struct packet_info));

  int offset = 0;

  // Extract Ethernet header

  struct ethernet_header *eth = (struct ethernet_header *)packet;
  sprintf(info.src_mac, "%02x:%02x:%02x:%02x:%02x:%02x",
         eth->src[0], eth->src[1], eth->src[2],
         eth->src[3], eth->src[4], eth->src[5]);
  sprintf(info.dest_mac, "%02x:%02x:%02x:%02x:%02x:%02x",
         eth->dest[0], eth->dest[1], eth->dest[2],
         eth->dest[3], eth->dest[4], eth->dest[5]);
  eth->type = ntohs(eth->type);

  if (eth->type == 0x0800) {
    strcpy(info.eth_type, "IPv4");
  } else if (eth->type == 0x86DD) {
    strcpy(info.eth_type, "IPv6");
  } else if (eth->type == 0x0806) {
    strcpy(info.eth_type, "ARP");
  } else {
    sprintf(info.eth_type, "0x%04x", eth->type);
  }

  offset += 14; // Move past Ethernet header

  // Extract IPv6 header if present
  if (eth->type == 0x86DD) {
    offset += 6; // Skip version, traffic class, flow label, and payload length
    u_int8_t next_header = (u_int8_t)packet[offset];
    offset += 2; // Also skip hop limit

    // Source IP
    for (int i = 0; i < 16; i++) {
      sprintf(info.ipv6.src_ip + i * 2, "%02x", packet[offset + i]);
    }
    info.ipv6.src_ip[39] = '\0';
    offset += 16;
    // Destination IP
    for (int i = 0; i < 16; i++) {
      sprintf(info.ipv6.dest_ip + i * 2, "%02x", packet[offset + i]);
    }
    info.ipv6.dest_ip[39] = '\0';
    offset += 16;

    // Hop by hop options
    if (next_header == 0) {
      next_header = (u_int8_t)packet[offset];
      offset += 1;
      u_int8_t opt_len = (u_int8_t)packet[offset];
      offset += 1;
      offset += 6 + opt_len * 8; // Skip options
    } 

    // Destination options
    if (next_header == 60) {
      next_header = (u_int8_t)packet[offset];
      offset += 1;
      u_int8_t opt_len = (u_int8_t)packet[offset];
      offset += 1;
      offset += 6 + opt_len * 8; // Skip options
    }

    // Routing header
    if (next_header == 43) {
      next_header = (u_int8_t)packet[offset];
      offset += 1;
      u_int8_t hdr_ext_len = (u_int8_t)packet[offset];
      offset += 1;
      offset += hdr_ext_len * 8; // Skip routing header
    }
  
    // Fragment header
    if (next_header == 44) {
      next_header = (u_int8_t)packet[offset];
      offset += 8; // Skip fragment header
    }

    if (next_header == 50){
      strcpy(info.eth_type, "IPv6 ESP");
    }

    if (next_header == 1){
      strcpy(info.eth_type, "IPv6 ICMP");
    }else if (next_header == 6){
      strcpy(info.eth_type, "IPv6 TCP");
      struct tcp_info tcp_info;
      tcp_info.src_port = ntohs(*(u_int16_t*)(packet + offset));
      offset += 2;
      tcp_info.dest_port = ntohs(*(u_int16_t*)(packet + offset));
      offset += 2;
      info.tcp = tcp_info;
      offset += 8; // Skip sequence number and acknowledgment number
      u_int8_t data_offset = (u_int8_t)(packet[offset] >> 4);
      offset += data_offset * 4 - 12; // Move to the end of the TCP header

      int payload_length = length - offset;
      info.tcp.payload = (char*)malloc(payload_length);
      memcpy(info.tcp.payload, packet + offset, payload_length);
    }else if (next_header == 17){
      strcpy(info.eth_type, "IPv6 UDP");
    }
  } else if (eth->type == 0x0800) {
    u_int8_t data_offset = (u_int8_t)(packet[offset] & 0x0F);
    offset += 9; // Skip version, IHL, DSCP, ECN, total length, identification, flags, fragment offset, and TTL
    u_int8_t protocol = (u_int8_t)packet[offset];
    offset += 3; // Also skip headers checksum
    // Source IP
    sprintf(info.ipv4.src_ip, "%d.%d.%d.%d", (u_int8_t)packet[offset], (u_int8_t)packet[offset + 1], (u_int8_t)packet[offset + 2], (u_int8_t)packet[offset + 3]);
    offset += 4;
    // Destination IP
    sprintf(info.ipv4.dest_ip, "%d.%d.%d.%d", (u_int8_t)packet[offset], (u_int8_t)packet[offset + 1], (u_int8_t)packet[offset + 2], (u_int8_t)packet[offset + 3]);
    offset += 4;

    offset += data_offset * 4 - 20; // Go to the end of the IPv4 header
    if (protocol == 1) {
      strcpy(info.eth_type, "IPv4 ICMP");
    } else if (protocol == 6) {
      strcpy(info.eth_type, "IPv4 TCP");
      struct tcp_info tcp_info;
      tcp_info.src_port = ntohs(*(u_int16_t*)(packet + offset));
      offset += 2;
      tcp_info.dest_port = ntohs(*(u_int16_t*)(packet + offset));
      offset += 2;
      info.tcp = tcp_info;
      offset += 8; // Skip sequence number and acknowledgment number
      u_int8_t data_offset = (u_int8_t)(packet[offset] >> 4);
      offset += data_offset * 4 - 12; // Move to the end of the TCP header

      int payload_length = length - offset;
      info.tcp.payload = (char*)malloc(payload_length);
      memcpy(info.tcp.payload, packet + offset, payload_length);
    } else if (protocol == 17) {
      strcpy(info.eth_type, "IPv4 UDP");
    }
  }

  return info;
}

/*
  * Get a list of network interfaces that support monitor mode.
  * @param interfaces: A pointer to an array of strings to store the interface names.
  * @param count: A pointer to an integer to store the number of interfaces found.
  * @return: 0 on success, 2 on error
*/
int get_all_interfaces(char **interfaces[], int *count) {
  char errbuf[PCAP_ERRBUF_SIZE];
  pcap_if_t *devs;

  if (pcap_findalldevs(&devs, errbuf) != 0){
    fprintf(stderr, "Error getting interfaces: %s\n", errbuf);
    return (2);
  }
  if (devs == NULL){
    *count = 0;
    return (0);
  }

  *count = 0;
  for (pcap_if_t *d = devs; d != NULL; d = d->next) {
      pcap_t *dev = pcap_create(d->name, errbuf);
      if (dev == NULL) {
          continue;
      }
      pcap_close(dev);
      (*count)++;
  }

  *interfaces = (char **)malloc((*count) * sizeof(char *));

  int i = 0; pcap_if_t *d = devs;
  while (d != NULL && i < *count) {
    pcap_t *dev = pcap_create(d->name, errbuf);
    if (dev == NULL) {
        continue;
    }
    (*interfaces)[i] = (char *)malloc((strlen(d->name) + 1) * sizeof(char));
    strcpy((*interfaces)[i], d->name);
    i++;
    d = d->next;
    pcap_close(dev);
  }

  pcap_freealldevs(devs);
  return 0;
}

/*
  * Free the memory allocated for the list of interfaces.
  * @param interfaces: The array of strings containing the interface names.
  * @param count: The number of interfaces in the array.
  * @return: 0 on success
*/
int free_all_interfaces(char **interfaces, int count) {
  for (int i = 0; i < count; i++) {
    free(interfaces[i]);
  }
  free(interfaces);
  return 0;
}

/* Global handle so stop_capture() can break the loop from any thread. */
static pcap_t *active_handle = NULL;

/* Stub for standalone builds. */
#ifndef CGO_BUILD
void on_packet_captured(char *src_mac, char *dest_mac, char *eth_type,
                       char *src_ipv4, char *dest_ipv4,
                       char *src_ipv6, char *dest_ipv6,
                       int src_port, int dest_port,
                       char *payload, int payload_length) {
  (void)payload;
  (void)payload_length;
  printf("Packet: %s -> %s [%s]\n", src_mac, dest_mac, eth_type);
  if (src_ipv4[0]) printf("  IPv4: %s -> %s\n", src_ipv4, dest_ipv4);
  if (src_ipv6[0]) printf("  IPv6: %s -> %s\n", src_ipv6, dest_ipv6);
  if (src_port > 0) printf("  TCP: %d -> %d\n", src_port, dest_port);
}
#endif

void packet_capture_handler(u_char *user, const struct pcap_pkthdr *header, const u_char *packet) {
  (void)user;

  struct packet_info info = get_packet_info(packet, header->caplen);
  
  // Prepare data for callback
  char empty_ipv4[16] = "";
  char empty_ipv6[40] = "";
  
  // Call the Go (or C stub) callback
  on_packet_captured(
    info.src_mac,
    info.dest_mac,
    info.eth_type,
    info.ipv4.src_ip[0] ? info.ipv4.src_ip : empty_ipv4,
    info.ipv4.dest_ip[0] ? info.ipv4.dest_ip : empty_ipv4,
    info.ipv6.src_ip[0] ? info.ipv6.src_ip : empty_ipv6,
    info.ipv6.dest_ip[0] ? info.ipv6.dest_ip : empty_ipv6,
    info.tcp.src_port,
    info.tcp.dest_port,
    info.tcp.payload,
    info.tcp.payload ? strlen(info.tcp.payload) : 0
  );
    
  free(info.tcp.payload);
}

/*
  * Start capturing beacon frames on the given interface (monitor mode).
  * Blocks until stop_packet_capture() is called or an error occurs.
  * @param interface_name: The name of the interface.
  * @return: 0 on success, 1 on error
*/
int start_packet_capture(const char *interface_name) {
  char errbuf[PCAP_ERRBUF_SIZE];
  pcap_t *handle = pcap_create(interface_name, errbuf);
  if (handle == NULL) {
    fprintf(stderr, "Couldn't open device: %s\n", errbuf);
    return 1;
  }

  if(pcap_set_immediate_mode(handle, 1) != 0) {
    fprintf(stderr, "Couldn't immediate mode: %s\n", pcap_geterr(handle));
    pcap_close(handle);
    return 1;
  }

  if(pcap_activate(handle) != 0) {
    fprintf(stderr, "Couldn't activate handle: %s\n", pcap_geterr(handle));
    pcap_close(handle);
    return 1;
  }

  // Ethernet frames
  if(pcap_set_datalink(handle, DLT_EN10MB) != 0) {
    fprintf(stderr, "Couldn't set datalink type: %s\n", pcap_geterr(handle));
    pcap_close(handle);
    return 1;
  }

  active_handle = handle;

  /* Blocks until pcap_breakloop() is called or an error occurs. */
  int result = pcap_loop(handle, -1, packet_capture_handler, NULL);
  if (result == PCAP_ERROR) {
    fprintf(stderr, "Error during capture: %s\n", pcap_geterr(handle));
  }

  active_handle = NULL;
  pcap_close(handle);
  return (result == PCAP_ERROR) ? 1 : 0;
}

/*
  * Stop an active capture (safe to call from any thread).
  * @return: 0 on success
*/
int stop_packet_capture(void) {
  if (active_handle != NULL) {
    pcap_breakloop(active_handle);
  }
  return 0;
}

/* ---- standalone build (Makefile) ---- */
#ifndef CGO_BUILD

int main() {
  char **interfaces;
  int count;

  if (get_all_interfaces(&interfaces, &count) != 0) {
    fprintf(stderr, "Failed to get interfaces\n");
    return 1;
  }

  for (int i = 0; i < count; i++) {
    printf("%d: %s\n", i, interfaces[i]);
  }

  int interface_index;
  printf("Enter the interface number to capture on: ");
  scanf("%d", &interface_index);
  if (interface_index < 0 || interface_index >= count) {
    fprintf(stderr, "Invalid interface number\n");
    free_all_interfaces(interfaces, count);
    return 1;
  }

  if (start_packet_capture(interfaces[interface_index]) != 0) {
    fprintf(stderr, "Failed to capture on interface\n");
    return 1;
  }

  free_all_interfaces(interfaces, count);

  return 0;
}

#endif /* CGO_BUILD */