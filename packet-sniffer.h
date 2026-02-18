#ifndef PACKET_SNIFFER_H
#define PACKET_SNIFFER_H


int get_all_interfaces(char **interfaces[], int *count);
int free_all_interfaces(char **interfaces, int count);

int start_packet_capture(const char *interface_name);
int stop_packet_capture(void);

/* Callback implemented in Go (via //export) when built with cgo,
   or in C for standalone builds. Called for every captured packet. */
extern void on_packet_captured(
    char *src_mac, char *dest_mac, char *eth_type,
    char *src_ipv4, char *dest_ipv4,
    char *src_ipv6, char *dest_ipv6,
    int src_port, int dest_port,
    char *payload, int payload_length);

#endif /* PACKET_SNIFFER_H */
