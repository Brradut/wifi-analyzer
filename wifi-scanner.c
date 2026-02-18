#include <pcap/pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include "wifi-scanner.h"

struct ieee80211_radiotap_header {
  u_int8_t it_version; // should be 0
  u_int8_t it_pad;
  u_int16_t it_len; // entire length of the header in bytes
  u_int32_t it_present; // fields present in the header
};

struct network_info {
  u_int8_t channel;
  int8_t signal_strength; // in dBm
  u_int16_t frequency; // in MHz
  char ssid[33]; // SSID can be up to 32 bytes + null terminator
  char bssid[19]; // BSSID (MAC address) in string format "xx:xx:xx:xx:xx:xx"
};

/*
Given a raw beacon frame and its length, extract the network information.
@param packet: The raw packet data containing the beacon frame.
@param length: The length of the packet data.
@return: A pointer to a network_info struct containing the extracted information, or NULL if the packet is not a beacon frame.
*/
struct network_info* get_network_info(const u_char* packet, int length) {
  (void)length; // Unused parameter
  // Extract radiotap header
  struct ieee80211_radiotap_header *rtap = (struct ieee80211_radiotap_header *)packet;
  struct network_info* info = malloc(sizeof(struct network_info));
  memset(info, 0, sizeof(struct network_info));

  int offset = 8; // End of first bitmap

  int is_extended = 1;
  do {
    if (*(u_int32_t *)(packet + offset - 4) & (1 << 31)) { // Check if the extended bit is set
      offset += 4; // Move to the next bitmap
    } else {
      is_extended = 0; // No more extended headers
    }
  }while (is_extended);


  if (rtap->it_present & (1 << 0)) offset += (8 - offset%8)%8 + 8; // Skip TSFT field
  if (rtap->it_present & (1 << 1)) offset += 1; // Skip flags field
  if (rtap->it_present & (1 << 2)) offset += 1; // Skip rate field  
  if (rtap->it_present & (1 << 3)) { // Get channel frequency
    // align to 2 bytes
    offset += (2 - offset%2) % 2;
    info->frequency = *(u_int16_t *)(packet + offset);
    offset += 4;
  }
  if (rtap->it_present & (1 << 4)) offset += (2 - offset%2)%2 + 2; // Skip FHSS field
  if (rtap->it_present & (1 << 5)) { // Get signal strength
    info->signal_strength = (int8_t)packet[offset];
    offset += 1;
  }
  // The other fields are ignored

  
  offset = rtap->it_len; // Start of the 802.11 frame
  // Check if it's a beacon frame
  if (packet[offset] != 0x80) {
    printf("Not a beacon frame, skipping...\n");
    return NULL;
  }
  offset += 16; // Skip other fields
  // Extract the BSSID (MAC address of the access point)
  for (int i = 0; i < 5; i++) {
    sprintf(info->bssid + i * 3, "%02x:", packet[offset + i]); // Convert byte to hex string
  }
  sprintf(info->bssid + 15, "%02x", packet[offset + 5]);
  
  offset += 8; // Go to the end of the beacon frame header
  offset += 12; // Skip timestamp, beacon interval, and capability info

  //Extract the tagged parameters
  while (offset < length) {
    u_int8_t tag_number = packet[offset];
    u_int8_t tag_length = packet[offset + 1];
    offset += 2; // Move to the start of the tag data

    switch(tag_number) {
      case 0: // SSID
        for (int i = 0; i < tag_length; i++) {
          info->ssid[i] = packet[offset + i];
        }
        info->ssid[tag_length] = '\0';
        break;
      case 3: // DS Parameter Set (Channel)
        info->channel = (u_int8_t)packet[offset];
        break;
      default: // Skip other tags
        break;
    }
    offset += tag_length; // Move to the next tag
  }

  return info;
}

/*
  * Free the memory allocated for a network_info struct.
  * @param info: The pointer to the network_info struct to free.
*/
void free_network_info(struct network_info* info) {
  free(info);
}


/*
  * Get a list of network interfaces that support monitor mode.
  * @param interfaces: A pointer to an array of strings to store the interface names.
  * @param count: A pointer to an integer to store the number of interfaces found.
  * @return: 0 on success, 2 on error
*/
int get_monitor_interfaces(char **interfaces[], int *count) {
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
      if (pcap_can_set_rfmon(dev) == 1)
        (*count)++;
  }

  *interfaces = (char **)malloc((*count) * sizeof(char *));

  int i = 0; pcap_if_t *d = devs;
  while (d != NULL && i < *count) {
    pcap_t *dev = pcap_create(d->name, errbuf);
    if (dev == NULL) {
        continue;
    }
    if (pcap_can_set_rfmon(dev) == 1){
      (*interfaces)[i] = (char *)malloc((strlen(d->name) + 1) * sizeof(char));
      strcpy((*interfaces)[i], d->name);
      i++;
    } 
    d = d->next;
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
int free_monitor_interfaces(char **interfaces, int count) {
  for (int i = 0; i < count; i++) {
    free(interfaces[i]);
  }
  free(interfaces);
  return 0;
}

/* Global handle so stop_capture() can break the loop from any thread. */
static pcap_t *active_handle = NULL;

void packet_handler(u_char *user, const struct pcap_pkthdr *header, const u_char *packet) {
  (void)user;

  struct network_info* info = get_network_info(packet, header->len);
  if (info != NULL) {
    on_network_found(info->ssid, info->bssid,
                     info->channel, info->frequency,
                     info->signal_strength);
    free(info);
  }
}

/*
  * Start capturing beacon frames on the given interface (monitor mode).
  * Blocks until stop_capture() is called or an error occurs.
  * @param interface_name: The name of the interface.
  * @return: 0 on success, 1 on error
*/
int start_capture(const char *interface_name) {
  char errbuf[PCAP_ERRBUF_SIZE];
  pcap_t *handle = pcap_create(interface_name, errbuf);
  if (handle == NULL) {
    fprintf(stderr, "Couldn't open device: %s\n", errbuf);
    return 1;
  }
  
  if(pcap_set_rfmon(handle, 1) != 0) {
    fprintf(stderr, "Couldn't set monitor mode: %s\n", pcap_geterr(handle));
    pcap_close(handle);
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

  if(pcap_set_datalink(handle, DLT_IEEE802_11_RADIO) != 0) {
    fprintf(stderr, "Couldn't set datalink type: %s\n", pcap_geterr(handle));
    pcap_close(handle);
    return 1;
  }

  struct bpf_program fp;
  if (pcap_compile(handle, &fp, "type mgt subtype beacon", 1, 0) != 0) {
    fprintf(stderr, "Couldn't compile filter: %s\n", pcap_geterr(handle));
    pcap_close(handle);
    return 1;
  }

  if(pcap_setfilter(handle, &fp) != 0) {
    fprintf(stderr, "Couldn't set filter: %s\n", pcap_geterr(handle));
    pcap_close(handle);
    return 1;
  }

  active_handle = handle;

  /* Blocks until pcap_breakloop() is called or an error occurs. */
  int result = pcap_loop(handle, -1, packet_handler, NULL);
  if (result == PCAP_ERROR) {
    fprintf(stderr, "Error during capture: %s\n", pcap_geterr(handle));
  }

  active_handle = NULL;
  pcap_freecode(&fp);
  pcap_close(handle);
  return (result == PCAP_ERROR) ? 1 : 0;
}

/*
  * Stop an active capture (safe to call from any thread).
  * @return: 0 on success
*/
int stop_capture(void) {
  if (active_handle != NULL) {
    pcap_breakloop(active_handle);
  }
  return 0;
}


/* ---- standalone build (Makefile) ---- */
#ifndef CGO_BUILD

void on_network_found(char *ssid, char *bssid,
                      int channel, int frequency,
                      int signal_strength) {
  printf("Network: SSID=%s  BSSID=%s  Ch=%d  Freq=%d MHz  Signal=%d dBm\n",
         ssid, bssid, channel, frequency, signal_strength);
}

int main() {
  char **interfaces;
  int count;

  if (get_monitor_interfaces(&interfaces, &count) != 0) {
    fprintf(stderr, "Failed to get monitor interfaces\n");
    return 1;
  }

  printf("Interfaces that support monitor mode:\n");
  for (int i = 0; i < count; i++) {
    printf("%d.%s\n", i, interfaces[i]);
  }

  int interface_index;
  printf("Enter the interface number to capture on: ");
  scanf("%d", &interface_index);
  if (interface_index < 0 || interface_index >= count) {
    fprintf(stderr, "Invalid interface number\n");
    free_monitor_interfaces(interfaces, count);
    return 1;
  }

  if (start_capture(interfaces[interface_index]) != 0) {
    fprintf(stderr, "Failed to capture on interface\n");
    return 1;
  }

  free_monitor_interfaces(interfaces, count);

  return 0;
}

#endif /* CGO_BUILD */