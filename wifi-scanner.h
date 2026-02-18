#ifndef WIFI_SCANNER_H
#define WIFI_SCANNER_H

int get_monitor_interfaces(char **interfaces[], int *count);
int free_monitor_interfaces(char **interfaces, int count);
int start_capture(const char *interface_name);
int stop_capture(void);

/* Callback implemented in Go (via //export) when built with cgo,
   or in C for standalone builds. Called for every beacon frame. */
extern void on_network_found(char *ssid, char *bssid,
                             int channel, int frequency,
                             int signal_strength);

#endif /* WIFI_SCANNER_H */