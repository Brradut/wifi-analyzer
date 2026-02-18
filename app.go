package main

import (
	// #cgo pkg-config: libpcap
	// #cgo CFLAGS: -Wall -Wextra -Werror -O2 -DCGO_BUILD -Wno-unused-parameter
	// #cgo LDFLAGS: -Wl,-rpath,$ORIGIN/lib -lpthread
	// #include <stdlib.h>
	// #include "wifi-scanner.h"
	// #include "packet-sniffer.h"
	"C"
	"unsafe"

	"context"
	"fmt"

	"github.com/wailsapp/wails/v2/pkg/runtime"
)

// Global reference so the exported C callback can reach the Wails context.
var (
	appInstance *App
)

// App struct
type App struct {
	ctx context.Context
}

// NewApp creates a new App application struct
func NewApp() *App {
	a := &App{}
	appInstance = a
	return a
}

// startup is called when the app starts. The context is saved
// so we can call the runtime methods
func (a *App) startup(ctx context.Context) {
	a.ctx = ctx
}

func (a *App) GetInterfaces(monitor bool) []string {
	var interfaces **C.char
	var length C.int

	if monitor {
		C.get_monitor_interfaces(&interfaces, &length)
	} else {
		C.get_all_interfaces(&interfaces, &length)
	}
	println("Number of interfaces found:", length)

	var interfaceList []string
	for _, v := range unsafe.Slice(interfaces, length) {
		interfaceList = append(interfaceList, C.GoString(v))
	}

	return interfaceList
}

// StartMonitoring begins capturing beacons on the given interface.
// The capture runs in a background goroutine so the UI is never blocked.
func (a *App) StartMonitoring(interfaceName string) string {

	go func() {
		cName := C.CString(interfaceName)
		defer C.free(unsafe.Pointer(cName))

		result := C.start_capture(cName)

		if result != 0 {
			fmt.Println("Capture ended with error")
		} else {
			fmt.Println("Capture stopped cleanly")
		}
	}()

	return "ok"
}

func (a *App) StopMonitoring() {
	C.stop_capture()
}

// on_network_found is called from C's packet_handler for every beacon frame.
// It emits a Wails event so the Vue frontend can react in real time.

//export on_network_found
func on_network_found(ssid *C.char, bssid *C.char, channel C.int, frequency C.int, signalStrength C.int) {
	if appInstance == nil || appInstance.ctx == nil {
		return
	}

	runtime.EventsEmit(appInstance.ctx, "network:found", map[string]any{
		"ssid":           C.GoString(ssid),
		"bssid":          C.GoString(bssid),
		"channel":        int(channel),
		"frequency":      int(frequency),
		"signalStrength": int(signalStrength),
	})
}

// StartPacketCapture begins capturing packets on the given interface.
// The capture runs in a background goroutine so the UI is never blocked.
func (a *App) StartPacketCapture(interfaceName string) string {

	go func() {
		cName := C.CString(interfaceName)
		defer C.free(unsafe.Pointer(cName))

		result := C.start_packet_capture(cName)

		if result != 0 {
			fmt.Println("Packet capture ended with error")
		} else {
			fmt.Println("Packet capture stopped cleanly")
		}
	}()

	return "ok"
}

func (a *App) StopPacketCapture() {
	C.stop_packet_capture()
}

// on_packet_captured is called from C's packet_handler for every captured packet.
// It emits a Wails event so the Vue frontend can react in real time.

//export on_packet_captured
func on_packet_captured(srcMac *C.char, destMac *C.char, ethType *C.char,
	srcIPv4 *C.char, destIPv4 *C.char,
	srcIPv6 *C.char, destIPv6 *C.char,
	srcPort C.int, destPort C.int,
	payload *C.char, payloadLength C.int) {

	if appInstance == nil || appInstance.ctx == nil {
		return
	}

	payloadString := ""
	for i := C.int(0); i < payloadLength; i++ {
		payloadString += string(*(*byte)(unsafe.Pointer(uintptr(unsafe.Pointer(payload)) + uintptr(i))))
	}

	runtime.EventsEmit(appInstance.ctx, "packet:captured", map[string]any{
		"srcMac":   C.GoString(srcMac),
		"destMac":  C.GoString(destMac),
		"ethType":  C.GoString(ethType),
		"srcIPv4":  C.GoString(srcIPv4),
		"destIPv4": C.GoString(destIPv4),
		"srcIPv6":  C.GoString(srcIPv6),
		"destIPv6": C.GoString(destIPv6),
		"srcPort":  int(srcPort),
		"destPort": int(destPort),
		"payload":  payloadString,
	})
}
