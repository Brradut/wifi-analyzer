FLAGS = -Wall -Wextra -Werror -O2
output_folder = ${OUTPUT_FOLDER}

default: scanner sniffer

scanner: wifi-scanner.c
	gcc $(pkg-config --cflags libpcap) \
	${FLAGS} \
	wifi-scanner.c \
	-o ${output_folder}wifi-analyzer \
	$$(pkg-config --libs libpcap)

sniffer: packet-sniffer.c
	gcc $(pkg-config --cflags libpcap) \
	${FLAGS} \
	packet-sniffer.c \
	-o ${output_folder}packet-sniffer \
	$$(pkg-config --libs libpcap)
clean:
	rm -f ${output_folder}wifi-analyzer