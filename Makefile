all: fused_pcap

fused_pcap: main.c
	gcc -Wall -D_FILE_OFFSET_BITS=64 -o fused_pcap main.c -lfuse

clean:
	rm fused_pcap
