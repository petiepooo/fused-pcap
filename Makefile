all: fused_pcap

fused_pcap: main.c
	gcc -Wall main.c `pkg-config fuse --cflags --libs` -o fused_pcap

clean:
	rm fused_pcap
