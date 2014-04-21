/*
 * @file simplesniffer.c
 *
 * @author Akagi201
 * @date 2014/04/21
 *
 * gcc simplesniffer.c -o simplesniffer -lpcap
 *
 */

#include <pcap.h>
#include <string.h>
#include <stdlib.h>

#define MAXBYTES2CAPTURE (2048)

void process_packet(u_char *arg, const struct pcap_pkthdr *pkthdr, const u_char *packet) {
	int i = 0;
	int *counter = (int *)arg;
	
	printf("Packet Count: %d\n", ++(*counter));
	printf("Received Packet Size: %d\n", pkthdr->len);
	printf("Payload:\n");
	for (i = 0; i < pkthdr->len; ++i){
		if (isprint(packet[i])) {
			printf("%c ", packet[i]);
		} else {
			printf(". ");
		}
		
		if (((i % 16 == 0) && (i != 0)) || (i == pkthdr->len - 1)) {
			printf("\n");
		}
	}
	
	return;
}

int main(void) {
	int i = 0;
	int count = 0;
	pcap_t *descr = NULL;
	char errbuf[PCAP_ERRBUF_SIZE] = {0};
	char *device = NULL;
	
	memset(errbuf, 0, PCAP_ERRBUF_SIZE);
	
	//printf("errbuf size: %d\n", PCAP_ERRBUF_SIZE); // 256
	
	/* 获取第一个适合捕获的网络设备名称 */
	device = pcap_lookupdev(errbuf);
	
	printf("Open device %s\n", device); // eth0

	/* 以混杂模式打开网络设备 */
	descr = pcap_open_live(device, MAXBYTES2CAPTURE, 1, 512, errbuf);
	
	/* 死循环并在每一次接收到数据包时调用回调函数process_packet() */
	pcap_loop(descr, -1, process_packet, (u_char *)&count);
	
	return 0;
}

