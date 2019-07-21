#include <pcap.h>
#include <stdio.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#define ETHER_ADDR_LEN	6
#define TYPE_IPV4 0x0800
#define TYPE_TCP 0x6
#define ETHERNET_SIZE 14

struct sniff_ethernet {
		u_char ether_dhost[ETHER_ADDR_LEN];
		u_char ether_shost[ETHER_ADDR_LEN];
		u_short ether_type;
};

struct sniff_ip {
		u_char ip_vhl;
		u_char ip_tos;
		u_short ip_len;
		u_short ip_id;
		u_short ip_off;
		u_char ip_ttl;
		u_char ip_p;
		u_short ip_sum;
		struct in_addr ip_src,ip_dst;
};

struct sniff_tcp {
		u_short th_sport;
		u_short th_dport;
		u_int th_seq;
		u_int th_ack;
		u_char th_offset;
		u_char th_flags;
		u_short th_win;
		u_short th_sum;
		u_short th_urp;
};

#define TH_OFF(th)	(((th)->th_offx2 & 0xf0) >> 4)

void usage() {
  printf("syntax: pcap_test <interface>\n");
  printf("sample: pcap_test wlan0\n");
}

void print_packet_info(struct sniff_ethernet * ethernet, struct sniff_ip * ip, struct sniff_tcp * tcp, u_char * data, u_int data_size){
	printf("Dest Mac : %02x-%02x-%02x-%02x-%02x-%02x\n", ethernet->ether_dhost[0],ethernet->ether_dhost[1],ethernet->ether_dhost[2],ethernet->ether_dhost[3],ethernet->ether_dhost[4],ethernet->ether_dhost[5]);
	printf("Dest IP : %s\n", inet_ntoa(ip->ip_dst));
	printf("Dest Port : %u\n\n", ntohs(tcp->th_dport));
	printf("Src Mac : %02x-%02x-%02x-%02x-%02x-%02x\n", ethernet->ether_shost[0],ethernet->ether_shost[1],ethernet->ether_shost[2],ethernet->ether_shost[3],ethernet->ether_shost[4],ethernet->ether_shost[5]);
	printf("Src IP : %s\n", inet_ntoa(ip->ip_src));
	printf("Src Port : %u\n\n", ntohs(tcp->th_sport));

	printf("---------------Data(Max 10 bytes)---------------\n");
	for(int i=0; i<10 && i<data_size; i++) printf("%02x ", data[i]);
	printf("\n-----------------------------------------------_\n\n\n");
}

int main(int argc, char* argv[]) {
  if (argc != 2) {
    usage();
    return -1;
  }

  char* dev = argv[1];
  char errbuf[PCAP_ERRBUF_SIZE];
  pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
  if (handle == NULL) {
    fprintf(stderr, "couldn't open device %s: %s\n", dev, errbuf);
    return -1;
  }

  while (true) {
    struct pcap_pkthdr* header;
    const u_char* packet;
		u_char * data;
		u_int ip_size, tcp_size, data_size;

    int res = pcap_next_ex(handle, &header, &packet);
    if (res == 0) continue;
    if (res == -1 || res == -2) break;

		struct sniff_ethernet * ethernet = (struct sniff_ethernet *)packet;
		if(ntohs(ethernet->ether_type) != TYPE_IPV4) continue;

		struct sniff_ip * ip = (struct sniff_ip *)(packet + ETHERNET_SIZE);
		ip_size = (((ip)->ip_vhl) & 0x0f)
		if(ip->ip_p != TYPE_TCP) continue;

		struct sniff_tcp * tcp = (struct sniff_tcp *)(packet + ETHERNET_SIZE + ip_size);
		tcp_size = (((tcp)->th_offset & 0xf0) >> 4)*4;
		data = (u_char*)(packet + ETHERNET_SIZE + ip_size + tcp_size);
		data_size = header->caplen - (data-packet);

		print_packet_info(ethernet, ip, tcp, data, data_size);
  }

  pcap_close(handle);
  return 0;
}
