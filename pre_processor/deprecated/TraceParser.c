
#include <pcap.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

/* default snap length (maximum bytes per packet to capture) */
#define SNAP_LEN 65535

/* ethernet headers are always exactly 14 bytes [1] */
#define SIZE_ETHERNET 14

/* Ethernet addresses are 6 bytes */
#define ETHER_ADDR_LEN	6

/************ feature variables ends here ***************/

/* Ethernet header */
struct sniff_ethernet {
        u_char  ether_dhost[ETHER_ADDR_LEN];    /* destination host address */
        u_char  ether_shost[ETHER_ADDR_LEN];    /* source host address */
        u_short ether_type;                     /* IP? ARP? RARP? etc */
};

/* IP header */
struct sniff_ip {
          u_char  ip_vhl;                 /* version << 4 | header length >> 2 */
          u_char  ip_tos;                 /* type of service */
          u_short ip_len;                 /* total length */
          u_short ip_id;                  /* identification */
          u_short ip_off;                 /* fragment offset field */
          #define IP_RF 0x8000            /* reserved fragment flag */
          #define IP_DF 0x4000            /* dont fragment flag */
          #define IP_MF 0x2000            /* more fragments flag */
          #define IP_OFFMASK 0x1fff       /* mask for fragmenting bits */
          u_char  ip_ttl;                 /* time to live */
          u_char  ip_p;                   /* protocol */
          u_short ip_sum;                 /* checksum */
	  struct  in_addr ip_src,ip_dst;  /* source and dest address */
};

struct sniff_icmp
{
	u_char icmp_type;
	u_char icmp_code;
	u_short icmp_checksum;
};

#define IP_HL(ip)               (((ip)->ip_vhl) & 0x0f)
#define IP_V(ip)                (((ip)->ip_vhl) >> 4)
#define IP_Flag(ip)                (((ip)->ip_off) & 0xD0)
#define IP_off(ip)                (((ip)->ip_off) & 0x1F)

/* TCP header */
typedef u_int tcp_seq;

struct sniff_tcp {
        u_short th_sport;               /* source port */
        u_short th_dport;               /* destination port */
        tcp_seq th_seq;                 /* sequence number */
        tcp_seq th_ack;                 /* acknowledgement number */
       // tcp_seq th_syn;
       // tcp_seq th_fin;
        //tcp_seq th_urg;
        u_char  th_offx2;               /* data offset, rsvd */
	#define TH_OFF(th)      (((th)->th_offx2 & 0xf0) >> 4)
        u_char  th_flags;
        #define TH_FIN  0x01
        #define TH_SYN  0x02
        #define TH_RST  0x04
        #define TH_PUSH 0x08
        #define TH_ACK  0x10
        #define TH_URG  0x20
        #define TH_ECE  0x40
        #define TH_CWR  0x80
        #define TH_FLAGS        (TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR)
        u_short th_win;                 /* window */
        u_short th_sum;                 /* checksum */
        u_short th_urp;                 /* urgent pointer */
};
struct sniff_udp {
        u_short udp_sport;               /* source port */
        u_short udp_dport;               /* destination port */
        u_short udp_hlen;		/* Udp header length*/
        u_short udp_chksum;		/* Udp Checksum */
	};



void got_packet(const u_char *packet)
{
	/* declare pointers to packet headers */
	const struct sniff_ethernet *ethernet;  /* The ethernet header [1] */
	const struct sniff_ip *ip;              /* The IP header */
	const struct sniff_tcp *tcp;            /* The TCP header */
	struct sniff_udp *udp;            /* The Udp header */
	struct sniff_icmp *icmp;			/* The ICMP header*/
	int size_ip;
	int size_tcp;
	int size_payload;
	int size_udp;
     
    
	/* define ethernet header */
	ethernet = (struct sniff_ethernet*)(packet);


	/* define/compute ip header offset */
	ip = (struct sniff_ip*)(packet + SIZE_ETHERNET);
	size_ip = IP_HL(ip)*4;
	if (size_ip < 20) {
		printf("   * Invalid IP header length: %u bytes\n", size_ip);
		return;
	}
    
	/* print source and destination IP addresses */
	printf("    From: %s", inet_ntoa(ip->ip_src));
	printf("    To: %s", inet_ntoa(ip->ip_dst));


	switch(ip->ip_p) 
	{
		case IPPROTO_TCP: 
			{
				tcp = (struct sniff_tcp*)(packet + SIZE_ETHERNET + size_ip);
				size_tcp = TH_OFF(tcp)*4;
				if (size_tcp < 20){
					printf("   * Invalid TCP header length: %u0 bytes\n", size_tcp);
					return;
				}
				printf("   Protocol: TCP");
				printf("   From: %d", ntohs(tcp->th_sport));
				printf("   To: %d", ntohs(tcp->th_dport));
				break;
			}
                              
		case IPPROTO_UDP:
			{
				udp = (struct sniff_udp*)(packet + SIZE_ETHERNET + size_ip);
				size_udp = TH_OFF(tcp)*4;
				
				if (size_udp < 8) {
					printf("   * Invalid TCP header length: %u0 bytes\n", size_udp);
					return;
				}
				printf("   Protocol: UDP");
				printf("   From: %d", ntohs(udp->udp_sport));
				printf("   To: %d", ntohs(udp->udp_dport));
				break;
			}
		default:
				break;
	}
	
	printf("\n");	
	
	return;
}



//int main(int argc, char **argv)
int main()
{
	int num_packets = 0;			/* number of packets to capture */
	FILE *file ;
      	file= fopen("tracetest","r");
	char *ebuf;
	pcap_t * pHandle = pcap_fopen_offline(file, ebuf);
	struct pcap_pkthdr* header;
	int counter = 0;

	const u_char * packet;
	
	while(1)
	{
		pcap_next_ex(pHandle, &header, &packet);
		if (packet == NULL)
			break;
		got_packet(packet);
		counter ++;
		if (counter == 100)
			break;
	}
	
	fclose(file);
	printf("\nCapture complete.\n");

	return 0;
}
