#include "trace_parser.h"

namespace fs = boost::filesystem;
namespace io = boost::iostreams;

void got_packet(const u_char *packet, pcap_pkthdr * header, io::filtering_ostream &out, double *starttime)
{
	/* declare pointers to packet headers */
	const struct sniff_ethernet *ethernet;  /* The ethernet header [1] */
	const struct sniff_etherVPN *etherVPN;  /* The ethernet header [1] */
	const struct sniff_ip *ip;              /* The IP header */
	const struct sniff_tcp *tcp;            /* The TCP header */
	struct sniff_udp *udp;            /* The Udp header */
	//struct sniff_icmp *icmp;			/* The ICMP header*/
	int size_ip;
	//int size_tcp;
	//int size_payload;
	//int size_udp;
     
    
	/* define ethernet header */
	ethernet = (struct sniff_ethernet*)(packet);
	//printf("%x: ", ntohs(ethernet->ether_type));

	/* define/compute ip header offset */
	int vpnoffset = 0;
	
	if (*starttime < 0){ // Jesus born
		*starttime = header->ts.tv_sec;
	}

	if (ntohs(ethernet->ether_type) == 0x0800) // avgIP
		ip = (struct sniff_ip*)(packet + SIZE_ETHERNET);
	else{
		if (ntohs(ethernet->ether_type) == 0x8100){ // vpn
			etherVPN = (struct sniff_etherVPN*)(packet);
			if (etherVPN->ether_type == 0x0800){
				vpnoffset = 4;
				ip = (struct sniff_ip*)(packet + SIZE_ETHERNET + vpnoffset);
			}
			else 
				return;
		}
		else
			return;
	}

	size_ip = IP_HL(ip)*4;
	if (size_ip < 20) {
		return; // invalid ip header
	}
    	
	//std::cout<<counter<<"  From: "<< inet_ntoa(ip->ip_src) << " To: "<< inet_ntoa(ip->ip_dst);
	
	switch(ip->ip_p) 
	{
		case IPPROTO_TCP: 
			{

				tcp = (struct sniff_tcp*)(packet + SIZE_ETHERNET + vpnoffset + size_ip);
				//std::cout<< " Protocol: TCP "<<" From: "<<ntohs(tcp->th_sport) << " To: " << ntohs(tcp->th_dport);
				double ts= header->ts.tv_sec - (*starttime);
				ts += double(header->ts.tv_usec)/1000000;
				out<<ts<<"%"<<inet_ntoa(ip->ip_src)<<"%"<<inet_ntoa(ip->ip_dst)<<"%"<<ntohs(tcp->th_sport)<<"%"<<ntohs(tcp->th_dport)<<"%6"<<std::endl;
				break;
			}
                              
		case IPPROTO_UDP:
			{
				udp = (struct sniff_udp*)(packet + SIZE_ETHERNET + vpnoffset + size_ip);
				//std::cout<< " Protocol: UDP "<<" From: "<<ntohs(udp->udp_sport) << " To: "<< ntohs(udp->udp_dport);
				double ts= header->ts.tv_sec - (*starttime);
				ts += double(header->ts.tv_usec)/1000000;
				out<<ts<<"%"<<inet_ntoa(ip->ip_src)<<"%"<<inet_ntoa(ip->ip_dst)<<"%"<<ntohs(udp->udp_sport)<<"%"<<ntohs(udp->udp_dport)<<"%6"<<std::endl;
				break;
			}
		default:
				break;
	}
	
	//std::cout<<std::endl; 
	
	return;
}


void ParseTrace(const char* src_dir, const char* sav_file, size_t max_term)
{
	fs::path dir(src_dir);
	fs::directory_iterator end;
	std::ofstream log(sav_file);
	if (fs::exists(dir) && fs::is_directory(dir)){
		for( fs::directory_iterator itr(dir); itr != end; ++itr){
			if (fs::is_regular_file(itr->status())){
				double starttime = -1;
				std::cout << itr->path().c_str() <<std::endl;
				int len = sizeof(itr->path().filename().c_str());
				char newname[len+5];
				strcpy(newname, itr->path().filename().c_str());
				strcat(newname, ".gz");
				std::ofstream outfile(newname);
				outfile.precision(16);
				size_t counter = 0; // debug
				try{
					io::filtering_ostream out;
					out.push(io::gzip_compressor());
					out.push(outfile);
					out.precision(16);
					FILE *file ;
      					file= fopen( itr->path().c_str() ,"r");
					char ebuf[PCAP_ERRBUF_SIZE];
					pcap_t * pHandle = pcap_fopen_offline(file, ebuf);
					struct pcap_pkthdr* header;
					const u_char * packet;
					int res;
					while((res = pcap_next_ex(pHandle, &header, &packet))>=0)
					{
						counter ++; //debug
						if (max_term != 0 && counter > max_term )
							break;
						got_packet(packet, header, out, &starttime);
					}
					fclose(file);
				}catch(const io::gzip_error & e){
					std::cout<<e.what()<<std::endl;
				}
				outfile.close();
				log.precision(16);
				log<<newname<< " : "<< starttime<<std::endl;
			}
		}
	}
	log.close();
}
