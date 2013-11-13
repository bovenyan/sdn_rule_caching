//
//  try.cpp
//  
//
//  Created by Hongya Xing on 13-4-29.
//  Copyright (c) 2013年 NYU-Poly. All rights reserved.
//

#include <iostream>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <time.h>
#include <cstdio>
#include <deque>
#include <math.h>


#include <fstream>
#include <vector>
#include <sstream>
#include <cstdlib>
#include <cstring>
#include <cctype>
#include <arpa/inet.h>

#include <pcap.h>
#include <string.h>
#include <ctype.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>

#define MAX_STRING  1000        // Max length of matching string

using namespace std;

struct pkt_header_t{
    int             id;
    unsigned int             src_ip;
    unsigned int             dst_ip;
    int             src_port;
    int             dst_port;
    int             protocol;
};/* packet header structure*/


vector<struct pkt_header_t> header_vec;

int main(int argc, char * argv[]){
    ifstream        header_file("test_hdr.txt");
    string          headerline;
    int hdr_id=1;
    
    if(header_file.is_open()){
	printf("succeed!\n");
        while(getline(header_file, headerline)){
	    printf("here\n");
            stringstream header_strs(headerline);
            pkt_header_t pkt_header;
            char hdr_src_ip[10]="";
            char hdr_dst_ip[10]="";
            char hdr_src_port[10]="";
            char hdr_dst_port[10]="";
            char hdr_protocol[10]="";
            char hdr_rest[10]="";	
            char match_str[MAX_STRING]="";
            //printf("%d\n",hdr_src_ip); 
            header_strs >> hdr_src_ip >> hdr_dst_ip >> hdr_src_port >> hdr_dst_port >> hdr_protocol;
            header_strs.getline(match_str, MAX_STRING);
            printf("%s,%s,%s,%s,%s\n",hdr_src_ip,hdr_dst_ip,hdr_src_port,hdr_dst_port,hdr_protocol);
	    printf("%u\n",atoi(hdr_src_ip)); 
            if(strcmp(match_str,"\0")==0){break;}
            
   	    printf("w?"); 
            pkt_header.id=hdr_id;
            printf("Header ID: %d",pkt_header.id);
           
	    printf("here?"); 
            pkt_header.src_ip=atoi(hdr_src_ip);
            pkt_header.dst_ip=atoi(hdr_dst_ip);
            pkt_header.src_port=atoi(hdr_src_port);
            pkt_header.dst_port=atoi(hdr_dst_port);
            pkt_header.protocol=atoi(hdr_protocol);
            
            header_vec.push_back(pkt_header);
            hdr_id++;
            
        }
    }
    else{printf("what?");}
    
    
    vector<struct pkt_header_t>::iterator it;
    //printf("ok?\n");
    for(it=header_vec.begin();it<header_vec.end();it++){
        printf("\n%d, %u, %u, %d, %d,%d",it->id,it->src_ip,it->dst_ip,it->src_port,it->dst_port,it->protocol);
    }
    
    return 0;
}
