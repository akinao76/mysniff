#ifndef MYHEADER_H
#define MYHEADER_H

#include <pcap.h>
#include <arpa/inet.h>
#include <netinet/tcp.h>

/* Ethernet header */
struct ethheader {
  u_char  ether_dhost[6]; /* destination host address */
  u_char  ether_shost[6]; /* source host address */
  u_short ether_type;     /* protocol type (IP, ARP, RARP, etc) */
};

/* IP Header */
struct ipheader {
	unsigned char      iph_ihl:4, //IP header length
                     iph_ver:4; //IP version
  unsigned char      iph_tos; //Type of service
  unsigned short int iph_len; //IP Packet length (data + header)
  unsigned short int iph_ident; //Identification
  unsigned short int iph_flag:3, //Fragmentation flags
                     iph_offset:13; //Flags offset
  unsigned char      iph_ttl; //Time to Live
  unsigned char      iph_protocol; //Protocol type
  unsigned short int iph_chksum; //IP datagram checksum
  struct  in_addr    iph_sourceip; //Source IP address
  struct  in_addr    iph_destip;   //Destination IP address
};

/* TCP Header */
struct tcpheader {
  unsigned short int tcph_sport; // Source port
  unsigned short int tcph_dport; // Destination port
  unsigned int       tcph_seqnum; // Sequence number
  unsigned int       tcph_acknum; // Acknowledgment number
  unsigned char      tcph_off:4,  // Data offset
                     tcph_res:4;  // Reserved
  unsigned char      tcph_flags;  // Flags
  unsigned short int tcph_win;    // Window size
  unsigned short int tcph_chksum; // Checksum
  unsigned short int tcph_urgptr; // Urgent pointer
};

void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet);

#endif
