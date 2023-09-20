#include <stdlib.h>
#include <stdio.h>
#include <pcap.h>  //libpcap 라이브러리 호출
#include "myheader.h" // myheader.h 포함, 해당 헤더 파일에 패킷 헤더 구조 정의

	// 캡처한 패킷의 정보 및 출력 형식
void got_packet(u_char *args, const struct pcap_pkthdr *header,
                              const u_char *packet)
{
  struct ethheader *eth = (struct ethheader *)packet;

  if (ntohs(eth->ether_type) == 0x0800) { // 0x0800 is IP type
    struct ipheader * ip = (struct ipheader *)
                           (packet + sizeof(struct ethheader)); 

    if (ip->iph_protocol == IPPROTO_TCP) {
      struct tcphdr *tcp = (struct tcphdr *)(packet + sizeof(struct ethheader) + (ip->iph_ihl << 2));

      printf("Ethernet Source MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",
             eth->ether_shost[0], eth->ether_shost[1],
             eth->ether_shost[2], eth->ether_shost[3],
             eth->ether_shost[4], eth->ether_shost[5]);

      printf("Ethernet Destination MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",
             eth->ether_dhost[0], eth->ether_dhost[1],
             eth->ether_dhost[2], eth->ether_dhost[3],
             eth->ether_dhost[4], eth->ether_dhost[5]);

      printf("       From: %s\n", inet_ntoa(ip->iph_sourceip));   
      printf("         To: %s\n", inet_ntoa(ip->iph_destip));    
      
      printf("   Protocol: TCP\n");
      printf("   Source Port: %u\n", ntohs(tcp->th_sport));
      printf("   Destination Port: %u\n", ntohs(tcp->th_dport));

      // TCP header 구조 생성 
      struct tcpheader *tcph = (struct tcpheader *)tcp;

		  // TCP header 길이 계산
      int tcp_header_length = tcph->tcph_off * 4;

      // payload 찾기
      u_char *payload = (u_char *)(packet + sizeof(struct ethheader) + (ip->iph_ihl << 2) + tcp_header_length);

      // payload 길이 계산 
      int payload_length = ntohs(ip->iph_len) - (ip->iph_ihl << 2) - tcp_header_length;

      // TCP payload 출력 (message)
      if (payload_length > 0) {
        printf("   Message:\n");
        for (int i = 0; i < payload_length; i++) {
          printf("%c", payload[i]);
        }
        printf("\n");
      }

      printf("---------------------------------------------\n");
    }
  }
}

int main()
{
  pcap_t *handle;
  char errbuf[PCAP_ERRBUF_SIZE];
  struct bpf_program fp;
  char filter_exp[] = ""; // 패킷 필터 표현식을 저장하는 부분, 비어 있을시 모든 패킷을 캡처
  bpf_u_int32 net;

  // Step 1: NIC에서 라이브PCAP 세션 열기
  handle = pcap_open_live("enp3s0f0", BUFSIZ, 1, 1000, errbuf);

  // Step 2: filter_exp를 BPF(Berkeley Packet Filter) 형식의 코드로 컴파일 
  pcap_compile(handle, &fp, filter_exp, 0, net);
  if (pcap_setfilter(handle, &fp) !=0) {
      pcap_perror(handle, "Error:");
      exit(EXIT_FAILURE);
  }

  // Step 3: 패킷 캡처
  pcap_loop(handle, -1, got_packet, NULL);

  pcap_close(handle);   //handle 종료
  return 0;
}

