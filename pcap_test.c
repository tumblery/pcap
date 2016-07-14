	#include <stdio.h>
        #include <pcap.h>
        #include <sys/socket.h>
        #include <netinet/in.h>
        #include <arpa/inet.h>
	#include <net/ethernet.h>
	#include <stdlib.h> 
	#include <string.h> 
	#include <netinet/ip.h>
	#include <netinet/tcp.h>
 
        #define PCAP_CNT_MAX 10
        #define PCAP_SNAPSHOT 1024
        #define PCAP_TIMEOUT 100
        
        void packet_view(unsigned char *, const struct pcap_pkthdr *, const unsigned char *);
        
        int main(int argc, char *argv[]) {
                char *dev;
                char errbuf[PCAP_ERRBUF_SIZE];
                bpf_u_int32 net;
                bpf_u_int32 netmask;
                struct in_addr net_addr, mask_addr;
                pcap_t *pd;
        
                if(!(dev = pcap_lookupdev(errbuf))) {
                        perror(errbuf);
                }
        
                if(pcap_lookupnet(dev, &net, &netmask, errbuf) < 0) {
                        perror(errbuf);
                }
        
                net_addr.s_addr = net;
                mask_addr.s_addr = netmask;
        
                printf("Device : %s\n", dev);
                printf("Net Address : %s\n", inet_ntoa(net_addr));
                printf("Netmask : %s\n", inet_ntoa(mask_addr));
        
                pd = pcap_open_live(dev, PCAP_SNAPSHOT, 1, PCAP_TIMEOUT, errbuf); 
                
        
                pcap_loop(pd, 0, packet_view, 0); 
                
        
                return 1;
        }
        void packet_view(unsigned char *user, const struct pcap_pkthdr *h, const unsigned char *p)
         {
                int len;
        
                len = 0;
        
		struct ip *iph;
                struct ether_header *ep;
		struct tcphdr *tcph;
                unsigned short e_type;


                ep = (struct ether_header *)p;

                e_type = ntohs(ep->ether_type);                         

                if( e_type ==  ETHERTYPE_IP ){
			printf("////////////////////////////////////////////////////////////////////////////////\n");
			p += sizeof(struct ether_header);
	                iph = (struct ip *) p;

			if( iph->ip_p == IPPROTO_TCP) { 

			  printf("PROTOCOL: tcp \n");
			  printf("------------------------------------------------------------------------\n");
                          printf("IP \n");
                          p += sizeof(struct ether_header);                         
                          printf("SRC IP= %s\n", inet_ntoa(iph->ip_src));
                          printf("DST IP= %s\n", inet_ntoa(iph->ip_dst));
                          printf("IP Version = %d\n", iph->ip_v);
			  printf("------------------------------------------------------------------------\n");
			  printf("MAP\n");
			  ep = (struct ether_header *) p;
			  printf("SRC MAP= %x-%x-%x-%x-%x-%x\n",ep->ether_shost[0],ep->ether_shost[1],ep->ether_shost[2],ep->ether_shost[3],ep->ether_shost[4],ep->ether_shost[5]);
			  printf("DST MAP= %x-%x-%x-%x-%x-%x\n",ep->ether_dhost[0],ep->ether_dhost[1],ep->ether_dhost[2],ep->ether_dhost[3],ep->ether_dhost[4],ep->ether_dhost[5]);
                          printf("------------------------------------------------------------------------\n");
                          printf("PORT\n");
	         	  tcph = (struct tcp *)(p + iph->ip_hl * 4);
   			  printf("Src Port : %d\n" , ntohs(tcph->source));
		          printf("Dst Port : %d\n" , ntohs(tcph->dest));

                                        }
        }                 
                return ;
        
}
