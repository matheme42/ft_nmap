#include <stdio.h>
#include <time.h>
#include <pcap.h>
#include <netinet/in.h>
#include <netinet/if_ether.h>
#include "ft_nmap.h"

void my_packet_handler(
    u_char *args,
    const struct pcap_pkthdr *packet_header,
    const u_char *packet_body
)
{
    print_packet_info(packet_body, *packet_header);
    return;
}

void print_packet_info(const u_char *packet, struct pcap_pkthdr packet_header) {
    printf("Packet capture length: %d\n", packet_header.caplen);
    printf("Packet total length %d\n", packet_header.len);
}

void print_devs(pcap_if_t *alldevsp) {
    char errbuf[PCAP_ERRBUF_SIZE];
    bpf_u_int32 netp, maskp;
    pcap_if_t *dev;

    dev = alldevsp;
    printf("devs:\n");
    while (dev) {
        if (pcap_lookupnet(dev->name, &netp, &maskp, errbuf)) {
            fprintf(stderr, "Error lookupnet: %s\n", errbuf);
            dev = dev->next;
            continue;
        }
        printf("name %s\n", dev->name);
        printf("ip %d\n", netp);
        printf("mask %d\n\n", maskp);
        dev = dev->next;
    }
}

void set_filter(pcap_t *p) {
    struct bpf_program program;
    const char *str = "greater 200";

    if (pcap_compile(p, &program, str, 1, PCAP_NETMASK_UNKNOWN)) {
        fprintf(stderr, "Could not compile program : %s\n", pcap_geterr(p));
        return ;
    }
    if (pcap_setfilter(p, &program)) {
        fprintf(stderr, "Could not set filter : %s\n", pcap_geterr(p));
        return ;
    }
    free(program.bf_insns);
    //pcap_freecode(&program);
}

int create_socket() {
    int sockId;
    int option;


    if ((sockId = socket(PF_INET, SOCK_RAW, IPPROTO_ICMP)) < 0) {
        dprintf(2, "ft_traceroute: Socket creation failed\n");
        return 0;
    }

    // set custom header to true
    option = 1;
    if (setsockopt(sockId, IPPROTO_IP, IP_HDRINCL, &option, sizeof(option))) {
        dprintf(2, "ft_traceroute: Failed to set socket option\n");
        return 0;
    }
    return (sockId);
}

void fill_UDP_Header(struct udphdr *udphdr, int port) {
    udphdr->source = INADDR_ANY;
    udphdr->dest = htons(port);
    udphdr->len = htons(sizeof(struct packet) - sizeof(struct iphdr));
    udphdr->check = 0;
}

void fill_TCP_Header(struct tcphdr *tcphdr, t_scan flags) {
    ft_bzero(tcphdr, sizeof(struct tcphdr));
    tcphdr->source = 0;
    tcphdr->dest = 0;
    tcphdr->seq = 0;
    tcphdr->ack_seq = 0;
    tcphdr->res1 = sizeof(struct tcphdr) / 4;
    tcphdr->ack = flags.type.ack;
    tcphdr->syn = flags.type.syn;
    tcphdr->fin = flags.type.fin;
    tcphdr->doff = 0;
    tcphdr->check = 0;
    tcphdr->window = sizeof(struct packet);
    tcphdr->urg_ptr = 0;
}

void fill_IP_Header(struct iphdr *header, uint32_t daddr, u_int8_t protocol) {
    header->version = IPVERSION;
    header->ihl = 5;
    header->tos = 0;
    header->tot_len = 0;
    header->id = getuid();
    header->frag_off = 0;
    header->ttl = 255;
    header->protocol = protocol;
    header->check = 0;
    header->saddr = INADDR_ANY;
    header->daddr = daddr;
}

void send_tcp_packet() {
    struct packet pkt;
    struct sockaddr_in addr;
    t_scan flag;
    int sock = create_socket();

    flag.mask = 0;
    flag.type.syn = 1;
    addr.sin_family = AF_INET;
    addr.sin_port = htons(80);
    addr.sin_addr.s_addr = 0;
    fill_IP_Header(&pkt.iphdr, 0, IPPROTO_TCP);
    fill_TCP_Header(&pkt.tcphdr, flag);

    sendto(sock, &pkt, sizeof(struct packet), 0, (struct sockaddr*)&addr, sizeof(struct sockaddr_in));
}

int main(int argc, char **argv) {

    t_data data;

    if (!parse_arguments(argc, argv, &data)) return (1);

    print_data(&data);
    // execute program
    send_tcp_packet();

    free_data(&data);


    char *device;
    char error_buffer[PCAP_ERRBUF_SIZE];
    pcap_t *handle;
    pcap_if_t *alldevsp;
    int timeout_limit = 1000; /* In milliseconds */

    if (pcap_findalldevs(&alldevsp, error_buffer)) {
        fprintf(stderr, "Error finding devs: %s\n", error_buffer);
        return 1;
    }
    print_devs(alldevsp);

    /* Open device for live capture */
    handle = pcap_open_live(
            alldevsp->name,
            BUFSIZ,
            0,
            timeout_limit,
            error_buffer
        );
    if (handle == NULL) {
         fprintf(stderr, "Could not open device %s: %s\n", device, error_buffer);
         return 2;
    }

    pcap_freealldevs(alldevsp);

    set_filter(handle);
     
    pcap_dispatch(handle, 0, my_packet_handler, NULL);

    pcap_close(handle);
    return 0;
}