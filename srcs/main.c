#include <stdio.h>
#include <time.h>
#include <pcap.h>
#include <netinet/in.h>
#include <netinet/if_ether.h>

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
            printf("Error lookupnet: %s\n", errbuf);
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

int main(int argc, char *argv[]) {
    char *device;
    char error_buffer[PCAP_ERRBUF_SIZE];
    pcap_t *handle;
    pcap_if_t *alldevsp;
    int timeout_limit = 1000; /* In milliseconds */

    if (pcap_findalldevs(&alldevsp, error_buffer)) {
        printf("Error finding devs: %s\n", error_buffer);
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