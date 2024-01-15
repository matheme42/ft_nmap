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

     
    while (1) pcap_dispatch(handle, 0, my_packet_handler, NULL);

    pcap_close(handle);
    return 0;
}