#include "ft_nmap.h"

char *convert_value(char scan, unsigned char v) {
    static char data[6][4][16] = {
        {"FILTERED", "CLOSED", "OPEN"}, // SYN
        {"FILTERED", "UNFILTERED"}, // ACK
        {"OPEN | FILTERED", "CLOSED", "FILTERED"}, // FIN
        {"OPEN | FILTERED", "CLOSED", "FILTERED"}, // NULL
        {"OPEN | FILTERED", "CLOSED", "FILTERED"}, // XMAS
        {"OPEN | FILTERED", "OPEN", "CLOSED", "FILTERED"} // UDP
    };
    return data[scan][v];
}

void display_response(thread_data threads[MAX_SPEEDUP], int speedup) {
    thread_data *data;

    for (int i = 0; i < speedup; i++) {
        data = &threads[i];

        for (int j = 0; j < data->nb_port; j++) {
            int port = data->ports[j];
            t_response response = data->response[j];
            if (port == 80 || port == 443)
            dprintf(1, "port: %5d SYN (%-15s), ACK (%-15s), FIN (%-15s) NULL (%-15s) XMAS (%-15s) UDP (%-15s)\n", port, convert_value(0, response.syn), convert_value(1, response.ack), convert_value(2, response.fin), convert_value(3, response.null), convert_value(4, response.xmas), convert_value(5, response.udp));
        }
    }
}