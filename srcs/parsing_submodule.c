#include "ft_nmap.h"

void set_speedup_value(char *str, t_data *data) {
    int value = ft_atoi(str);
    if (value < MIN_SPEEDUP || value > MAX_SPEEDUP) {
        dprintf(1, "valeur invalide pour l'option speedup %s\n", str);
        return ;
    }
    data->speedup = (short)value;
}


static void set_ports_value_from_range(char *str, t_data *data) {
    int     len;
    short   start_port;
    short   end_port;
    int     v1;
    int     v2;

    char **split_data = ft_strsplit(str, '-', &len);
    if (split_data == NULL) {
        fprintf(stderr, "low memory can't store some data\n");
        return ;
    }
    if (len != 2) {
        fprintf(stderr, "Invalide range for option ports\n");
        free_tab(split_data);
        return ;
    }
    v1 = ft_atoi(split_data[0]);
    v2 = ft_atoi(split_data[1]);
    free_tab(split_data);
    if (v1 < MIN_PORT || v1 > MAX_PORT || v2 < MIN_PORT || v2 > MAX_PORT) {
        fprintf(stderr, "Invalide range for option ports: (MIN: %d MAX: %d)\n", MIN_PORT, MAX_PORT);
        return ;
    }

    if (v1 > v2) {
        end_port = v1;
        start_port = v2;
    } else if (v2 > v1) {
        end_port = v2;
        start_port = v1;
    } else {
        data->ports_number = 1;
        *(data->ports) = v1;
        return ;
    }
    data->ports_number = (end_port - start_port) + 1;
    for (size_t i = start_port; (short int)i <= end_port; i++)
        data->ports[i - start_port] = i;
}


static void set_ports_value_from_list(char *str, t_data *data) {
    int     len;
    int     v;
    int     nb_valid_ports;

    char **split_data = ft_strsplit(str, ',', &len);
    if (split_data == NULL) {
        fprintf(stderr, "low memory can't store some data\n");
        return ;
    }

    nb_valid_ports = 0;
    for (int i = 0; i < len; i++) {
        v = ft_atoi(split_data[i]);
        if (v < MIN_PORT || v > MAX_PORT) {
            fprintf(stderr, "Invalide range for option ports: %s (MIN: %d MAX: %d)\n", split_data[i], MIN_PORT, MAX_PORT);
            continue;
        }
        data->ports[nb_valid_ports++] = v;
    }
    data->ports_number = nb_valid_ports;
    free_tab(split_data);
}


void set_ports_value(char *str, t_data *data)
{
    char *coma;
    char *dash;

    coma = ft_strchr(str, ',');
    dash = ft_strchr(str, '-');
    bool contain_coma = coma != NULL;
    bool contain_dash = dash != NULL;

    if (!str) {
        fprintf(stderr, "ports value(s) can't be empty\n");
        return ;
    }

    if (contain_coma && contain_dash) {
        fprintf(stderr, "Can't be a list and a range at the same time\n");
        return ;
    }
    if (!contain_coma && ! contain_dash) contain_coma = true;

    if (contain_dash) {
        set_ports_value_from_range(str, data);
        return ;
    }
    set_ports_value_from_list(str, data);
}

void show_help() {
    fprintf(stderr, "> ft_nmap [OPTIONS]\n");
    fprintf(stderr, "--help     Print this help screen\n");
    fprintf(stderr, "--ports    ports to scan (eg: 1-10 or 1,2,3)\n");
    fprintf(stderr, "--ip       ip addresses to scan in dot format\n");
    fprintf(stderr, "--file     File name containing IP addresses to scan\n");
    fprintf(stderr, "--speedup  [250 max] number of parallel threads to use\n");
    fprintf(stderr, "--scan     SYN / NULL / FIN / XMAS / ACK / UDP\n");
}