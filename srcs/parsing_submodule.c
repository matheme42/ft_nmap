#include "ft_nmap.h"

void set_speedup_value(char *str, t_data *data) {
    int value = ft_atoi(str);
    if (value < MIN_SPEEDUP || value > MAX_SPEEDUP) {
        dprintf(1, "valeur invalide pour l'option speedup %s\n", str);
        return ;
    }
    data->speedup = (short)value;
}


void set_ports_value_from_range(char *str, t_data *data) {
    int len;

    char **split_data = ft_strsplit(str, '-', &len);
    if (len != 2) {
        fprintf(stderr, "Invalide range for option ports\n");
        return ;
    }
    int v1 = ft_atoi(split_data[0]);
    if (v1 < MIN_PORT || v1 > MAX_PORT) {
        fprintf(stderr, "Invalide range for option ports: (MIN: %d MAX: %d)\n", MIN_PORT, MAX_PORT);
        return ;
    }
    int v2 = ft_atoi(split_data[1]);
    if (v2 < MIN_PORT || v2 > MAX_PORT) {
        fprintf(stderr, "Invalide range for option ports: (MIN: %d MAX: %d)\n", MIN_PORT, MAX_PORT);
        return ;
    }

    if (v1 > v2) {
        data->ports_range.end = v1;
        data->ports_range.end = v2;
    }
}

void set_ports_value(char *str, t_data *data)
{
    char *coma;
    char *dash;

    coma = ft_strchr(str, ',');
    dash = ft_strchr(str, '-');
    bool contain_coma = coma != NULL;
    bool contain_dash = dash != NULL;

    if (contain_coma && contain_dash) {
        fprintf(stderr, "Can't be a list and a range at the same time\n");
        return ;
    }
    if (!contain_coma && ! contain_dash) {
        fprintf(stderr, "ports value(s) can't be empty\n");
        return ;
    }

    if (contain_dash) {
        set_ports_value_from_range(str, data);
        return ;
    }
}