#include "ft_nmap.h"

void set_speedup_value(char *str, t_data *data) {
    int value = ft_atoi(str);
    if (value < MIN_SPEEDUP || value > MAX_SPEEDUP) {
        dprintf(1, "valeur invalide pour l'option speedup %s\n", str);
        return ;
    }
    data->speedup = (short)value;
}


void set_ports_value(char *str, t_data *data) {
char **tab;
int nb = 0;
int nb2 = 0;

tab = ft_strsplit(str, ',', &nb);
tab = ft_strsplit(str, '-', &nb2);
dprintf(1, "%d - %d\n", nb , nb2);
}