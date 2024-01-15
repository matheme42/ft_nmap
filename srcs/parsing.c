#include "ft_nmap.h"

void usage() {
    dprintf(1, "%s\n%s\n", USAGE, USAGE_FILE);
}

#define help 6385292014
#define ports 210724489981
#define ip 5863486
#define speedup 229482867160219
#define scan 6385684778

const unsigned long hash(const char *str) {
    unsigned long hash = 5381;  
    int c;

    while ((c = *str++))
        hash = ((hash << 5) + hash) + c;
    return hash;
}

char **parse_file(char *file_name) {

}

void manage_argument(char *option, char *value, t_data *data) {
    switch (hash(option)) {
    case 6385292014: // help
        dprintf(1, "HELP\n");
        break;
    case 210724489981: // ports
        dprintf(1, "PORTS\n");
        set_ports_value(value, data);
        break;
    case 5863486: // ip
        dprintf(1, "IP\n");
        break;
    case 229482867160219: // speedup
        dprintf(1, "SPEEDUP\n");
        set_speedup_value(value, data);
        break;     
    case 6385684778: // scan
        dprintf(1, "SCAN\n");
        break;        
    case 6385224485: // file
        dprintf(1, "FILE\n");
        parse_file(value);
        break;
    default:
        dprintf(2, "\e[1;31mUnknown option %s\e[1;0m\n", option);
        break;
    }
}

bool parse_arguments(int ac, char **av, t_data *data) {
    bool skip;
    
    skip = false;
    for (int idx = 1; idx < ac; idx++) {
        if (!skip && av[idx][0] == '-' && av[idx][1] == '-') {
            manage_argument(&(av[idx][2]), av[idx + 1], data);
            skip = true;
            continue;
        }
        skip = false;
    }
    return false;
}

int main(int ac, char **av) {
    t_data data;

    bzero(&data, sizeof(data));
    if (!parse_arguments(ac, av, &data)) usage();

    return (0);
}