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

void manage_argument(char *argument_name, char *value) {
    switch (hash(argument_name))
    {
    case 6385292014: // help
        /* code */
        break;
    case 210724489981: // ports
        /* code */
        break;
    case 5863486: // ip
        /* code */
        break;
    case 229482867160219: // speedup
        /* code */
        break;     
    case 6385684778: // scan
        /* code */
        break;        
    case 6385224485: // file
        parse_file(value);
        break;                    
    default:
        break;
    }
}

bool parse_arguments(int ac, char **av) {
    bool skip;
    
    skip = false;
    for (int idx = 1; idx < ac; idx++) {
        if (!skip && av[idx][0] == '-' && av[idx][1] == '-') {
            manage_argument(&(av[idx][2]), av[idx + 1]);
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
    if (!parse_arguments(ac, av)) usage();

    return (0);
}