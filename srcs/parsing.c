#include "ft_nmap.h"

void usage() {
    dprintf(1, "%s\n%s\n", USAGE, USAGE_FILE);
}

#define HELP 6385292014
#define PORTS 210724489981
#define IP 5863486
#define SPEEDUP 229482867160219
#define SCAN 6385684778

const unsigned long hash(const char *str) {
    unsigned long hash = 5381;  
    int c;

    while ((c = *str++))
        hash = ((hash << 5) + hash) + c;
    return hash;
}

void free_ips(char **ips) {
    int n;

    if (!ips)
        return ;
    n = 0;
    while (ips[n]) {
        dprintf(0, "%s\n", ips[n]);
        free(ips[n++]);
    }
    free(ips);
}

static int fill_file_data(char *file_name, void *buf, int size) {
    int fd;
    FILE *file;
    int ret;

    if (!(file = fopen(file_name, "r"))) {
        fprintf(stderr, "Unable to open the file %s\n", file_name);
        return 0;
    }
    if ((fd = fileno(file)) < 0) {
        perror("Fileno failed");
        return 0;
    }
    if ((ret = read(fd, buf, size - 1)) < 0) {
        perror("Read failed");
        return 0;
    }
    ((char*)buf)[ret] = 0;
    fclose(file);
    return 1;
}

int is_valid_addr(char *addr) {
    struct addrinfo hints;
    struct addrinfo* info;
    int error;

    ft_bzero(&hints, sizeof(struct addrinfo));
    hints.ai_family = PF_INET;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = 0;
    hints.ai_flags = AI_CANONNAME;
    if ((error = getaddrinfo(addr, 0, &hints, &info))) {
        fprintf(stderr, "Addr %s is invalid : %s\n", addr, gai_strerror(error));
        return 0;
    }
    freeaddrinfo(info);
    return 1;
}

char **parse_file(char *file_name) {
    char    **ips;
    int     nb_ips, nb_lines;
    char    buff[16384];
    
    if (!fill_file_data(file_name, buff, 16384) ||
        !(ips = ft_strsplit(buff, '\n', &nb_lines)))
        return 0;
    nb_ips = 0;
    for (int n = 0; n < nb_lines; n++) {
        if (is_valid_addr(ft_strcpy(ips[n], ft_trim(ips[n]))))
            ips[nb_ips++] = ips[n];
        else
            free(ips[n]);
    }
    ips[nb_ips] = 0;
    return ips;
}

char **parse_ip_line(char *line) {
    char    **ips;
    int     nb_ips, nb_arg;
    
    if (!(ips = ft_strsplit(line, ',', &nb_arg)))
        return 0;
    nb_ips = 0;
    for (int n = 0; n < nb_arg; n++) {
        if (is_valid_addr(ft_strcpy(ips[n], ft_trim(ips[n]))))
            ips[nb_ips++] = ips[n];
        else
            free(ips[n]);
    }
    ips[nb_ips] = 0;
    return ips;
}

int	ft_strcmp(const char *s1, const char *s2)
{
	int n;

	n = 0;
	while (s1[n] == s2[n] && (s1[n] != '\0' || s2[n] != '\0'))
		n++;
	return ((unsigned char)s1[n] - (unsigned char)s2[n]);
}

t_scan strtoscan(char *str) {
    t_scan scan;

    scan.mask = 0;
    if (!ft_strcmp(str, "ACK"))
        scan.type.ack = 1;
    else if (!ft_strcmp(str, "FIN"))
        scan.type.fin = 1;
    else if (!ft_strcmp(str, "NULL"))
        scan.type.null = 1;
    else if (!ft_strcmp(str, "SYN"))
        scan.type.syn = 1;
    else if (!ft_strcmp(str, "UDP"))
        scan.type.udp = 1;
    else if (!ft_strcmp(str, "XMAS"))
        scan.type.xmas = 1;
    return scan;
}

t_scan parse_scan(char *line) {
    t_scan  scan;
    char    *ptr;

    scan.mask = 0;
    if (!line)
        return scan;
    while((ptr = ft_strchr(line, ','))) {
        ptr[0] = 0;
        scan.mask |= strtoscan(line).mask;
        line = ptr + 1;
    }
    scan.mask |= strtoscan(line).mask;
    return scan;
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
        data->ip_address = parse_ip_line(value);
        break;
    case 229482867160219: // speedup
        dprintf(1, "SPEEDUP\n");
        set_speedup_value(value, data);
        break;     
    case 6385684778: // scan
        dprintf(1, "SCAN\n");
        data->scanmask = parse_scan(value);
        break;        
    case 6385224485: // file
        dprintf(1, "FILE\n");
        data->ip_address = parse_file(value);
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

    free_ips(data.ip_address);
    return (0);
}