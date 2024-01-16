 #include "ft_nmap.h"

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

static int is_valid_addr(char *addr) {
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
