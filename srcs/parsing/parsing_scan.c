#include "../../includes/ft_nmap.h"

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
  t_scan scan;
  char *ptr;

  scan.mask = 0;
  if (!line)
    return scan;
  while ((ptr = ft_strchr(line, ','))) {
    ptr[0] = 0;
    scan.mask |= strtoscan(line).mask;
    line = ptr + 1;
  }
  scan.mask |= strtoscan(line).mask;
  return scan;
}
