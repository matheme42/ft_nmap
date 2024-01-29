#include "../../includes/ft_nmap.h"

void usage() { dprintf(1, "%s\n%s\n", USAGE, USAGE_FILE); }

void show_help() {
  fprintf(stderr, "> ft_nmap [OPTIONS]\n");
  fprintf(stderr, "--help     Print this help screen\n");
  fprintf(stderr, "--ports    ports to scan (eg: 1-10 or 1,2,3)\n");
  fprintf(stderr, "--ip       ip addresses to scan in dot format\n");
  fprintf(stderr, "--file     File name containing IP addresses to scan\n");
  fprintf(stderr, "--speedup  [250 max] number of parallel threads to use\n");
  fprintf(stderr, "--scan     SYN / NULL / FIN / XMAS / ACK / UDP\n");
}
