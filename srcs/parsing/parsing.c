#include "../../includes/ft_nmap.h"

static unsigned long hash(const char *str) {
  unsigned long hash = 5381;
  int c;

  while ((c = *str++))
    hash = ((hash << 5) + hash) + c;
  return hash;
}

static int manage_argument(char *option, char *value, t_data *data) {
  switch (hash(option)) {
  case 6385292014: // help
    return 1;
  case 210724489981: // ports
    if (data->ports_number != 0) {
      fprintf(stderr, "ports are already reffered\n option %s ignored", option);
      break;
    }
    set_ports_value(value, data);
    break;
  case 5863486: // ip
    if (data->ip_address != NULL) {
      fprintf(stderr, "Adresses are already reffered: option %s ignored\n",
              option);
      break;
    }
    data->ip_address = parse_ip_line(value);
    break;
  case 229482867160219: // speedup
    set_speedup_value(value, data);
    break;
  case 6385684778: // scan
    data->scanmask = parse_scan(value);
    break;
  case 6385224485: // file
    if (data->ip_address != NULL) {
      fprintf(stderr, "Adresses are already reffered: option %s ignored\n",
              option);
      break;
    }
    data->ip_address = parse_file(value);
    break;
  case 193486302: // all
      data->display_all = true;
      return 2;
    break;
  default:
      dprintf(2, "\e[1;31mUnknown option %s\e[1;0m\n", option);
    break;
  }
  return 0;
}

static bool check_parsed_arguments(t_data *data) {
  if (data->ip_address == NULL || data->ip_address[0] == NULL) return false;
  if (data->ports_number == 0) set_ports_value("1-1024", data);
  if (data->scanmask.mask == 0) data->scanmask.mask = 255;
  return true;
}

bool parse_arguments(int ac, char **av, t_data *data) {
  bool skip;
  int ret;

  skip = false;
  ft_bzero(data, sizeof(t_data));
  for (int idx = 1; idx < ac; idx++) {
    if (!skip && av[idx][0] == '-' && av[idx][1] == '-') {
      if ((ret = manage_argument(&(av[idx][2]), av[idx + 1], data))) {
        if (ret == 2) continue ;
        free_tab(data->ip_address);
        show_help();
        return false;
      }
      skip = true;
      continue;
    }
    skip = false;
  }
  if (!check_parsed_arguments(data)) {
    free_tab(data->ip_address);
    usage();
    return (false);
  }
  return true;
}

void free_data(t_data *data) { free_tab(data->ip_address); }
