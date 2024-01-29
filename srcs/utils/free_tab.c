#include "../../includes/ft_nmap.h"

void free_tab(char **x) {
  int n;

  if (!x)
    return;
  n = 0;
  while (x[n])
    free(x[n++]);
  free(x);
}
