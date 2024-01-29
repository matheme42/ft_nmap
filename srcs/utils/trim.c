#include "../../includes/ft_nmap.h"

char *ft_trim(char *s) {
  char *ptr;
  if (!s)
    return NULL;
  while (*s == ' ' || *s == '\t' || *s == '\v')
    s++;
  ptr = s + ft_strlen(s) - 1;
  while (*ptr == ' ' || *ptr == '\t' || *ptr == '\v')
    ptr--;
  ptr[1] = '\0';
  return s;
}
