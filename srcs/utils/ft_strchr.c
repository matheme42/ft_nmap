#include "../../includes/ft_nmap.h"

char *ft_strchr(const char *s, int c) {
  int a;

  a = 0;
  while (s[a] && s[a] != (char)c)
    a++;
  if (s[a] == '\0' && c != '\0')
    return (NULL);
  return ((char *)&s[a]);
}
