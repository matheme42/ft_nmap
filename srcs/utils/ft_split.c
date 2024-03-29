#include "../../includes/ft_nmap.h"

static size_t ft_lenfromto(const char *s, size_t i, char c) {
  size_t j;

  j = 0;
  while (s[i + j] && s[i + j] != c)
    j++;
  return (j);
}

static size_t nbmots(const char *s, char c) {
  size_t i;
  size_t n;

  i = 0;
  n = 0;
  while (s[i]) {
    while (s[i] == c && s[i])
      i++;
    if (s[i]) {
      while (s[i] != c && s[i])
        i++;
      n++;
    }
  }
  return (n);
}

char **ft_strsplit(const char *s, char c, int *len) {
  char **tab;
  size_t i;
  size_t j;

  if (s == NULL)
    return (NULL);
  if (!(tab = ft_malloc(sizeof(char *) * (nbmots(s, c) + 1))))
    return (NULL);
  i = 0;
  j = 0;
  while (s[i]) {
    while (s[i] == c && s[i])
      i++;
    if (s[i]) {
      tab[j] = ft_strsub(s, i, ft_lenfromto(s, i, c));
      i = i + ft_lenfromto(s, i, c);
      j++;
    }
  }
  tab[j] = NULL;
  *len = j;
  return (tab);
}
