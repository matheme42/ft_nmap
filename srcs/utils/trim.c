#include "ft_nmap.h"

char *trim(char *s) {
    char *ptr;
    if (!s) return NULL;
    if (!*s) return s;
    for (ptr = s + ft_strlen(s) - 1; (ptr >= s) && (*ptr == ' ' || *ptr == '\t' || *ptr == '\v'); --ptr);
    ptr[1] = '\0';
    return s;
}