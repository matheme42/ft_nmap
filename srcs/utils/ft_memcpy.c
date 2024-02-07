#include <unistd.h>

void *ft_memcpy(void *dest, const void *str, size_t size) {
    for (size_t n = 0; n < size; n++) ((char*)dest)[n] = ((char*)str)[n];
    return dest;
}