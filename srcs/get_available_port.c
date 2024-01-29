#include "ft_nmap.h"

int getAvailablePort() {
    static int portNumber = 33445;
    return portNumber++;
}