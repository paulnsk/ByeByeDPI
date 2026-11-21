#ifndef BBD_LAB_TRAFFIC_H
#define BBD_LAB_TRAFFIC_H

#include <stddef.h>

void lab_tcp_status(int fd, int error);
void lab_client_hello(int fd, const char *data, size_t len);

#endif
