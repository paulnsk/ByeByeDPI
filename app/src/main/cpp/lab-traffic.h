#ifndef BBD_LAB_TRAFFIC_H
#define BBD_LAB_TRAFFIC_H

#include <stddef.h>

void lab_tcp_status(int fd, int error);
void lab_client_hello(int fd, const char *data, size_t len);
void lab_set_journal_dir(const char *path);

int lab_set_hello_wait(const char *value);
int lab_arm_hello_wait(int fd);
int lab_has_hello_wait(int fd);
int lab_finish_hello_wait(int fd, int timed_out);

#endif
