#include <openssl/err.h>
#include <stdbool.h>


bool ssl_check_error(int return_value);

void ssl_close(int sockfd, SSL* cSSL);

void ssl_exit(int code);

bool stoint(char* string, int* integer);