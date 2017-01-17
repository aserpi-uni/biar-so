#include <openssl/evp.h>
#include <openssl/ssl.h>
#include <unistd.h>
#include "common.h"


bool ssl_check_error(int return_value)
{
    if (return_value == 1)
        return true;

    char error_string[512];
    ERR_error_string_n(ERR_get_error(), error_string, sizeof(error_string));
    printf(error_string);
    fflush(stdout);

    return false;

}


void ssl_close(int sockfd, SSL* cSSL)
{
    if (sockfd == -1)
        return;
    close(sockfd);

    if (cSSL == NULL)
        return;

    SSL_shutdown(cSSL);
    SSL_free(cSSL);
}


void ssl_exit(int code)
{
    ERR_free_strings();
    EVP_cleanup();

    exit(code);
}


bool stoint(char* string, int* integer)
{
    char* last_converted;
    *integer = (int)strtol(string, &last_converted, 10);

    return last_converted != string;
}