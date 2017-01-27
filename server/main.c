#include <netinet/in.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <stdbool.h>
#include <unistd.h>
#include <signal.h>
#include "board.h"
#include "../common.h"


#define FORMAT_ERROR "%d&%s"
#define MAX_ARGUMENTS 5
#define PAGE_SIZE 10
#define PAGES 5
#define PORT 42318
#define REQUEST_SIZE 512
#define RESPONSE_SIZE 4096
#define USERS 50


void close_handler(int signo);
void segfault_handler(int signo);

void activate_message(char **args, char* response, int response_size);
void deactivate_message(char **args, char* response, int response_size);
void expand_message(char **args, char* response, int response_size);
void get_page(char** args, char* response, int response_size);
void insert_message(char **args, char* response, int response_size);
void register_user(char **args, char* response, int response_size);
void stalk_user(char** args, char* response, size_t response_size);


bool close_server = false, segflt = false;
const int enable = 1;
int error;

int main(int argc, char *argv[])
{
    signal(SIGINT, close_handler);
    signal(SIGTERM, close_handler);

    error = initialize_board(USERS, PAGES, PAGE_SIZE);
    if (error < 0)
    {
        printf("Error %d initializing board!", error);
        shutdown_board();
        exit(1);
    }

    OpenSSL_add_ssl_algorithms();
    SSL_load_error_strings();

    errno = 0;
    SSL_CTX* sslctx = SSL_CTX_new(TLSv1_2_server_method());
    SSL_CTX_set_options(sslctx, SSL_OP_SINGLE_DH_USE);

    if (!ssl_check_error(SSL_CTX_use_certificate_file(sslctx, "ssl/server.crt", SSL_FILETYPE_PEM)))
        ssl_exit(2);

    if (!ssl_check_error(SSL_CTX_use_RSAPrivateKey_file(sslctx, "ssl/server.key", SSL_FILETYPE_PEM)))
        ssl_exit(2);

    int sockfd;
    while(true)
    {
        sockfd = socket(AF_INET, SOCK_STREAM, 0);

        if (sockfd != -1)
            break;

        if (errno == EINTR)
            continue;

        printf("Error %d when creating socket!", errno);
        ssl_exit(3);
    }

    struct timeval timeout;
    timeout.tv_sec = 2;
    timeout.tv_usec = 0;
    setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &enable, sizeof(enable));

    struct sockaddr_in serv_addr;
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_addr.s_addr = INADDR_ANY;
    serv_addr.sin_port = htons(PORT);
    while(true)
    {
        if(bind(sockfd, (struct sockaddr*) &serv_addr, sizeof(serv_addr)) == 0)
            break;

        if (errno == EINTR)
            continue;

        printf("Error %d when binding socket!", errno);
        close(sockfd);
        ssl_exit(4);
    }

    while(true)
    {
        if(listen(sockfd, 1) == 0)
            break;

        if (errno == EINTR)
            continue;

        printf("Error %d when listening!", errno);
        close(sockfd);
        ssl_exit(5);
    }

    char request[REQUEST_SIZE], response[RESPONSE_SIZE];
    char* token;
    char* args[MAX_ARGUMENTS];
    int auth, count, newsockfd;
    size_t size;
    struct sockaddr_in* cli_addr = (struct sockaddr_in*)malloc(sizeof(struct sockaddr_in));
    while (!close_server)
    {
        size = sizeof(struct sockaddr_in);
        memset(cli_addr, 0, size);
        memset(request, 0, REQUEST_SIZE);
        memset(response, 0, RESPONSE_SIZE);

        newsockfd = accept(sockfd, (struct sockaddr*)cli_addr, (socklen_t*)&size);
        if (newsockfd == -1)
        {
            printf("Error %d when accepting connection!", errno);
            fflush(stdout);
            continue;
        }

        setsockopt(newsockfd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
        signal(SIGSEGV, segfault_handler);

        errno = 0;
        SSL *cSSL = SSL_new(sslctx);
        SSL_set_fd(cSSL, newsockfd );

        if (!ssl_check_error(SSL_accept(cSSL)))
            ssl_close(newsockfd, cSSL);

        int used = 0;
        while(true)
        {
            if(REQUEST_SIZE - used == 0)
                break;

            error = SSL_read(cSSL, request + used, RESPONSE_SIZE - used);

            if (segflt) break;

            switch(SSL_get_error(cSSL, error))
            {
                case SSL_ERROR_NONE:
                    used += error;
                    error = false;
                    break;
                case SSL_ERROR_ZERO_RETURN:
                    printf("Connection closed by the client.");
                    error = true;
                case SSL_ERROR_WANT_READ:
                    continue;
                default:
                    ssl_close(newsockfd, cSSL);
                    printf("ERROR %d when reading!\n", error);
                    error = true;
            }

            fflush(stdout);
            if(!error)
                break;
        }

        signal(SIGSEGV, SIG_DFL);
        if (segflt)
        {
            printf("Connection timed out");
            segflt = false;
            continue;
        }

        memset(args, 0, sizeof(args));
        token = strtok(request, "&");
        for(count = 0; token != NULL; count++)
        {
            if (count == MAX_ARGUMENTS)
                break;
            args[count] = token;
            token = strtok(NULL, "&");
        }

        if (count < 2 || count > MAX_ARGUMENTS)
        {
            snprintf(response, sizeof(response), FORMAT_ERROR, 5,
                     "Invalid number of arguments, check your syntax!");

            SSL_write(cSSL, response, (int)strlen(response) + 1);
            ssl_close(newsockfd, cSSL);

            continue;
        }
        else if (strcmp(args[0], "R") == 0)
        {
            register_user(args, response, sizeof(response));

            SSL_write(cSSL, response, (int)strlen(response));
            close(newsockfd);

            continue;
        }

        auth = check_pwd(args[1], args[2]);
        switch (auth)
        {
            case -1:
                snprintf(response, sizeof(response), FORMAT_ERROR, 1, "No such user!");
                error = true;
                break;
            case -2:
                snprintf(response, sizeof(response), FORMAT_ERROR, 2, "Wrong password!");
                error = true;
                break;
            default:
                error = false;
                break;
        }
        if (error)
        {
            SSL_write(cSSL, response, (int)strlen(response));

            close(newsockfd);
            continue;
        }

        if(count < 3)
            snprintf(response, sizeof(response), FORMAT_ERROR, 4, "Invalid number of arguments, check your syntax!");
        else if (strcmp(args[0], "G") == 0)
            get_page(args, response, sizeof(response));
        else if (strcmp(args[0], "E") == 0)
            expand_message(args, response, sizeof(response));
        else if(strcmp(args[0], "I") == 0)
            if(args[4] == NULL)
                snprintf(response, sizeof(response), FORMAT_ERROR, 4,
                         "Invalid number of arguments, check your syntax!");
            else
                insert_message(args, response, sizeof(response));
        else if(strcmp(args[0], "D") == 0)
            deactivate_message(args, response, sizeof(response));
        else if(strcmp(args[0], "S") == 0)
            if(args[4] == NULL)
                snprintf(response, sizeof(response), FORMAT_ERROR, 4,
                         "Invalid number of arguments, check your syntax!");
            else
                stalk_user(args, response, sizeof(response));
        else if (strcmp(args[0], "A") == 0)
            activate_message(args, response, sizeof(response));
        else if (strcmp(args[0], "P") == 0)
        {
            change_pwd(args[1], args[3]);
            snprintf(response, sizeof(response), "%d", 0);
        }
        else
            snprintf(response, sizeof(response), FORMAT_ERROR, 5, "Unknown command!");

        SSL_write(cSSL, response, RESPONSE_SIZE);
        ssl_close(newsockfd, cSSL);
    }

    close(sockfd);
    ssl_exit(0);
}


void activate_message(char **args, char *response, int response_size)
{
    char* last_converted;
    int message_id = (int)strtol(args[3], &last_converted, 10);

    if ((last_converted) == args[3] || !delete_message(message_id))
    {
        snprintf(response, (size_t)response_size, FORMAT_ERROR, 11, "Nonexistent message!");
        return;
    }

    restore_message(message_id);
    snprintf(response, (size_t)response_size, "%d&Deleted message with id %d", 0, message_id);
}



void deactivate_message(char **args, char *response, int response_size)
{
    char* last_converted;
    int message_id = (int)strtol(args[3], &last_converted, 10);

    if ((last_converted) == args[3] || !delete_message(message_id))
    {
        snprintf(response, (size_t)response_size, FORMAT_ERROR, 11, "Nonexistent message!");
        return;
    }

    delete_message(message_id);
    snprintf(response, (size_t)response_size, "%d&Deleted message with id %d", 0, message_id);
}



void expand_message(char **args, char *response, int response_size)
{
    char* last_converted;
    int message_id = (int)strtol(args[3], &last_converted, 10);

    if ((last_converted) == args[3])
    {
        snprintf(response, (size_t)response_size, FORMAT_ERROR, 11, "Nonexistent message!");
        return;
    }

    msg* message = get_message(message_id);
    char date[512];

    if (message == NULL)
    {
        snprintf(response, (size_t)response_size, FORMAT_ERROR, 11, "Nonexistent message!");
        return;
    }

    if(!strftime(date, (size_t)sizeof(date), "%F %T %Z", gmtime(&message->timestamp)))
        snprintf(date, sizeof(date), "%s", "Date not available");
    snprintf(response, (size_t)response_size, "%d&%d&%d&%s&%s&%s&%s", 0, message_id, message->active, message->content,
             message->subject, date, message->user);

    free(message);
}



/**
 * Sends a string formatted like:
 * <ul>
 * <li>0 (if succeeding)
 * <li>page size
 * <li>id of the first message
 * <li>messages formatted like
 * <ul>
 * <li>date
 * <li>user
 * <li>subject
 * <li>active
 * </ul>
 * </ul>
 */
void get_page(char** args, char* response, int response_size)
{
    char* last_converted;
    int message_id = (int)strtol(args[3], &last_converted, 10);
    if ((last_converted) == args[3])
    {
        snprintf(response, (size_t)response_size, FORMAT_ERROR, 11, "Nonexistent message!");
        return;
    }

    char date[RESPONSE_SIZE], temp[RESPONSE_SIZE];
    int size;
    msg* page = get_messages(message_id, &size);
    snprintf(response, (size_t)response_size, "%d&%d&%d", 0, size, message_id);
    size_t used = strlen(response);

    for (int i = 0; i < size; i++)
    {
        msg message = page[i];
        if(!strftime(date, sizeof(date), "%F %T %Z", gmtime(&message.timestamp)))
            snprintf(date, sizeof(date), "%s", "Date not available");

        snprintf(temp, RESPONSE_SIZE, "&%s&%s&%s&%d", date, message.user, message.subject, message.active);
        strncat(response, temp, size - (used + 1));
        used = strlen(response);
    }

    free(page);
}



void insert_message(char **args, char *response, int response_size)
{
    int new_message = message(args[1], args[3], args[4]);

    switch(new_message)
    {
        case -1:
        case -2:
            snprintf(response, (size_t)response_size, FORMAT_ERROR, 11, "No more space on the board!");
            break;
        default:
            snprintf(response, (size_t)response_size, "%d&%d", 0, new_message);
    }
}



void register_user(char **args, char *response, int response_size)
{
    char* new_user = user(args[1], args[2]);

    if (new_user == NULL)
        snprintf(response, (size_t)response_size, "%s&%s\n%s %s", "1", "Already exists an user with the same id.",
                 "If this is not the first time you see this message,",
                 "maybe the board is not accepting new users.");
    else
        snprintf(response, (size_t)response_size, "%d&%s", 0, new_user);
}



void stalk_user(char** args, char* response, size_t response_size)
{
    char* last_converted;

    int message_id = (int)strtol(args[4], &last_converted, 10);
    if ((last_converted) == args[4])
    {
        snprintf(response, response_size, FORMAT_ERROR, 11, "Invalid message id!");
        return;
    }

    char date[RESPONSE_SIZE], temp[RESPONSE_SIZE];
    int size;
    int ids[PAGE_SIZE];
    msg* page = get_user_messages(args[3], message_id, ids, &size);

    snprintf(response, response_size, "%d&%d", 0, size);
    for (int i = 0; i < size; i++)
    {
        msg message = page[i];
        if(!strftime(date, sizeof(date), "%F %T %Z", gmtime(&message.timestamp)))
            snprintf(date, sizeof(date), "%d", -1);

        snprintf(temp, RESPONSE_SIZE, "&%d&%s&%s&%d", ids[i], date, message.subject, message.active);
        strncat(response, temp, RESPONSE_SIZE - (strlen(response) + 1));
    }

    if(size == 0 && !exists_user(args[3]))
        snprintf(response, response_size, FORMAT_ERROR, 12, "Nonexistent user!");


    free(page);
}



void close_handler(int signo)
{
    close_server = true;
}


void segfault_handler(int signo)
{
    segflt = true;
}
