#include <arpa/inet.h>
#include <netinet/in.h>
#include <openssl/bio.h>
#include <openssl/ssl.h>
#include <signal.h>
#include <unistd.h>
#include "../common.h"



#define ADDRESS "127.0.0.1"
#define COMMAND_SIZE 8
#define CONTENT_SIZE 174
#define PASSWORD_SIZE 32
#define SUBJECT_SIZE 32
#define PORT 42318
#define REQUEST_SIZE 512
#define RESPONSE_SIZE 4096
#define USER_SIZE 16



bool check_ampersand(char* field, size_t size);
void check_authentication();
void exit_handler(int signo);
void get_password(char* buffer);
void get_user(char* buffer);
void server_error();
void ssl_open();

void activate_message();
void change_pwd();
void deactivate_message();
void expand_message();
void insert_message();
void stalk_user();

void get_page();



char discard[2], command[COMMAND_SIZE] = {0},
        password[PASSWORD_SIZE + 2] = {0}, user[USER_SIZE + 2] = {0},
        user_argument[USER_SIZE + 2] = {0},
        request[REQUEST_SIZE] = {0}, response[RESPONSE_SIZE] = {0};
const int enable = 1;
int int_argument = 0, error = false, sockfd = -1;
SSL *cSSL = NULL;



int main(int argc, char *argv[]) {
    signal(SIGINT, exit_handler);
    signal(SIGTERM, exit_handler);

    while (true)
    {
        printf("(1)Login or (2)register: ");
        fflush(stdout);

        fgets(command, COMMAND_SIZE, stdin);
        size_t length = strlen(command);

        if (length == 2 && (command[0] == '1' || command[0] == '2')) {
            command[length - 1] = '\0';
            break;
        }
        else if (length > COMMAND_SIZE - 2 && command[COMMAND_SIZE - 2] != '\n')
            while (fgetc(stdin) != '\n');

        memset(command, 0, COMMAND_SIZE);
        printf("\nCommand not recognized.\n\n");
    }

    get_user(user);
    get_password(password);

    OpenSSL_add_ssl_algorithms();
    SSL_load_error_strings();

    if (command[0] == '2') {
        ssl_open();

        snprintf(request, REQUEST_SIZE, "R&%s&%s", user, password);
        SSL_write(cSSL, request, REQUEST_SIZE);

        memset(response, 0, RESPONSE_SIZE);
        SSL_read(cSSL, response, RESPONSE_SIZE);

        if (response[0] != '0')
        {
            printf("\n\n%s\nPlease restart the application.", response + 2);
            error = true;
        }
        else
        {
            printf("\n\nRegistration of the user %s successful.", response + 2);
            error = false;
        }
        fflush(stdout);
        ssl_close(sockfd, cSSL);

        if (error)
        {
            fgets(discard, sizeof(discard), stdin);
            ssl_exit(1);
        }
    }

    while (true)
    {
        while(true)
        {
            printf("\n\nChoose an action:\n1. Get last page\n2. Get first page");
            printf("\n3. Insert new message\n4. Search messages of an user\n5. Change password\n");
            fflush(stdout);

            fgets(command, COMMAND_SIZE, stdin);
            size_t length = strlen(command);

            error = false;
            if (length > 2)
            {
                while (fgetc(stdin) != '\n');
                error = true;
            }

            if (length != 2)
                error = true;
            else if(command[0] == '1')
                command[0] = 'L';
            else if(command[0] == '2')
                command[0] = 'G';
            else if(command[0] == '3')
                command[0] = 'I';
            else if(command[0] == '4')
                command[0] = 'S';
            else if(command[0] == '5')
                command[0] = 'P';
            else
                error = true;

            if(!error)
            {
                command[1] = '\0';
                break;
            }
            printf("\nCommand not recognized.\n\n");
        }

        while(true)
        {
            if (command[0] == '\0')
                break;

            if (command[0] == 'L')
            {
                int_argument = -1;
                get_page();
            }
            else if(command[0] == 'G')
                get_page();
            else if(command[0] == 'E')
                expand_message();
            else if(command[0] == 'I')
                insert_message();
            else if(command[0] == 'D')
                deactivate_message();
            else if(command[0] == 'S')
                stalk_user();
            else if (command[0] == 'A')
                activate_message();
            else if (strcmp(command, "P") == 0)
                change_pwd();
            else
            {
                printf("Client error!");
                ssl_exit(101);
            }
        }
    }
}





void activate_message()
{
    int message_id = int_argument;
    memset(command, 0, COMMAND_SIZE);
    memset(request, 0, REQUEST_SIZE);
    memset(response, 0, RESPONSE_SIZE);
    int_argument = 0;

    snprintf(request, REQUEST_SIZE, "A&%s&%s&%d", user, password, message_id);
    ssl_open();
    SSL_write(cSSL, request, REQUEST_SIZE);
    SSL_read(cSSL, response, RESPONSE_SIZE);
    ssl_close(sockfd, cSSL);

    check_authentication();

    if(strtok(response, "&")[0] != '0')
    {
        printf("\n%s", strtok(NULL, "&"));
        return;
    }

    int_argument = message_id;
    command[0] = 'E';
}



void change_pwd()
{
    char new_pwd[PASSWORD_SIZE + 2] = {0}, new_pwd_conf[PASSWORD_SIZE + 2] = {0};
    while(true)
    {
        memset(request, 0, REQUEST_SIZE);

        printf("\nType the new password.");
        get_password(new_pwd);

        printf("\nConfirm the password.");
        get_password(new_pwd_conf);

        if(strcmp(new_pwd, new_pwd_conf) == 0)
        {
            snprintf(request, REQUEST_SIZE, "P&%s&%s&%s", user, password, new_pwd);
            break;
        }

        memset(new_pwd, 0, sizeof(new_pwd));
        memset(new_pwd_conf, 0, sizeof(new_pwd_conf));

        printf("\n\nThe passwords do not match!\n");
    }

    memset(response, 0, RESPONSE_SIZE);
    ssl_open();
    SSL_write(cSSL, request, REQUEST_SIZE);
    SSL_read(cSSL, response, RESPONSE_SIZE);
    ssl_close(sockfd, cSSL);

    check_authentication();

    if(response[0] != '0')
        server_error();

    for (int i = 0; i < PASSWORD_SIZE; i++)
        password[i] = new_pwd[i];

    printf("\nPassword change successful.");
    fflush(stdout);

    memset(command, 0, COMMAND_SIZE);
}



void deactivate_message()
{
    int message_id = int_argument;
    memset(command, 0, COMMAND_SIZE);
    memset(request, 0, REQUEST_SIZE);
    memset(response, 0, RESPONSE_SIZE);
    int_argument = 0;

    snprintf(request, REQUEST_SIZE, "D&%s&%s&%d", user, password, message_id);
    ssl_open();
    SSL_write(cSSL, request, REQUEST_SIZE);
    SSL_read(cSSL, response, RESPONSE_SIZE);
    ssl_close(sockfd, cSSL);

    check_authentication();

    if(strtok(response, "&")[0] != '0')
    {
        printf("\n%s", strtok(NULL, "&"));
        return;
    }

    int_argument = message_id;
    command[0] = 'E';
}



void expand_message()
{
    int message_id = int_argument;
    memset(command, 0, COMMAND_SIZE);
    memset(request, 0, REQUEST_SIZE);
    memset(response, 0, RESPONSE_SIZE);
    int_argument = 0;

    snprintf(request, REQUEST_SIZE, "E&%s&%s&%d", user, password, message_id);
    ssl_open();
    SSL_write(cSSL, request, REQUEST_SIZE);
    SSL_read(cSSL, response, RESPONSE_SIZE);
    ssl_close(sockfd, cSSL);

    check_authentication();

    if(strtok(response, "&")[0] != '0')
    {
        printf("\n%s", strtok(NULL, "&"));
        return;
    }

    strtok(NULL, "&");
    int active;
    if(!stoint(strtok(NULL, "&"), &active))
        server_error();

    char* content = strtok(NULL, "&");
    char* subject = strtok(NULL, "&");
    char* date = strtok(NULL, "&");
    char* user_msg = strtok(NULL, "&");

    if(active)
        printf("\nmessage %d by %s at %s\nSubject: %s\n%s", message_id, user_msg, date, subject, content);
    else
        printf("\nmessage %d by %s at %s - DELETED\nSubject: %s\n%s", message_id, user_msg, date, subject, content);

    printf("\n\nType ");
    if (strcmp(user, user_msg) == 0)
    {
        if (active)
            printf("'D' to delete ");
        else
            printf("'R' to restore ");
        printf("this message, ");
    }


    printf("'P' to read the previous message, 'N' to read the next, ");
    printf("'UF' to see the first message of the user, 'UN' to see his/her next messages, ");
    printf("nothing to return to the main menu: ");
    fflush(stdout);

    fgets(command, COMMAND_SIZE, stdin);
    size_t length = strlen(command);

    if(strcmp(command, "D\n") == 0 && strcmp(user, user_msg) == 0)
        int_argument = message_id;
    else if(strcmp(command, "R\n") == 0 && strcmp(user, user_msg) == 0)
    {
        memset(command, 0, COMMAND_SIZE);
        command[0] = 'A';

        int_argument = message_id;
    }
    else if(strcmp(command, "N\n") == 0)
    {
        memset(command, 0, COMMAND_SIZE);
        command[0] = 'E';

        int_argument = message_id;
        int_argument++;
    }
    else if(strcmp(command, "P\n") == 0)
    {
        memset(command, 0, COMMAND_SIZE);
        command[0] = 'E';

        int_argument = message_id;
        int_argument--;
    }
    else if (length > COMMAND_SIZE - 2  && command[COMMAND_SIZE - 2] != '\n')
    {
        while (fgetc(stdin) != '\n');

        printf("\nCommand not recognized!");
    }
    else if(command[0] == 'U')
    {
        if (command[1] == 'N')
        {
            int_argument = message_id;
            int_argument++;
        }

        memset(command, 0, COMMAND_SIZE);
        command[0] = 'S';

        memset(user_argument, 0, USER_SIZE + 2);
        snprintf(user_argument, USER_SIZE, user_msg);
    }
    else
        memset(command, 0, COMMAND_SIZE);
}



void get_page()
{
    memset(command, 0, COMMAND_SIZE);
    memset(request, 0, REQUEST_SIZE);
    memset(response, 0, RESPONSE_SIZE);

    snprintf(request, REQUEST_SIZE, "G&%s&%s&%d", user, password, int_argument);
    int_argument = 0;

    ssl_open();
    SSL_write(cSSL, request, REQUEST_SIZE);
    SSL_read(cSSL, response, RESPONSE_SIZE);
    ssl_close(sockfd, cSSL);

    check_authentication();

    if(strtok(response, "&")[0] != '0')
    {
        printf("\n%s", strtok(NULL, "&"));
        return;
    }

    int max;
    if(!stoint(strtok(NULL, "&"), &max))
        server_error();

    int first_message;
    if(!stoint(strtok(NULL, "&"), &first_message))
        server_error();

    if(max == 0)
    {
        if (first_message > 0)
            printf("\n\nNo more messages.");
        else
            printf("\n\nNo messages on the board.");

        fflush(stdout);
        return;
    }

    char* msg_active, *msg_subject, *msg_timestamp, *msg_user;
    int msg_active_int;
    for (int i = 0; i < max; i++)
    {
        msg_timestamp = strtok(NULL, "&");
        msg_user = strtok(NULL, "&");
        msg_subject = strtok(NULL, "&");
        msg_active = strtok(NULL, "&");

        bool converted = stoint(msg_active, &msg_active_int);
        printf("\n%d\t %s\t %s\t %s\t %s", first_message + i, msg_timestamp, msg_user, msg_subject,
               converted ? (msg_active_int ? "" : "DELETED") : "Unknown state");
    }


    printf("\n\nType the id of a message to see its content, ");
    printf("'N' to go to the next page, ");
    printf("'P' to go to the previous one, ");
    printf("nothing to return to the main menu: ");
    fflush(stdout);

    fgets(command, COMMAND_SIZE, stdin);
    size_t length = strlen(command);

    if(strcmp(command, "N\n") == 0)
    {
        memset(command, 0, COMMAND_SIZE);
        command[0] = 'G';

        int_argument = first_message + max;
        return;
    }
    else if (strcmp(command, "P\n") == 0)
    {
        memset(command, 0, COMMAND_SIZE);
        command[0] = 'G';

        int_argument = first_message - 1;

        return;
    }
    else if (length > COMMAND_SIZE - 2  && command[COMMAND_SIZE - 2] != '\n')
    {
        while (fgetc(stdin) != '\n');

        printf("\nCommand not recognized!");
    }
    else if (stoint(command, &int_argument))
    {
        memset(command, 0, COMMAND_SIZE);
        memset(user_argument, 0, USER_SIZE + 2);
        command[0] = 'E';

        return;
    }

    memset(command, 0, COMMAND_SIZE);
    memset(user_argument, 0, USER_SIZE + 2);
}



void insert_message()
{
    memset(command, 0, COMMAND_SIZE);
    memset(request, 0, REQUEST_SIZE);
    memset(response, 0, RESPONSE_SIZE);

    char subject[SUBJECT_SIZE + 2];
    while (true)
    {
        printf("\nType the subject.\nIts length must be comprised from %d to %d ASCII characters", 1, SUBJECT_SIZE - 1);
        printf(" and can not contain '&'.\n");
        fflush(stdout);

        fgets(subject, SUBJECT_SIZE + 2, stdin);
        error = false;

        size_t length = strlen(subject);

        if (length > 1 && length <= SUBJECT_SIZE && check_ampersand(subject, length))
        {
            subject[length - 1] = '\0';
            break;
        }
        else if(length > SUBJECT_SIZE && subject[SUBJECT_SIZE] != '\n')
            while (fgetc(stdin) != '\n');

        printf("\nWrong input!\n\n");
    }

    char content[CONTENT_SIZE + 2];
    while (true)
    {
        printf("\nType the content.\nIts length must be comprised from %d to %d ASCII characters", 1, CONTENT_SIZE - 1);
        printf(" and can not contain '&'.\n");
        fflush(stdout);

        fgets(content, CONTENT_SIZE + 2, stdin);
        error = false;

        size_t length = strlen(content);

        if (length > 1 && length <= CONTENT_SIZE && check_ampersand(content, length))
        {
            content[length - 1] = '\0';
            break;
        }
        else if(length > CONTENT_SIZE && content[CONTENT_SIZE] != '\n')
            while (fgetc(stdin) != '\n');

        printf("\nWrong input!\n\n");
    }

    snprintf(request, REQUEST_SIZE, "I&%s&%s&%s&%s", user, password, subject, content);

    ssl_open();
    SSL_write(cSSL, request, REQUEST_SIZE);
    SSL_read(cSSL, response, RESPONSE_SIZE);
    ssl_close(sockfd, cSSL);

    check_authentication();

    if((strtok(response, "&"))[0] == '0')
        printf("\n\nMessage inserted with id %s", strtok(NULL, "&"));

    else
        printf("\n\n%s", strtok(NULL, "&"));
}



void stalk_user()
{
    memset(command, 0, COMMAND_SIZE);
    memset(request, 0,  REQUEST_SIZE);
    memset(response, 0, RESPONSE_SIZE);

    if(strlen(user_argument) == 0)
    get_user(user_argument);

    int first_message = int_argument;
    int_argument = 0;
    snprintf(request, REQUEST_SIZE, "S&%s&%s&%s&%d", user, password, user_argument, first_message);

    ssl_open();
    SSL_write(cSSL, request, REQUEST_SIZE);
    SSL_read(cSSL, response, RESPONSE_SIZE);
    ssl_close(sockfd, cSSL);

    check_authentication();

    int max;
    if(strtok(response, "&")[0] != '0')
    {
        printf("\n%s", strtok(NULL, "&"));

        memset(user_argument, 0, USER_SIZE + 2);
        return;
    }

    if(!stoint(strtok(NULL, "&"), &max))
        server_error();

    if(max == 0)
    {
        if (first_message == 0)
            printf("\n\nNo messages from the user.");
        else
            printf("\n\nNo more messages");
        fflush(stdout);

        memset(user_argument, 0, USER_SIZE + 2);
        return;
    }

    char* msg_active, *msg_id, *msg_subject, *msg_timestamp, *last_id = NULL;
    int msg_active_int;
    for (int i = 0; i < max; i++)
    {
        msg_id = strtok(NULL, "&");
        msg_timestamp = strtok(NULL, "&");
        msg_subject = strtok(NULL, "&");
        msg_active = strtok(NULL, "&");
        last_id = msg_id;

        bool converted = stoint(msg_active, &msg_active_int);
        printf("\n%s\t %s\t %s\t %s", msg_id, msg_timestamp, msg_subject, converted ? (msg_active_int ? "" : "DELETED") :
                                                                    "Unknown state");
    }

    printf("\n\nType the id of a message to see its content, ");
    printf("'N' to go to the next page, ");
    printf("nothing to return to the main menu: ");
    fflush(stdout);

    fgets(command, COMMAND_SIZE, stdin);
    size_t length = strlen(command);

    if(strcmp(command, "N\n") == 0)
    {
        memset(command, 0, COMMAND_SIZE);
        command[0] = 'S';

        stoint(last_id, &int_argument);

        int_argument++;
        return;
    }
    else if (length > COMMAND_SIZE - 2  && command[COMMAND_SIZE - 2] != '\n')
    {
        while (fgetc(stdin) != '\n');

        printf("\nCommand not recognized!");
    }
    else if (!stoint(command, &int_argument))
        int_argument = 0;
    else
    {
        memset(command, 0, COMMAND_SIZE);
        memset(user_argument, 0, USER_SIZE + 2);
        command[0] = 'E';

        return;
    }

    memset(command, 0, COMMAND_SIZE);
    memset(user_argument, 0, USER_SIZE + 2);
}





void exit_handler(int signo)
{
    ssl_close(sockfd, cSSL);
    ssl_exit(0);
}



bool check_ampersand(char* field, size_t size)
{
    for (int i = 0; i < size; i++)
        if (field[i] == '&')
            return false;

    return true;
}



void check_authentication()
{
    if((response[0] != '1' && response[0] != '2') || response[1] != '&')
        return;

    printf("\nAuthentication failure: %s\nThe application will close automatically.", response + 2);
    fflush(stdout);

    ssl_exit(5);
}



void get_password(char* buffer)
{
    while (true) {
        printf("\nType the password.\nIts length must be comprised from %d to %d ASCII characters",
               8, PASSWORD_SIZE - 1);
        printf(" and can not contain '&'.\n");
        fflush(stdout);

        fgets(buffer, PASSWORD_SIZE + 2, stdin);
        error = false;

        size_t length = strlen(buffer);

        if (length > 8 && length <= PASSWORD_SIZE && check_ampersand(buffer, length))
        {
            buffer[length - 1] = '\0';
            break;
        }
        else if(length > PASSWORD_SIZE && buffer[PASSWORD_SIZE] != '\n')
            while (fgetc(stdin) != '\n');

        printf("\nWrong input!\n\n");
    }
}



void get_user(char* buffer)
{
    while (true)
    {
        printf("\n\nType the user id.\nIts length must be comprised from %d to %d ASCII characters", 4, USER_SIZE - 1);
        printf(" and can not contain '&'.\n");
        fflush(stdout);

        fgets(buffer, USER_SIZE + 2, stdin);
        error = false;

        size_t length = strlen(buffer);
        if (length > 4 && length <= USER_SIZE && check_ampersand(buffer, length))
        {
            buffer[length - 1] = '\0';
            break;
        }
        else if(length > USER_SIZE && buffer[USER_SIZE] != '\n')
            while (fgetc(stdin) != '\n');

        printf("\nWrong input!\n\n");
    }
}



void server_error()
{
    printf("\n\nServer error!");

    ssl_exit(99);
}



void ssl_open()
{
    printf("\n\nConnecting...\n");
    fflush(stdout);

    while(true)
    {
        sockfd = socket(AF_INET, SOCK_STREAM, 0);
        if (sockfd != -1)
            break;
        if (errno == EINTR)
            continue;

        printf("Error %d when creating socket!", errno);
        fflush(stdout);
        fgets(discard, sizeof(discard), stdin);

        exit(1);
    }

    struct timeval timeout;
    timeout.tv_sec = 2;
    timeout.tv_usec = 0;
    setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
    setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &enable, sizeof(enable));

    struct sockaddr_in serv_addr;
    serv_addr.sin_family = AF_INET;
    inet_aton(ADDRESS, &serv_addr.sin_addr);
    serv_addr.sin_port = htons(PORT);
    while(true)
    {
        if(connect(sockfd, (struct sockaddr*) &serv_addr, sizeof(serv_addr)) == 0)
            break;
        if (errno == EINTR)
            continue;

        printf("Error %d when connecting to the server!", errno);
        fflush(stdout);
        fgets(discard, sizeof(discard), stdin);

        close(sockfd);
        exit(2);
    }

    printf("Connection done. Initializing SSL...\n");

    errno = 0;
    SSL_CTX* sslctx = SSL_CTX_new(TLSv1_2_client_method());
    SSL_CTX_set_options(sslctx, SSL_OP_SINGLE_DH_USE);

    cSSL = SSL_new(sslctx);
    SSL_set_fd(cSSL, sockfd);

    if(!ssl_check_error(SSL_connect(cSSL)))
    {
        printf("Error initializing SSL.\nPlease restart the application.\n");
        fflush(stdout);

        fgets(discard, sizeof(discard), stdout);

        ssl_close(sockfd, cSSL);
        ssl_exit(3);
    }
}
