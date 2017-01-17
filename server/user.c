#include <malloc.h>
#include <string.h>
#include "user.h"



#define USER_SIZE 16
#define PASSWORD_SIZE 32



struct usr {
    char id[USER_SIZE];
    char pwd[PASSWORD_SIZE];
};



int last_user, unit_size, unities;
struct usr* users;
struct usr* get_user(char* id);



void change_pwd(char* id, char* new_pwd)
{
    strcpy(get_user(id)->pwd, new_pwd);
}


int check_pwd(char* id, char* pwd)
{
    struct usr* user = get_user(id);
    if (user == NULL)
        return -1;

    return strcmp(user->pwd, pwd) == 0 ? 0 : -2;
}


bool exists_user(char* user)
{
    for (int i = 0; i < last_user + 1; i++)
        if(strcmp(users[i].id, user) == 0)
            return true;

    return false;
}


struct usr* get_user(char* id)
{
    for (int i = 0; i < last_user + 1; i++)
        if (strcmp(users[i].id, id) == 0)
            return &users[i];

    return NULL;
}


int initialize_user(int size)
{
    last_user = -1;
    unit_size = size;
    unities = 1;

    users = malloc(unit_size * sizeof(struct usr));
    if (users == NULL)
        return -1;

    return 0;
}

void close_user()
{
    free(users);
}


char* user(char* id, char* pwd)
{
    for (int i = 0; i < last_user; i++)
        if (strcmp(users[i].id, id) == 0)
            return NULL;

    last_user++;

    if (last_user > unit_size*unities)
    {
        unities++;

        struct usr* new_users = realloc(users, (size_t)unit_size);
        if (new_users == NULL)
        {
            unities--;
            return NULL;
        }

        free(users);
        users = new_users;
    }

    strcpy(users[last_user].id, id);
    strcpy(users[last_user].pwd, pwd);

    char* ret = (char*)malloc((strlen(users[last_user].id) + 1)* sizeof(char));
    strcpy(ret, users[last_user].id);
    return ret;
}
