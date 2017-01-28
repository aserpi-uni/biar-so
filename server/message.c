#include <malloc.h>
#include <string.h>
#include "message.h"



int last_message;
msg** messages;
int pages;
int page_size;



msg* copy_message(msg* message)
{
    msg* new_message = (msg*)malloc(sizeof(msg));

    new_message->active = message->active;
    strcpy(new_message->content, message->content);
    strcpy(new_message->subject, message->subject);
    new_message->timestamp = message->timestamp;
    strcpy(new_message->user, message->user);

    return new_message;
}


void close_message()
{
    for (int i = 0; i < last_message/page_size; i++)
        free(messages[i]);
    free(messages);
}


bool delete_message(int id)
{
    if (id > last_message)
        return false;

    messages[id/page_size][id%page_size].active = false;

    return true;
}


msg* get_message(int id)
{
    if (id > last_message || id < 0)
        return NULL;

    msg* message = copy_message(&messages[id/page_size][id%page_size]);

    if (!message->active)
        strncpy(message->content, "DELETED", CONTENT_SIZE);

    return message;
}


msg* get_messages(int start, int* size)
{
    if (start == -1)
        start = last_message;
    else if (start > last_message || start < 0)
        return NULL;

    msg* new_page = malloc(page_size*sizeof(msg));
    start = start/page_size*page_size;
    for (int i = 0; i < page_size; i++)
    {
        msg* message = get_message(start + i);
        new_page[i] = *message;
        free(message);
    }

    *size = page_size;
    return new_page;
}


msg* get_user_messages(char* user, int start, int* ids, int* size)
{
    *size = 0;

    if (start > last_message || start < 0)
        return NULL;

    msg* new_page = malloc(page_size*sizeof(msg));
    msg* copy_message;
    for (int i = start; (i <= last_message) && (*size < page_size); i++)
    {
        msg* message = &(messages[i/page_size][i%page_size]);
        if (strcmp(message->user, user) != 0)
            continue;

        copy_message = get_message(i);
        new_page[*size] = *copy_message;
        free(copy_message);

        ids[*size] = i;
        (*size)++;
    }

    return new_page;
}


int initialize_message(int pgs, int pg_size)
{
    last_message = -1;
    pages = pgs;
    page_size = pg_size;

    messages = malloc(pages * sizeof(msg*));
    if (messages == NULL)
        return -1;

    return 0;
}


int message(char* user, char* subject, char* content)
{
    last_message++;

    if (last_message%page_size == 0)
    {
        if (last_message/page_size > pages)
        {
            int new_pages = (int)(last_message / page_size * 1.5);
            msg** new_messages = realloc(messages, (size_t)new_pages);
            if (new_messages == NULL)
            {
                last_message--;
                return -1;
            }

            free(messages);
            messages = new_messages;
            pages = new_pages;
        }

        msg* new_array = malloc(page_size*sizeof(msg));
        if (new_array == NULL)
        {
            last_message--;
            return -2;
        }
        messages[last_message/page_size] = new_array;
    }

    messages[last_message/page_size][last_message%page_size].active = true;
    strncpy(messages[last_message/page_size][last_message%page_size].content, content, CONTENT_SIZE);
    strncpy(messages[last_message/page_size][last_message%page_size].subject, subject, SUBJECT_SIZE);
    time(&messages[last_message/page_size][last_message%page_size].timestamp);
    strncpy(messages[last_message/page_size][last_message%page_size].user, user, USER_SIZE);

    return last_message;
}


bool restore_message(int id)
{
    if (id > last_message)
        return false;

    messages[id / page_size][id % page_size].active = true;

    return true;
}