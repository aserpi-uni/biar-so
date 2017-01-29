#include <malloc.h>
#include <string.h>
#include "message.h"



int last_message;
msg** messages;
int pages;
int page_size;



void copy_message(msg* message, msg* copy)
{
    copy->active = message->active;
    strcpy(copy->content, message->content);
    strcpy(copy->subject, message->subject);
    copy->timestamp = message->timestamp;
    strcpy(copy->user, message->user);
}


void close_message()
{
    for (int i = 0; i < last_message/page_size; i++)
        free(messages[i]);
    free(messages);
}


bool delete_message(int id)
{
    if (id < 0 || id > last_message)
        return false;

    messages[id/page_size][id%page_size].active = false;

    return true;
}


bool get_message(int id, msg* message)
{
    if (id < 0 || id > last_message)
        return false;

    copy_message(&messages[id/page_size][id%page_size], message);

    if (!message->active)
        strncpy(message->content, "DELETED", CONTENT_SIZE);

    return true;
}


msg* get_messages(int start, int* size, int* id)
{
    *size = 0;
    *id = start > 0 ? start : 0;

    if (start == -1)
        start = last_message;
    else if (start < 0 || start > last_message)
        return NULL;

    *id = start = start/page_size*page_size;
    msg* new_page = malloc(page_size*sizeof(msg));

    for (; *size < page_size; (*size)++)
    {
        if(!get_message(start + *size, &new_page[*size]))
            break;
    }

    new_page = realloc(new_page, (*size)*sizeof(msg));
    return new_page;
}


msg* get_user_messages(char* user, int start, int* ids, int* size)
{
    *size = 0;

    if (start < 0 || start > last_message)
        return NULL;

    msg* new_page = malloc(page_size*sizeof(msg));
    for (int i = start; (i <= last_message) && (*size < page_size); i++)
    {
        msg* message = &(messages[i/page_size][i%page_size]);

        if (strcmp(message->user, user) != 0)
            continue;

        get_message(i, &new_page[*size]);
        ids[*size] = i;
        (*size)++;
    }

    new_page = realloc(new_page, (*size)*sizeof(msg));
    return new_page;
}


int initialize_message(int pgs, int pg_size)
{
    last_message = -1;
    pages = pgs;
    page_size = pg_size;

    messages = malloc(pages * sizeof(msg*));
    return messages != NULL ? 0 : -1;
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
    if (id < 0 || id > last_message)
        return false;

    messages[id/page_size][id%page_size].active = true;

    return true;
}