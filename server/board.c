#include <stdbool.h>
#include "board.h"

bool initialized;

int initialize_board(int users, int pages, int page_size)
{
    if (initialized)
        return -1;

    int user = initialize_user(users);
    if (user < 0)
        return user*10;

    int message = initialize_message(pages, page_size);
    if (message < 0)
        return message*100;

    initialized = true;
    return 0;
}

bool is_initialized()
{
    return initialized;
}

bool shutdown_board()
{
    if (!initialized)
        return true;

    close_user();

    close_message();

    initialized = false;
    return false;
}
