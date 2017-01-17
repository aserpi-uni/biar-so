#include "message.h"
#include "user.h"

/**
 * Initializes the board.
 *
 * @param users Minimum  number of users guaranteed.
 * @param pages Minimum number of pages guaranteed.
 * @param page_size Number of messages per page.
 *
 * @return 0 if succeeding <br>
 * -1 if the board was already initialized <br>
 * -1x if there is an error initializing the user part <br>
 * -1xx if there is an error initializing the message part <br>
 *
 * @warning This function must be called before performing any operation on the board.
 */
int initialize_board(int users, int pages, int page_size);


/**
 * Returns if the board has been already initialized.
 */
bool is_initialized();


/**
 * Closes the board.
 *
 * @returns Returns if the board was already closed.
 *
 * @warning After calling this function, no more operations can be performed on the board.
 */
bool shutdown_board();