#include "stdbool.h"
#include <time.h>

#define CONTENT_SIZE 174
#define subject_SIZE 32
#define USER_SIZE 16



/**
 * Struct containing a message.
 */
typedef struct msg {
    bool active;
    time_t timestamp;
    char user[USER_SIZE];
    char subject[subject_SIZE];
    char content[CONTENT_SIZE];
} msg;


/**
 * Closes the message part of the board.
 *
 * @warning This function must not be called directly.
 */
void close_message();


/**
 * Marks a message as deleted.
 *
 * @param id The message id.
 *
 * @return True if the message has been deleted or was already inactive, false if there is no message with such an id.
 */
bool delete_message(int id); //Deactivate


/**
 * Inserts a new message with the specified attributes.
 *
 * @param user The user that is inserting the message.
 * @param subject The subject of the message.
 * @param content The textual content of the message.
 *
 * @return The message id.
 */
int message(char* user, char* subject, char* content); //Insert


/**
 * Gets a message with the specified id.
 *
 * @return A pointer to the desired message (must be freed by the user).
 * If there is no such a message or enough memory, NULL is returned.
 */
msg* get_message(int id);  //Expand


/**
 * Get the page of the board containing the message with the specified id.
 *
 *
 * @param start First accepted message. If it -1, then the last page is returned.
 * @param size In the location pointer by the parameter is copied the number of messages returned.
 *
 * @returns An array of messages.
 * If there is no message with such an id or not enough memory to store the page, NULL is returned.
 */
msg* get_messages(int start, int* size); //Get


/**
 * Returns a page filled with messages of the specified user.
 *
 * @param start Id of the first accepted message.
 * @param ids Where will be copied the message ids.
 * @param retrieved Where will be copied the number of messages returned.
 *
 * @return An array of messages.
 * If there is no message with id equal to start or not enough memory to store the page, NULL is returned.
 */
msg* get_user_messages(char* user, int start, int* ids, int* retrieved); //Stalk


/**
 * Initializes the message part of the board.
 *
 * @param pg_size Messages per page.
 * @param pgs Starting pages.
 *
 * @return 0 if succeeding, -1 if there is not enough memory.
 *
 * @warning This function must not be called directly.
 */
int initialize_message(int pgs, int pg_size);


/**
 * Restores a deleted message.
 *
 * @return True if the message has been restored or was already active, false if there is no message with such an id.
 */
bool restore_message(int id); //Activate