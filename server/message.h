#include "stdbool.h"
#include <time.h>


#define CONTENT_SIZE 174
#define SUBJECT_SIZE 32
#define USER_SIZE 16



/**
 * Struct containing a message.
 */
typedef struct msg {
    bool active;
    time_t timestamp;
    char user[USER_SIZE];
    char subject[SUBJECT_SIZE];
    char content[CONTENT_SIZE];
} msg;


/**
 * Closes the message part of the board.
 *
 * @warning Must not be called directly.
 */
void close_message();


/**
 * Marks a message as deleted.
 *
 * @param id The message id.
 *
 * @return If the message exists.
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
 * @param id The message id.
 * @param message Pointer to a msg object in which copy the message.
 *
 * @return If the message exists.
 */
bool get_message(int id, msg* message);  //Expand


/**
 * Get the page of the board containing the message with the specified id.
 *
 *
 * @param start First accepted message. If it is -1, then the last page is returned.
 * @param size In the location pointed by the parameter the number of messages is copied.
 * @param id In the location pointed by the parameter the id of the first message is copied.
 *
 * @returns An array of messages.
 * If there is no message with such an id or not enough memory to store the page, NULL is returned.
 */
msg* get_messages(int start, int* size, int* id); //Get


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
