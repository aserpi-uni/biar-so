#include <stdbool.h>



/**
 * Struct containing an user.
 */
struct usr;


/**
 * Changes the password for a specified user.
 *
 * @param id The user id.
 * @param new_pwd The new password.
 */
void change_pwd(char* id, char* new_pwd); //Password


/** Checks the correctness of a password.
 *
 * @param id The user id.
 * @param pwd The password inserted.
 *
 * @return 0 if the password provided is correct <br>
 * -1 if there is no user with such an id <br>
 * -2 if there password is not correct.
 */
int check_pwd(char* id, char* pwd);


/**
 * Closes the user part of the board.
 *
 * @warning This function must not be called directly.
 */
void close_user();


/**
 * Check if a user exists in the board.
 *
 * @param user The user id.
 */
bool exists_user(char* user);


/**
 * Initializes the user part of the board.
 *
 * @param size The guaranteed number of users.
 *
 * @return 0 if succeeding, -1 if there is not enough memory.
 *
 * @warning This function must not be called directly.
 */
int initialize_user(int size);


/**
 * Inserts a new user with the specified attributes.
 *
 * @param id The new user's id.
 * @param pwd The new user's password.
 *
 * @return The user id.
 * If there is already an user with such an id or no enough memory, NULL is returned.
 */
char* user(char* id, char* pwd); //Register
