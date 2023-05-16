/**
 * Header file for Script for generating and storing the user data and keys
 *
 **/

#pragma once

#include "encrypteduser.h"
#include <fstream>


void writeKey(seal::SecretKey *sk_pointer);
void writeUser(EncryptedUser* e_pointer);
void generateDatabase();
