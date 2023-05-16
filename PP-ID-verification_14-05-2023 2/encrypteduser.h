/**
 * Header file for the EncryptedUser class
 *
 **/

#pragma once
#include "seal/seal.h"
#include "user.h"

#ifndef ENCRYPTEDUSER
#define ENCRYPTEDUSER

class EncryptedUser{
    public:
        seal::BatchEncoder* batch_encoder;
        seal::PublicKey* public_key;
        seal::Encryptor* encryptor;
        seal::Evaluator* evaluator;

    // For having each demographic field data as a spearate entry
        // seal::Ciphertext enc_name;
        // seal::Ciphertext enc_sex;
        // seal::Ciphertext enc_pincode;
        // seal::Ciphertext enc_dateofbirth;
        // seal::Ciphertext enc_phonenumber;
        // seal::Ciphertext enc_email;
        // seal::Ciphertext enc_biometric_template;

    // Combining demographic data into a single vector
        seal::Ciphertext enc_demographic;
        // seal::Ciphertext enc_dateofbirth;
        seal::Ciphertext enc_biometric_template;




        int ID;

        EncryptedUser(User* user = nullptr, seal::BatchEncoder* be = nullptr, seal::PublicKey* pk = nullptr, seal::Encryptor* enc = nullptr, seal::Evaluator* eval = nullptr, int id = 0);

        
};


#endif
