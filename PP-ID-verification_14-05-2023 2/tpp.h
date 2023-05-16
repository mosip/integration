/**
 * Implementation file for  Third party server routines.
 *
 **/

#pragma once
#ifndef TPP_H
#define TPP_H

#include "encrypteduser.h"

class TPP{
    private:
        seal::SEALContext* context;
        seal::PublicKey pk;
        seal::RelinKeys rk;
        seal::GaloisKeys gk;
        seal::BatchEncoder* encoder;
        seal::Encryptor* encryptor;
        seal::Evaluator* evaluator;
    public:
        TPP();
        int findUser(int id);
        void AND(seal::Ciphertext* c1, seal::Ciphertext* c2, seal::Ciphertext* output);
        void NOT(seal::Ciphertext* c, seal::Ciphertext* output);
        void OR(seal::Ciphertext* c1, seal::Ciphertext* c2, seal::Ciphertext* output);
        void XOR(seal::Ciphertext* c1, seal::Ciphertext* c2, seal::Ciphertext* output);

        seal::Ciphertext* generateEmpty(int start, int size);
        // void rotate_and_add(seal::Ciphertext* input, int rotations, seal::Ciphertext* output, seal::Evaluator* evaluator, seal::GaloisKeys* gk, int type);

        void compareName(seal::Ciphertext* inputName, int id);
        void compareSex(seal::Ciphertext* inputSex, int id);
        void comparePincode(seal::Ciphertext* inputPincode, int id);
        void compareEmail(seal::Ciphertext* inputEmail, int id);
        void comparePhonenumber(seal::Ciphertext* inputPhonenumber, int id);
        void compareDOB(std::string input, int id, seal::Ciphertext* output);
        void compareBiometric(seal::Ciphertext* input, int id, seal::Ciphertext* output);
        void compareBiometricSingle(seal::Ciphertext* input, int id, seal::Ciphertext* output);
};

#endif
