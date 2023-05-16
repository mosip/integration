/**
 * Header file Codebase for Central Server
 *
 **/

#pragma once
#ifndef CS_H
#define CS_H

#include "dbgen.h"
#include "tpp.h"
#include <iostream>
#include <fstream>

using namespace std;

class CentralServer{
    private:
        seal::PublicKey pk;
        seal::SecretKey sk;
        seal::Decryptor* decryptor;
        seal::Evaluator* evaluator;

    public:
        seal::BatchEncoder* encoder;
        seal::Encryptor* encryptor;
        CentralServer();
        int encryptInput(string data, int type, seal::Ciphertext* out);
        vector<int> decrypt(seal::Ciphertext* c);
        void printVector(seal::Ciphertext* out);
};

#endif
