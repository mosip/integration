/**
 * Header file for the User class
 *
 **/

#pragma once
#ifndef USER
#define USER
#include <string>
#include <vector>

std::string convertToString(char* a, int size);

class User{
    private:
    // Data members    
    std::string name; //50
    char sex;
    std::string pincode; // 6
    int dateofbirth_year; // 8
    int dateofbirth_day; // 8
    std::string phonenumber; // 13
    std::string email; // 30
    std::vector<int> biometric_template = std::vector<int>(640);

    public:

    User(std::string n, char s, std::string pin, std::string dob, std::string pno, std::string e, std::vector<int> bio);
    std::string getName();
    std::string getEmail();
    std::string getPincode();
    std::string getDOB();
    std::string getPno();
    char getSex();
    std::vector<int> getTemplate();
};

#endif
