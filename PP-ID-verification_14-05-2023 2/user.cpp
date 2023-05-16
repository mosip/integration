/**
 * Class files for the User class
 *
 **/

#include "user.h"
#include<iostream>
using namespace std;


string convertToString(char* a, int size)
{
    string s(a);
    int spaces = size - s.size();
    while (spaces > 0){
        s = s + " ";
        spaces = spaces - 1;
    }
    return s;
}



User::User(string n, char s, string pin, string dob, string pno, string e, vector<int> bio){
    // We are assuming that for the DoB, the first 3 digits are the year from 1 Jan 1900, and the rest are number of days from 1 Jan for that year in the date. So it has 6 characters.
    name = n;
    sex = s;
    pincode = pin;
    // dateofbirth = dob;
    int temp = stoi(dob);
    dateofbirth_year = temp/1000;
    dateofbirth_day = temp%1000;
    phonenumber = pno;
    email = e;
    // for (int i = 0; i < 640; i++){
    //     biometric_template[i] = bio[i];
    // }
    biometric_template = bio;
}

string User::getName(){
    int spaces = 50 - name.length();
    while (spaces > 0){
        name = name + " ";
        spaces = spaces - 1;
    }
    return name;
}

string User::getEmail(){
    int spaces = 30 - email.length();
    while (spaces > 0){
        email = email + " ";
        spaces = spaces - 1;
    }
    return email;
}

string User::getPincode(){
    return pincode;
}

string User::getDOB(){
    string dob = to_string(dateofbirth_year);
    if (dob.size() < 3)
        dob = "0" + dob;
    string temp = to_string(dateofbirth_day);
    if (temp.size() < 3)
        temp = "0" + temp;
    dob = dob + temp;
    return dob;
}

string User::getPno(){
    return phonenumber;
}

char User::getSex(){
    return sex;
}

vector<int> User::getTemplate(){
    return biometric_template;
}
