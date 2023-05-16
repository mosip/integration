/**
 * Implementation file for  Third party server routines.
 *
 **/

#include "tpp.h"
#include <iostream>
#include <fstream>

using namespace std;
using namespace seal;

// Assumption:
// Object of type encrypted user has all data stured in a vector, where each element of the vector
// is a bit correcponding to that data. Specifically:-
// Name will be 400 bits, with all the unused bits of 400 padded with 1s
// gender is 8 bits
// DoB is 64 bits
// Phone number is 104 bits
// Email is 160 bits
// pincode is 48 bits
// Biometric is 6720 bits
// For this purpose, we will have a ciphertext modulus of 8192, and a 17 bit plain modulus. 
// Also, the plain modulus needs to be available to the Third Party. 


// Need to read from file:
    // object containing SEALcontext context.
    // Object containing public key

// To generate from context and public key:
    // Encryptor
    // Evaluator
    // BatchEncoder


// Plan of action:-
    // 1. Create functions for AND, NOT, and OR gate.
    // 2. Create functions for each of Name, Age, Pno, email, pincode comparison in binary
    // 3. Implement *sorting*. Worry about operational cost later.


TPP::TPP(){
    EncryptionParameters parms(scheme_type::bfv);
    size_t poly_modulus_degree = 8192;
    parms.set_poly_modulus_degree(poly_modulus_degree);
    parms.set_coeff_modulus(CoeffModulus::BFVDefault(poly_modulus_degree));    
    parms.set_plain_modulus(PlainModulus::Batching(poly_modulus_degree, 22));
    // Checking the validity of the set parameters
    context = new SEALContext(parms);
    ifstream file_obj;
    file_obj.open("keys/publickey.pk", ios::in);
    pk.load(*context, file_obj);
    file_obj.close();
    file_obj.clear();
    file_obj.open("keys/relinkeys.rk", ios::in);
    rk.load(*context, file_obj);
    file_obj.close();
    file_obj.clear();
    file_obj.open("keys/galoiskeys.gk", ios::in);
    gk.load(*context, file_obj);
    encryptor = new Encryptor(*context, pk);
    evaluator = new Evaluator(*context);
    encoder = new BatchEncoder(*context);
    // cout << sizeof(*user) <<endl;
}

int TPP::findUser(int id){
    // Read array of DbObjects from a file and get the one for which the ID is a match. Assign it to user.
    ifstream infile("userData/" + to_string(id) + "_demo.data");
    if (infile.good()){
        return 1;
    }
    else{
        return 0;
    }
    // cout << "here 1" << endl;
    // file_obj.open("data.txt", ios::in);
    // cout << "here 2" << endl;
    // int found = 0;
    // while(!file_obj.eof() || found==1){
    //     cout << "here 4" << endl;
    //     file_obj.read((char*)user, sizeof(*user));
    //     cout << "here 4" << endl;
    //     if (user->ID == id){
    //         found = 1;
    //         file_obj.close();
    //     }
    // }
    // if (found == 0){
    //     cout << "User with given ID not found!" << endl;
    //     exit(0);
    // }
}


// Need to fix all binary ops functions to include
// dynamic memory allocation
void TPP::AND(Ciphertext* c1, Ciphertext* c2, Ciphertext* out){
    evaluator->multiply(*c1, *c2, *out);
    evaluator->relinearize_inplace(*out, rk);
}

void TPP::NOT(Ciphertext* c, Ciphertext* out){
    evaluator->negate(*c, *out);
    size_t slot_count = encoder->slot_count();
    size_t row_size = slot_count / 2;
    vector<uint64_t> template_pod_matrix(slot_count, 1ULL);
    Plaintext plain_matrix;
    encoder->encode(template_pod_matrix, plain_matrix);
    Ciphertext encrypted_matrix;
    encryptor->encrypt(plain_matrix, encrypted_matrix);
    evaluator->add_inplace(*out, encrypted_matrix);
}

void TPP::OR(Ciphertext* c1, Ciphertext* c2, Ciphertext* out){
    Ciphertext* out1 = new Ciphertext();
    Ciphertext* out2 = new Ciphertext();
    Ciphertext* out3 = new Ciphertext();
    NOT(c1, out1);
    NOT(c2, out2);
    // c1 = NOT(c1);
    // c2 = NOT(c2);
    AND(out1, out2, out3);
    NOT(out3, out);
}

void TPP::XOR(Ciphertext* c1, Ciphertext* c2, Ciphertext* out){
    Ciphertext* p1 = new Ciphertext(); 
    Ciphertext* p2 = new Ciphertext();
    Ciphertext* p3 = new Ciphertext();
    OR(c1, c2, p1);
    AND(c1, c2, p2);
    NOT(p2, p3);
    AND(p1, p3, out);
}

Ciphertext* TPP::generateEmpty(int start, int size){
    // Function to generate a ciphertext of all 0's having 1's from start
    // index to finish index
    vector<uint64_t> out(encoder->slot_count(), 0ULL);
    for (int i=start; i<start+size; i++){
        out[i] = 1ULL;
    }
    // cout << "Printing the out vector:-" << endl;
    // for (int i = 0; i < 2000; i++){
    //     cout << out[i] << " "; 
    // }
    // cout << endl;
    Plaintext pout;
    Ciphertext *enc_out = new Ciphertext;
    encoder->encode(out, pout);
    encryptor->encrypt(pout, *enc_out);
    return enc_out;
}

void TPP::compareName(Ciphertext* input, int id){
    ifstream file_obj;
    Ciphertext data;
    file_obj.open("userData/"+to_string(id)+"_demo.data", ios::in);
    data.load(*context, file_obj);
    // evaluator->sub_inplace(*input, user->enc_name);

    chrono::high_resolution_clock::time_point time_start, time_end;
    chrono::microseconds time_diff;
    time_start = chrono::high_resolution_clock::now();
    Ciphertext* empty = generateEmpty(0, 400);
    evaluator->multiply_inplace(*empty, data);
    evaluator->relinearize_inplace(*empty, rk);
    evaluator->sub_inplace(*input, *empty);
    time_end = chrono::high_resolution_clock::now();
    time_diff = chrono::duration_cast<chrono::microseconds>(time_end - time_start);
    cout << "Done [" << time_diff.count() << " microseconds]" << endl;
}

void TPP::compareSex(Ciphertext* input, int id){
    ifstream file_obj;
    Ciphertext data;
    file_obj.open("userData/"+to_string(id)+"_demo.data", ios::in);
    data.load(*context, file_obj);
    // evaluator->sub_inplace(*input, user->enc_sex);
    chrono::high_resolution_clock::time_point time_start, time_end;
    chrono::microseconds time_diff;
    time_start = chrono::high_resolution_clock::now();
    Ciphertext* empty = generateEmpty(400, 8);
    evaluator->multiply_inplace(*empty, data);
    evaluator->relinearize_inplace(*empty, rk);
    evaluator->sub_inplace(*input, *empty);
    evaluator->rotate_rows_inplace(*input, 400, gk);
    time_end = chrono::high_resolution_clock::now();
    time_diff = chrono::duration_cast<chrono::microseconds>(time_end - time_start);
    cout << "Done [" << time_diff.count() << " microseconds]" << endl;
}

void TPP::comparePincode(Ciphertext* input, int id){
    ifstream file_obj;
    Ciphertext data;
    file_obj.open("userData/"+to_string(id)+"_demo.data", ios::in);
    data.load(*context, file_obj);
    // evaluator->sub_inplace(*input, user->enc_pincode);
    chrono::high_resolution_clock::time_point time_start, time_end;
    chrono::microseconds time_diff;
    time_start = chrono::high_resolution_clock::now();
    Ciphertext* empty = generateEmpty(408, 48);
    evaluator->multiply_inplace(*empty, data);
    evaluator->relinearize_inplace(*empty, rk);
    evaluator->sub_inplace(*input, *empty);
    evaluator->rotate_rows_inplace(*input, 408, gk);
    time_end = chrono::high_resolution_clock::now();
    time_diff = chrono::duration_cast<chrono::microseconds>(time_end - time_start);
    cout << "Done [" << time_diff.count() << " microseconds]" << endl;
}

void TPP::compareEmail(Ciphertext* input, int id){
    ifstream file_obj;
    Ciphertext data;
    file_obj.open("userData/"+to_string(id)+"_demo.data", ios::in);
    data.load(*context, file_obj);
    // evaluator->sub_inplace(*input, user->enc_email);
    chrono::high_resolution_clock::time_point time_start, time_end;
    chrono::microseconds time_diff;
    time_start = chrono::high_resolution_clock::now();
    Ciphertext* empty = generateEmpty(560, 240);
    evaluator->multiply_inplace(*empty, data);
    evaluator->relinearize_inplace(*empty, rk);
    evaluator->sub_inplace(*input, *empty);
    evaluator->rotate_rows_inplace(*input, 560, gk);
    time_end = chrono::high_resolution_clock::now();
    time_diff = chrono::duration_cast<chrono::microseconds>(time_end - time_start);
    cout << "Done [" << time_diff.count() << " microseconds]" << endl;
}

void TPP::comparePhonenumber(Ciphertext* input, int id){
    ifstream file_obj;
    Ciphertext data;
    file_obj.open("userData/"+to_string(id)+"_demo.data", ios::in);
    data.load(*context, file_obj);
    // evaluator->sub_inplace(*input, user->enc_phonenumber);
    chrono::high_resolution_clock::time_point time_start, time_end;
    chrono::microseconds time_diff;
    time_start = chrono::high_resolution_clock::now();
    Ciphertext* empty = generateEmpty(456, 104);
    evaluator->multiply_inplace(*empty, data);
    evaluator->relinearize_inplace(*empty, rk);
    evaluator->sub_inplace(*input, *empty);
    evaluator->rotate_rows_inplace(*input, 456, gk);
    time_end = chrono::high_resolution_clock::now();
    time_diff = chrono::duration_cast<chrono::microseconds>(time_end - time_start);
    cout << "Done [" << time_diff.count() << " microseconds]" << endl;
}

void TPP::compareDOB(string input, int id, Ciphertext* output){

    ifstream file_obj;
    Ciphertext data;
    file_obj.open("userData/"+to_string(id)+"_demo.data", ios::in);
    data.load(*context, file_obj);

    chrono::high_resolution_clock::time_point time_start, time_end;
    chrono::microseconds time_diff;
    time_start = chrono::high_resolution_clock::now();
    int temp = stoi(input);
    int year = temp/1000;
    int day = temp%1000;
    
    vector<uint64_t> out1(encoder->slot_count(), 0ULL);
    vector<uint64_t> out2(encoder->slot_count(), 0ULL);
    for (int i=0; i<year; i++){
        out1[i] = 1ULL;
    }
    for (int i = 0; i < 400; i++){
        out2[i] = size_t(day);
    }
    // for (int i = 0; i < 800 ; i++){
    //     cout << out2[i] << " ";
    // }
    cout << endl;
    Plaintext pout1, pout2;
    Ciphertext *enc_out1 = new Ciphertext;
    Ciphertext *enc_out2 = new Ciphertext;
    encoder->encode(out1, pout1);
    encoder->encode(out2, pout2);
    encryptor->encrypt(pout1, *enc_out1);
    encryptor->encrypt(pout2, *enc_out2);

    // Enc_out1 is the input DoB year and enc_out2 is the input DoB day. The first 400 bits is the year field.
    // Now we need to extract this info from the demographic data vector for comparison.
    // The algorithm: 
        // 1: Multiply the demo vector with a vector having 1's from index 800 to 1200, and 0 everywhere else. Lets call this v1
        // 2: Multiply the demo vector with a vector having 1's from index 1200 to 1600, and 0 everywhere else. Lets call this v2
        // 3: Left shift v1 800 times to obtain c1.
        // 4: Left shift v2 1200 times to obtain c2.
        // 5: Define vector x1 = v1 XOR enc_out1
        // 6: Define x2 = enc_out2 - v2
        // 7: Define ans1 = v1 AND x1
        // 8: Define ans2 = x2 AND NOT(x1)
        // 9: Right shift ans2 400 places
        // 10: Add ans1 + ans2. This is the final output.

    Ciphertext* empty1 = generateEmpty(800, 400);
    Ciphertext* empty2 = generateEmpty(1200, 400);


    // Defining v1, v2
    Ciphertext v1;
    Ciphertext v2;
    evaluator->multiply(data, *empty1, v1);
    evaluator->multiply(data, *empty2, v2);
    evaluator->relinearize_inplace(v1, rk);
    evaluator->relinearize_inplace(v2, rk);

    // Rotating the rows
    evaluator->rotate_rows_inplace(v1, 800, gk);
    evaluator->rotate_rows_inplace(v2, 1200, gk);

    // Defining x1, x2
    Ciphertext* x1 = new Ciphertext();
    Ciphertext* x2 = new Ciphertext();
    // output = XOR(&v1, enc_out1);
    XOR(&v1, enc_out1, x1);
    evaluator->sub(*enc_out2, v2, *x2);

    // Defining ans1 and ans2
    Ciphertext* ans1 = new Ciphertext();
    Ciphertext* ans2 = new Ciphertext();
    Ciphertext* intermediate = new Ciphertext();
    AND(&v1, x1, ans1);
    NOT(x1, intermediate);
    AND(intermediate, x2, ans2);
    evaluator->rotate_rows_inplace(*ans2, -400, gk);
    evaluator->add(*ans1, *ans2, *output);

    time_end = chrono::high_resolution_clock::now();
    time_diff = chrono::duration_cast<chrono::microseconds>(time_end - time_start);
    cout << "Done [" << time_diff.count() << " microseconds]" << endl;
}

// Biometric data comparison algorithm
// 1: data = data - input
// 2: data = data * data
// 3: for i in range(640):
//      eucledian_distance = eucledian_distance + data
//      data = leftshift(data, 1)
// 4: temp = enc(<1,0,0,0,...,0>)
// 5: distance = temp * distance
// 6: v1 = enc(<0,1,2,3,...,3000,0,0,...,0>)
// 7: for i in range(3000):
//      v2 = v2 + distance
//      distance = rightshift(distance, 1)
// 8: return v1 - v2


// Old rotate-and-add
void rotate_and_add_old(Ciphertext* input, int rotations, Ciphertext* output, Evaluator* evaluator, GaloisKeys* gk, int rotation){
    for(int i = 0; i < rotations; i++){
        evaluator->add_inplace(*output, *input);
        evaluator->rotate_rows_inplace(*input, rotation, *gk);
    }
}

// New rotate-and-add
void rotate_and_add(Ciphertext* input, int rotations, Ciphertext* output, Evaluator* evaluator, GaloisKeys* gk, RelinKeys* rk, int type, Ciphertext* temp, Ciphertext* temp2){
    if (type == -1){
        evaluator->add_inplace(*output, *input);
        int exp_count = 1;
        // Ciphertext* temp = generateEmpty(0, 0);

        while(exp_count < rotations){
            evaluator->rotate_rows(*output, exp_count*-1, *gk, *temp);
            evaluator->add_inplace(*output, *temp);
            exp_count = exp_count * 2;
        }
    }
    // Hardcoded for now with 184. Will generalise it later.
    else if (type == 0){
        evaluator->add_inplace(*output, *input);
        int exp_count = 1;
        // Ciphertext* temp = generateEmpty(0, 0);

        while(exp_count < 128){
            evaluator->rotate_rows(*output, exp_count*-1, *gk, *temp);
            evaluator->add_inplace(*output, *temp);
            exp_count = exp_count * 2;
        }

        // Ciphertext* temp2 = generateEmpty(0, 56);
        evaluator->multiply_inplace(*temp2, *output);
        evaluator->relinearize_inplace(*temp2, *rk);
        evaluator->rotate_rows_inplace(*temp2, -128, *gk);
        evaluator->add_inplace(*output, *temp2);
    }
}

void TPP::compareBiometric(Ciphertext* input, int id, Ciphertext* output){
    ifstream file_obj;
    Ciphertext data;
    file_obj.open("userData/"+to_string(id)+"_biometric.data", ios::in);
    data.load(*context, file_obj);
    // output = &data;
    
    chrono::high_resolution_clock::time_point time_start, time_end;
    chrono::microseconds time_diff;
    time_start = chrono::high_resolution_clock::now();
    // Step 1: Calculating Euclidean distance
    evaluator->sub_inplace(data, *input);
    evaluator->square_inplace(data);
    evaluator->relinearize_inplace(data, rk);

    // Creating data copies for threads
    Ciphertext* data_1 = generateEmpty(0, 0);
    Ciphertext* data_2 = generateEmpty(0, 0);
    Ciphertext* data_3 = generateEmpty(0, 0);
    Ciphertext* data_4 = generateEmpty(0, 0);
    Ciphertext* data_5 = generateEmpty(0, 0);
    Ciphertext* data_6 = generateEmpty(0, 0);
    Ciphertext* data_7 = generateEmpty(0, 0);
    Ciphertext* data_8 = generateEmpty(0, 0);
    Ciphertext* data_9 = generateEmpty(0, 0);
    Ciphertext* data_10 = generateEmpty(0, 0);
    Ciphertext* data_11 = generateEmpty(0, 0);
    Ciphertext* data_12 = generateEmpty(0, 0);
    Ciphertext* data_13 = generateEmpty(0, 0);
    Ciphertext* data_14 = generateEmpty(0, 0);
    Ciphertext* data_15 = generateEmpty(0, 0);
    evaluator->add_inplace(*data_1, data);
    evaluator->add_inplace(*data_2, data);
    evaluator->add_inplace(*data_3, data);
    evaluator->add_inplace(*data_4, data);
    evaluator->add_inplace(*data_5, data);
    evaluator->add_inplace(*data_6, data);
    evaluator->add_inplace(*data_7, data);
    evaluator->add_inplace(*data_8, data);
    evaluator->add_inplace(*data_9, data);
    evaluator->add_inplace(*data_10, data);
    evaluator->add_inplace(*data_11, data);
    evaluator->add_inplace(*data_12, data);
    evaluator->add_inplace(*data_13, data);
    evaluator->add_inplace(*data_14, data);
    evaluator->add_inplace(*data_15, data);

    Ciphertext* euc_dist1 = generateEmpty(0, 0);
    Ciphertext* euc_dist2 = generateEmpty(0, 0);
    Ciphertext* euc_dist3 = generateEmpty(0, 0);
    Ciphertext* euc_dist4 = generateEmpty(0, 0);
    Ciphertext* euc_dist5 = generateEmpty(0, 0);
    Ciphertext* euc_dist6 = generateEmpty(0, 0);
    Ciphertext* euc_dist7 = generateEmpty(0, 0);
    Ciphertext* euc_dist8 = generateEmpty(0, 0);
    Ciphertext* euc_dist9 = generateEmpty(0, 0);
    Ciphertext* euc_dist10 = generateEmpty(0, 0);
    Ciphertext* euc_dist11 = generateEmpty(0, 0);
    Ciphertext* euc_dist12 = generateEmpty(0, 0);
    Ciphertext* euc_dist13 = generateEmpty(0, 0);
    Ciphertext* euc_dist14 = generateEmpty(0, 0);
    Ciphertext* euc_dist15 = generateEmpty(0, 0);
    Ciphertext* euc_dist16 = generateEmpty(0, 0);

    // Initialising 2 threads: each doing 320 rotations.
    thread t1(rotate_and_add_old, &data, 40, euc_dist1, evaluator, &gk, 1);
    evaluator->rotate_rows_inplace(*data_1, 40, gk);
    thread t2(rotate_and_add_old, data_1, 160, euc_dist2, evaluator, &gk, 1);
    evaluator->rotate_rows_inplace(*data_2, 80, gk);
    thread t3(rotate_and_add_old, data_2, 40, euc_dist3, evaluator, &gk, 1);
    evaluator->rotate_rows_inplace(*data_3, 120, gk);
    thread t4(rotate_and_add_old, data_3, 40, euc_dist4, evaluator, &gk, 1);
    evaluator->rotate_rows_inplace(*data_4, 160, gk);
    thread t5(rotate_and_add_old, data_4, 40, euc_dist5, evaluator, &gk, 1);
    evaluator->rotate_rows_inplace(*data_5, 200, gk);
    thread t6(rotate_and_add_old, data_5, 40, euc_dist6, evaluator, &gk, 1);
    evaluator->rotate_rows_inplace(*data_6, 240, gk);
    thread t7(rotate_and_add_old, data_6, 40, euc_dist7, evaluator, &gk, 1);
    evaluator->rotate_rows_inplace(*data_7, 280, gk);
    thread t8(rotate_and_add_old, data_7, 40, euc_dist8, evaluator, &gk, 1);
    evaluator->rotate_rows_inplace(*data_8, 320, gk);
    thread t9(rotate_and_add_old, data_8, 40, euc_dist9, evaluator, &gk, 1);
    evaluator->rotate_rows_inplace(*data_9, 360, gk);
    thread t10(rotate_and_add_old, data_9, 40, euc_dist10, evaluator, &gk, 1);
    evaluator->rotate_rows_inplace(*data_10, 400, gk);
    thread t11(rotate_and_add_old, data_10, 40, euc_dist11, evaluator, &gk, 1);
    evaluator->rotate_rows_inplace(*data_11, 440, gk);
    thread t12(rotate_and_add_old, data_11, 40, euc_dist12, evaluator, &gk, 1);
    evaluator->rotate_rows_inplace(*data_12, 480, gk);
    thread t13(rotate_and_add_old, data_12, 40, euc_dist13, evaluator, &gk, 1);
    evaluator->rotate_rows_inplace(*data_13, 520, gk);
    thread t14(rotate_and_add_old, data_13, 40, euc_dist14, evaluator, &gk, 1);
    evaluator->rotate_rows_inplace(*data_14, 560, gk);
    thread t15(rotate_and_add_old, data_14, 40, euc_dist15, evaluator, &gk, 1);
    evaluator->rotate_rows_inplace(*data_15, 600, gk);
    thread t16(rotate_and_add_old, data_15, 40, euc_dist16, evaluator, &gk, 1);


    // Syncing the threads
    t1.join();
    t2.join();
    t3.join();
    t4.join();
    t5.join();
    t6.join();
    t7.join();
    t8.join();
    t9.join();
    t10.join();
    t11.join();
    t12.join();
    t13.join();
    t14.join();
    t15.join();
    t16.join();
    Ciphertext* euc_dist = generateEmpty(0, 0);
    evaluator->add(*euc_dist, *euc_dist1, *euc_dist2);
    evaluator->add_inplace(*euc_dist, *euc_dist3);
    evaluator->add_inplace(*euc_dist, *euc_dist4);
    evaluator->add_inplace(*euc_dist, *euc_dist5);
    evaluator->add_inplace(*euc_dist, *euc_dist6);
    evaluator->add_inplace(*euc_dist, *euc_dist7);
    evaluator->add_inplace(*euc_dist, *euc_dist8);
    evaluator->add_inplace(*euc_dist, *euc_dist9);
    evaluator->add_inplace(*euc_dist, *euc_dist10);
    evaluator->add_inplace(*euc_dist, *euc_dist11);
    evaluator->add_inplace(*euc_dist, *euc_dist12);
    evaluator->add_inplace(*euc_dist, *euc_dist13);
    evaluator->add_inplace(*euc_dist, *euc_dist14);
    evaluator->add_inplace(*euc_dist, *euc_dist15);
    evaluator->add_inplace(*euc_dist, *euc_dist16);

    // for(int i = 0; i < 640; i++){
    //     // cout << "*";
    //     evaluator->add_inplace(*euc_dist, data);
    //     evaluator->rotate_rows_inplace(data, 1, gk);
    // }

    // Step 2: Isolate distance at first index position
    Ciphertext* temp = generateEmpty(0, 1);
    evaluator->multiply_inplace(*euc_dist, *temp);
    evaluator->relinearize_inplace(*euc_dist, rk);

    // Step 3: Evaluating final vector
    vector<uint64_t> out(encoder->slot_count(), 0ULL);
    for (int i = 0; i < 3000; i++){
        out[i] = size_t(i);
    }
    Plaintext pout;
    Ciphertext v1;
    encoder->encode(out, pout);
    encryptor->encrypt(pout, v1);

    // Enabling multi threading
    // Lines 509 to 660 have been commented. Uncomment them.
    // Ciphertext* distance1 = generateEmpty(0, 0);
    // Ciphertext* distance2 = generateEmpty(0, 0);
    // Ciphertext* distance3 = generateEmpty(0, 0);
    // Ciphertext* distance4 = generateEmpty(0, 0);
    // Ciphertext* distance5 = generateEmpty(0, 0);
    // Ciphertext* distance6 = generateEmpty(0, 0);
    // Ciphertext* distance7 = generateEmpty(0, 0);
    // Ciphertext* distance8 = generateEmpty(0, 0);
    // Ciphertext* distance9 = generateEmpty(0, 0);
    // Ciphertext* distance10 = generateEmpty(0, 0);
    // Ciphertext* distance11 = generateEmpty(0, 0);
    // Ciphertext* distance12 = generateEmpty(0, 0);
    // Ciphertext* distance13 = generateEmpty(0, 0);
    // Ciphertext* distance14 = generateEmpty(0, 0);
    // Ciphertext* distance15 = generateEmpty(0, 0);
    // Ciphertext* distance16 = generateEmpty(0, 0);
    // Ciphertext* distance17 = generateEmpty(0, 0);
    // Ciphertext* distance18 = generateEmpty(0, 0);
    // Ciphertext* distance19 = generateEmpty(0, 0);
    // Ciphertext* distance20 = generateEmpty(0, 0);
    // evaluator->add_inplace(*distance1, *euc_dist);
    // evaluator->add_inplace(*distance2, *euc_dist);
    // evaluator->add_inplace(*distance3, *euc_dist);
    // evaluator->add_inplace(*distance4, *euc_dist);
    // evaluator->add_inplace(*distance5, *euc_dist);
    // evaluator->add_inplace(*distance6, *euc_dist);
    // evaluator->add_inplace(*distance7, *euc_dist);
    // evaluator->add_inplace(*distance8, *euc_dist);
    // evaluator->add_inplace(*distance9, *euc_dist);
    // evaluator->add_inplace(*distance10, *euc_dist);
    // evaluator->add_inplace(*distance11, *euc_dist);
    // evaluator->add_inplace(*distance12, *euc_dist);
    // evaluator->add_inplace(*distance15, *euc_dist);
    // evaluator->add_inplace(*distance14, *euc_dist);
    // evaluator->add_inplace(*distance15, *euc_dist);
    // evaluator->add_inplace(*distance16, *euc_dist);
    // evaluator->add_inplace(*distance17, *euc_dist);
    // evaluator->add_inplace(*distance18, *euc_dist);
    // evaluator->add_inplace(*distance19, *euc_dist);
    // evaluator->add_inplace(*distance20, *euc_dist);


    // Ciphertext* out1 = generateEmpty(0, 0);
    // Ciphertext* out2 = generateEmpty(0, 0);
    // Ciphertext* out3 = generateEmpty(0, 0);
    // Ciphertext* out4 = generateEmpty(0, 0);
    // Ciphertext* out5 = generateEmpty(0, 0);
    // Ciphertext* out6 = generateEmpty(0, 0);
    // Ciphertext* out7 = generateEmpty(0, 0);
    // Ciphertext* out8 = generateEmpty(0, 0);
    // Ciphertext* out9 = generateEmpty(0, 0);
    // Ciphertext* out10 = generateEmpty(0, 0);
    // Ciphertext* out11 = generateEmpty(0, 0);
    // Ciphertext* out12 = generateEmpty(0, 0);
    // Ciphertext* out13 = generateEmpty(0, 0);
    // Ciphertext* out14 = generateEmpty(0, 0);
    // Ciphertext* out15 = generateEmpty(0, 0);
    // Ciphertext* out16 = generateEmpty(0, 0);
    // Ciphertext* out17 = generateEmpty(0, 0);
    // Ciphertext* out18 = generateEmpty(0, 0);
    // Ciphertext* out19 = generateEmpty(0, 0);
    // Ciphertext* out20 = generateEmpty(0, 0);

    // thread k1(rotate_and_add, distance1, 150, out1, evaluator, &gk, -1);
    // evaluator->rotate_rows_inplace(*distance2, -150, gk);
    // thread k2(rotate_and_add, distance2, 150, out2, evaluator, &gk, -1);
    // evaluator->rotate_rows_inplace(*distance3, -300, gk);
    // thread k3(rotate_and_add, distance3, 150, out3, evaluator, &gk, -1);
    // evaluator->rotate_rows_inplace(*distance4, -450, gk);
    // thread k4(rotate_and_add, distance4, 150, out4, evaluator, &gk, -1);
    // evaluator->rotate_rows_inplace(*distance5, -600, gk);
    // thread k5(rotate_and_add, distance5, 150, out5, evaluator, &gk, -1);
    // evaluator->rotate_rows_inplace(*distance6, -750, gk);
    // thread k6(rotate_and_add, distance6, 150, out6, evaluator, &gk, -1);
    // evaluator->rotate_rows_inplace(*distance7, -900, gk);
    // thread k7(rotate_and_add, distance7, 150, out7, evaluator, &gk, -1);
    // evaluator->rotate_rows_inplace(*distance8, -1050, gk);
    // thread k8(rotate_and_add, distance8, 150, out8, evaluator, &gk, -1);
    // evaluator->rotate_rows_inplace(*distance9, -1200, gk);
    // thread k9(rotate_and_add, distance9, 150, out9, evaluator, &gk, -1);
    // evaluator->rotate_rows_inplace(*distance10, -1350, gk);
    // thread k10(rotate_and_add, distance10, 150, out10, evaluator, &gk, -1);
    // evaluator->rotate_rows_inplace(*distance11, -1500, gk);
    // thread k11(rotate_and_add, distance11, 150, out11, evaluator, &gk, -1);
    // evaluator->rotate_rows_inplace(*distance12, -1650, gk);
    // thread k12(rotate_and_add, distance12, 150, out12, evaluator, &gk, -1);
    // evaluator->rotate_rows_inplace(*distance13, -1800, gk);
    // thread k13(rotate_and_add, distance13, 150, out13, evaluator, &gk, -1);
    // evaluator->rotate_rows_inplace(*distance14, -1950, gk);
    // thread k14(rotate_and_add, distance14, 150, out14, evaluator, &gk, -1);
    // evaluator->rotate_rows_inplace(*distance15, -2100, gk);
    // thread k15(rotate_and_add, distance15, 150, out15, evaluator, &gk, -1);
    // evaluator->rotate_rows_inplace(*distance16, -2250, gk);
    // thread k16(rotate_and_add, distance16, 150, out16, evaluator, &gk, -1);
    // evaluator->rotate_rows_inplace(*distance17, -2400, gk);
    // thread k17(rotate_and_add, distance17, 150, out17, evaluator, &gk, -1);
    // evaluator->rotate_rows_inplace(*distance18, -2550, gk);
    // thread k18(rotate_and_add, distance18, 150, out18, evaluator, &gk, -1);
    // evaluator->rotate_rows_inplace(*distance19, -2700, gk);
    // thread k19(rotate_and_add, distance19, 150, out19, evaluator, &gk, -1);
    // evaluator->rotate_rows_inplace(*distance20, -2850, gk);
    // thread k20(rotate_and_add, distance20, 150, out20, evaluator, &gk, -1);






    // // for(int i = 0; i < 3000; i++){
    // //     evaluator->add_inplace(*v2, *euc_dist);
    // //     evaluator->rotate_rows_inplace(*euc_dist, -1, gk);
    // // }
    // k1.join();
    // k2.join();
    // k3.join();
    // k4.join();
    // k5.join();
    // k6.join();
    // k7.join();
    // k8.join();
    // k9.join();
    // k10.join();
    // k11.join();
    // k12.join();
    // k13.join();
    // k14.join();
    // k15.join();
    // k16.join();
    // k17.join();
    // k18.join();
    // k19.join();
    // k20.join();
    // Ciphertext* v2 = generateEmpty(0, 0);
    // evaluator->add(*v2, *out1, *out2);
    // evaluator->add_inplace(*v2, *out3);
    // evaluator->add_inplace(*v2, *out4);
    // evaluator->add_inplace(*v2, *out5);
    // evaluator->add_inplace(*v2, *out6);
    // evaluator->add_inplace(*v2, *out7);
    // evaluator->add_inplace(*v2, *out8);
    // evaluator->add_inplace(*v2, *out9);
    // evaluator->add_inplace(*v2, *out10);
    // evaluator->add_inplace(*v2, *out11);
    // evaluator->add_inplace(*v2, *out12);
    // evaluator->add_inplace(*v2, *out13);
    // evaluator->add_inplace(*v2, *out14);
    // evaluator->add_inplace(*v2, *out15);
    // evaluator->add_inplace(*v2, *out16);
    // evaluator->add_inplace(*v2, *out17);
    // evaluator->add_inplace(*v2, *out18);
    // evaluator->add_inplace(*v2, *out19);
    // evaluator->add_inplace(*v2, *out20);

    // Beginning of new code: Single threading




    // Beginning of new code - multi threading
    Ciphertext* distance1 = generateEmpty(0, 0);
    Ciphertext* distance2 = generateEmpty(0, 0);
    Ciphertext* distance3 = generateEmpty(0, 0);
    Ciphertext* distance4 = generateEmpty(0, 0);
    Ciphertext* distance5 = generateEmpty(0, 0);
    Ciphertext* distance6 = generateEmpty(0, 0);
    Ciphertext* distance7 = generateEmpty(0, 0);
    Ciphertext* distance8 = generateEmpty(0, 0);

    evaluator->add_inplace(*distance1, *euc_dist);
    evaluator->add_inplace(*distance2, *euc_dist);
    evaluator->add_inplace(*distance3, *euc_dist);
    evaluator->add_inplace(*distance4, *euc_dist);
    evaluator->add_inplace(*distance5, *euc_dist);
    evaluator->add_inplace(*distance6, *euc_dist);
    evaluator->add_inplace(*distance7, *euc_dist);
    evaluator->add_inplace(*distance8, *euc_dist);

    Ciphertext* out1 = generateEmpty(0, 0);
    Ciphertext* out2 = generateEmpty(0, 0);
    Ciphertext* out3 = generateEmpty(0, 0);
    Ciphertext* out4 = generateEmpty(0, 0);
    Ciphertext* out5 = generateEmpty(0, 0);
    Ciphertext* out6 = generateEmpty(0, 0);
    Ciphertext* out7 = generateEmpty(0, 0);
    Ciphertext* out8 = generateEmpty(0, 0);

    Ciphertext* temp1 = generateEmpty(0, 0);
    Ciphertext* temp2 = generateEmpty(0, 0);
    Ciphertext* temp3 = generateEmpty(0, 0);
    Ciphertext* temp4 = generateEmpty(0, 0);
    Ciphertext* temp5 = generateEmpty(0, 0);
    Ciphertext* temp6 = generateEmpty(0, 0);
    Ciphertext* temp7 = generateEmpty(0, 0);
    Ciphertext* temp8 = generateEmpty(0, 0);
    Ciphertext* temp9 = generateEmpty(0, 56);

    thread k1(rotate_and_add, distance1, 512, out1, evaluator, &gk, &rk, -1, temp1, temp9);
    evaluator->rotate_rows_inplace(*distance2, -512, gk);
    thread k2(rotate_and_add, distance2, 512, out2, evaluator, &gk, &rk, -1, temp2, temp9);
    evaluator->rotate_rows_inplace(*distance3, -1024, gk);
    thread k3(rotate_and_add, distance3, 512, out3, evaluator, &gk, &rk, -1, temp3, temp9);
    evaluator->rotate_rows_inplace(*distance4, -1536, gk);
    thread k4(rotate_and_add, distance4, 512, out4, evaluator, &gk, &rk, -1, temp4, temp9);
    evaluator->rotate_rows_inplace(*distance5, -2048, gk);
    thread k5(rotate_and_add, distance5, 256, out5, evaluator, &gk, &rk, -1, temp5, temp9);
    evaluator->rotate_rows_inplace(*distance6, -2304, gk);
    thread k6(rotate_and_add, distance6, 256, out6, evaluator, &gk, &rk, -1, temp6, temp9);
    evaluator->rotate_rows_inplace(*distance7, -2560, gk);
    thread k7(rotate_and_add, distance7, 256, out7, evaluator, &gk, &rk, -1, temp7, temp9);
    evaluator->rotate_rows_inplace(*distance8, -2816, gk);
    thread k8(rotate_and_add, distance8, 184, out8, evaluator, &gk, &rk, 0, temp8, temp9);

    k1.join();
    k2.join();
    k3.join();
    k4.join();
    k5.join();
    k6.join();
    k7.join();
    k8.join();

    Ciphertext* v2 = generateEmpty(0, 0);
    evaluator->add(*v2, *out1, *out2);
    evaluator->add_inplace(*v2, *out3);
    evaluator->add_inplace(*v2, *out4);
    evaluator->add_inplace(*v2, *out5);
    evaluator->add_inplace(*v2, *out6);
    evaluator->add_inplace(*v2, *out7);
    evaluator->add_inplace(*v2, *out8);


    // Step 4: Final output
    evaluator->sub_inplace(v1, *v2);
    evaluator->rotate_rows(v1, -400, gk, *output);
    time_end = chrono::high_resolution_clock::now();
    time_diff = chrono::duration_cast<chrono::microseconds>(time_end - time_start);
    cout << "Done [" << time_diff.count() << " microseconds]" << endl;
}




void TPP::compareBiometricSingle(Ciphertext* input, int id, Ciphertext* output){
    ifstream file_obj;
    Ciphertext data;
    file_obj.open("userData/"+to_string(id)+"_biometric.data", ios::in);
    data.load(*context, file_obj);
    // output = &data;
    
    chrono::high_resolution_clock::time_point time_start, time_end;
    chrono::microseconds time_diff;
    time_start = chrono::high_resolution_clock::now();
    // Step 1: Calculating Euclidean distance
    evaluator->sub_inplace(data, *input);
    evaluator->square_inplace(data);
    evaluator->relinearize_inplace(data, rk);

    Ciphertext* euc_dist = generateEmpty(0, 0);
    evaluator->add_inplace(*euc_dist, data);
    int shift = 320;
    for(int i = 0; i <7; i++){
        Ciphertext* temp = generateEmpty(0, 0);
        evaluator->add_inplace(*temp, *euc_dist);
        evaluator->rotate_rows_inplace(*temp, shift, gk);
        evaluator->add_inplace(*euc_dist, *temp);
        shift = shift / 2;
    }

    Ciphertext* temp = generateEmpty(0, 0);
    evaluator->add_inplace(*temp, *euc_dist);
    for(int i = 0; i < 4; i++){
        evaluator->rotate_rows_inplace(*temp, 1, gk);
        evaluator->add_inplace(*euc_dist, *temp);
    }

    Ciphertext* temp2 = generateEmpty(0, 1);
    evaluator->multiply_inplace(*euc_dist, *temp2);
    evaluator->relinearize_inplace(*euc_dist, rk);


    // Step 3: Evaluating final vector
    vector<uint64_t> out(encoder->slot_count(), 0ULL);
    for (int i = 0; i < 3000; i++){
        out[i] = size_t(i);
    }
    Plaintext pout;
    Ciphertext v1;
    encoder->encode(out, pout);
    encryptor->encrypt(pout, v1);

    int exponent = -1;
    for(int i = 0; i < 12; i++){
        Ciphertext* t = generateEmpty(0, 0);
        evaluator->add_inplace(*t, *euc_dist);
        evaluator->rotate_rows_inplace(*t, exponent, gk);
        exponent = exponent * 2;
        evaluator->add_inplace(*euc_dist, *t);
    }

    Ciphertext* t = generateEmpty(0, 3000);
    evaluator->multiply_inplace(*euc_dist, *t);
    evaluator->relinearize_inplace(*euc_dist, rk);



    // Step 4: Final output
    evaluator->sub_inplace(v1, *euc_dist);
    evaluator->rotate_rows(v1, -400, gk, *output);
    time_end = chrono::high_resolution_clock::now();
    time_diff = chrono::duration_cast<chrono::microseconds>(time_end - time_start);
    cout << "Done [" << time_diff.count() << " microseconds]" << endl;
}
