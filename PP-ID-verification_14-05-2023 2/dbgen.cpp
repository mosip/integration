/**
 * Script for generating and storing the user data and keys
 *
 **/

#include "dbgen.h"

using namespace std;
using namespace seal;


// void writeSecretKey(SecretKey *sk_pointer){
//     SecretKey sk = *sk_pointer;
//     ofstream file_obj("secretkey.txt", ios::trunc);
//     file_obj.write((char*)&sk, sizeof(sk));
//     file_obj.close();
// }

// void writePublicKey(PublicKey *pk_pointer){
//     PublicKey pk = *pk_pointer;
//     ofstream file_obj("publickey.txt", ios::trunc);
//     file_obj.write((char*)&pk, sizeof(pk));
//     file_obj.close();
// }

// void writeEncParms(EncryptionParameters *c){
//    EncryptionParameters pk = *c;
//     ofstream file_obj("encryptionparameters.txt", ios::trunc|ios::binary);
//     file_obj.write((char*)&pk, sizeof(pk));
//     file_obj.close();
// }

void writeUser(EncryptedUser* e){
    ofstream file;
    string id = to_string(e->ID);
    id = "userData/" + id;
    string f1 = id + "_demo.data";
    string f2 = id + "_biometric.data";

    file.open(f1, ios::binary);
    e->enc_demographic.save(file);
    file.close();
    file.clear();

    file.open(f2, ios::binary);
    e->enc_biometric_template.save(file);
    file.close();
    file.clear();
}

// void writeFirstUser(EncryptedUser* e_pointer){
//     EncryptedUser user = *e_pointer;
//     ofstream file_obj("data.txt", ios::trunc);
//     file_obj.write((char*)&user, sizeof(user));
//     file_obj.close();
// }

// void writeNewUser(EncryptedUser* e_pointer){
//     EncryptedUser user = *e_pointer;
//     ofstream file_obj("data.txt", ios::app);
//     file_obj.write((char*)&user, sizeof(user));
//     file_obj.close();
// }


void generateDatabase(){
    EncryptionParameters parms(scheme_type::bfv);
    size_t poly_modulus_degree = 8192;
    parms.set_poly_modulus_degree(poly_modulus_degree);
    parms.set_coeff_modulus(CoeffModulus::BFVDefault(poly_modulus_degree));
    
    parms.set_plain_modulus(PlainModulus::Batching(poly_modulus_degree, 22));

    // Checking the validity of the set parameters
    SEALContext context(parms);
    // print_parameters(context);
    // cout << endl;

    // Generating the keys
    KeyGenerator keygen(context);
    SecretKey secret_key = keygen.secret_key();
    PublicKey public_key;
    keygen.create_public_key(public_key);
    RelinKeys relin_keys;
    keygen.create_relin_keys(relin_keys);
    GaloisKeys galois_keys;
    keygen.create_galois_keys(galois_keys);
    // RelinKeys relin_keys;
    // keygen.create_relin_keys(relin_keys);
    Encryptor encryptor(context, public_key);
    Evaluator evaluator(context);
    Decryptor decryptor(context, secret_key);

    // Write secretkey to file
    // writeSecretKey(&secret_key);
    // writePublicKey(&public_key);
    // writeEncParms(&parms);

    ofstream file_obj;
    file_obj.open("keys/publickey.pk", ios::binary);
    public_key.save(file_obj);
    file_obj.close();
    file_obj.clear();
    file_obj.open("keys/secretkey.sk", ios::binary);
    secret_key.save(file_obj);
    file_obj.close();
    file_obj.clear();
    file_obj.open("keys/relinkeys.rk", ios::binary);
    relin_keys.save(file_obj);
    file_obj.close();
    file_obj.clear();
    file_obj.open("keys/galoiskeys.gk", ios::binary);
    galois_keys.save(file_obj);
    file_obj.close();
    



    BatchEncoder batch_encoder(context);
    size_t slot_count = batch_encoder.slot_count();
    size_t row_size = slot_count / 2;
    cout << "Plaintext matrix row size: " << row_size << endl;

    string n1 = "Deep Inder Mohan";
    char s1 = 'M';
    string pin1 = "134112";
    string dob1 = "099096"; // Encoded as 99 years + 96 days from 1 jan 1900; This becomes 6th april 1999
    string pno1 = "+919877366693";
    string e1 = "mohan.deepinder";
    vector<int> bio1{108, 104, 113, 99, 106, 104, 93, 106, 106, 104, 102, 103, 104, 104, 107, 104, 117, 118, 103, 89, 76, 118, 88, 99, 116, 118, 107, 111, 113, 118, 115, 118, 118, 118, 110, 90, 78, 118, 88, 99, 116, 118, 109, 112, 116, 118, 116, 118, 114, 114, 112, 86, 73, 114, 83, 94, 113, 114, 100, 98, 104, 114, 115, 114, 117, 116, 113, 111, 86, 116, 100, 114, 116, 116, 115, 115, 113, 116, 116, 116, 88, 92, 102, 82, 91, 92, 98, 96, 95, 92, 103, 106, 109, 92, 88, 92, 110, 109, 100, 85, 84, 109, 84, 100, 108, 109, 108, 112, 115, 109, 110, 109, 112, 111, 97, 96, 77, 111, 87, 93, 109, 111, 108, 117, 115, 111, 111, 111, 94, 95, 92, 78, 70, 95, 78, 85, 96, 95, 103, 110, 107, 95, 103, 95, 115, 115, 113, 110, 92, 115, 92, 101, 113, 115, 116, 119, 118, 115, 119, 115, 76, 66, 106, 58, 60, 66, 109, 98, 85, 66, 94, 110, 106, 66, 93, 66, 90, 85, 93, 69, 58, 85, 73, 81, 85, 85, 61, 75, 79, 85, 87, 85, 101, 101, 96, 75, 69, 101, 81, 84, 99, 101, 83, 89, 81, 101, 85, 101, 103, 103, 108, 86, 72, 103, 79, 84, 101, 103, 71, 83, 79, 103, 81, 103, 120, 120, 122, 112, 107, 120, 99, 107, 119, 120, 117, 98, 102, 120, 115, 120, 85, 78, 100, 63, 67, 78, 102, 93, 85, 78, 94, 100, 60, 78, 61, 78, 50, 52, 47, 52, 50, 52, 42, 51, 49, 52, 58, 54, 52, 52, 59, 52, 42, 40, 60, 62, 39, 40, 33, 40, 39, 40, 51, 46, 44, 40, 40, 40, 53, 51, 78, 74, 68, 51, 39, 44, 50, 51, 42, 44, 46, 51, 44, 51, 111, 111, 115, 113, 101, 111, 83, 103, 111, 111, 114, 85, 77, 111, 103, 111, 116, 115, 100, 109, 91, 115, 107, 118, 117, 115, 105, 103, 116, 115, 106, 115, 30, 26, 22, 26, 24, 26, 34, 60, 46, 26, 65, 63, 55, 26, 70, 26, 112, 113, 79, 88, 78, 113, 87, 93, 111, 113, 74, 95, 104, 113, 111, 113, 114, 113, 88, 89, 78, 113, 84, 95, 112, 113, 87, 90, 95, 113, 112, 113, 110, 110, 119, 107, 92, 110, 87, 103, 109, 110, 111, 93, 102, 110, 109, 110, 57, 46, 98, 48, 76, 46, 95, 90, 71, 46, 98, 86, 82, 46, 49, 46, 26, 26, 35, 33, 33, 26, 59, 26, 26, 26, 45, 58, 31, 26, 26, 26, 35, 36, 37, 28, 41, 36, 45, 51, 39, 36, 45, 38, 33, 36, 37, 36, 52, 52, 44, 49, 49, 52, 48, 59, 53, 52, 53, 50, 50, 52, 60, 52, 118, 118, 118, 108, 103, 118, 91, 109, 118, 118, 112, 103, 97, 118, 115, 118, 100, 104, 84, 82, 97, 104, 74, 82, 97, 104, 86, 85, 90, 104, 89, 104, 31, 29, 32, 41, 43, 29, 35, 26, 29, 29, 43, 46, 36, 29, 43, 29, 58, 59, 45, 46, 45, 59, 46, 49, 57, 59, 40, 45, 41, 59, 51, 59, 34, 30, 42, 42, 41, 30, 39, 24, 30, 30, 27, 38, 26, 30, 28, 30, 88, 87, 102, 99, 87, 87, 83, 80, 88, 87, 93, 66, 76, 87, 94, 87, 116, 116, 88, 89, 91, 116, 90, 94, 110, 116, 104, 108, 108, 116, 103, 116, 97, 95, 92, 74, 61, 95, 77, 95, 92, 95, 80, 97, 88, 95, 99, 95, 111, 110, 114, 88, 70, 110, 86, 100, 109, 110, 89, 101, 107, 110, 101, 110, 119, 119, 115, 102, 87, 119, 93, 97, 117, 119, 92, 101, 106, 119, 111, 119, 122, 122, 118, 113, 105, 122, 110, 110, 122, 122, 114, 110, 121, 122, 122, 122};
    int id1 = 1;

    string n2 = "Srinivas Vivek";
    char s2 = 'M';
    string pin2 = "560100";
    string dob2 = "110123"; // Similar encoding to the above date
    string pno2 = "+910123456789";
    string e2 = "srinivas.vivek";
    vector<int> bio2{76, 74, 82, 58, 75, 74, 106, 85, 79, 74, 85, 96, 85, 74, 85, 74, 82, 80, 77, 62, 52, 80, 59, 75, 78, 80, 73, 60, 61, 80, 79, 80, 71, 66, 93, 52, 52, 66, 56, 58, 65, 66, 62, 55, 82, 66, 103, 66, 114, 114, 104, 92, 78, 114, 86, 96, 112, 114, 77, 95, 114, 114, 112, 114, 120, 120, 111, 110, 88, 120, 93, 104, 120, 120, 111, 115, 121, 120, 120, 120, 102, 100, 101, 92, 84, 100, 111, 101, 99, 100, 100, 82, 101, 100, 78, 100, 18, 17, 18, 20, 38, 17, 30, 17, 19, 17, 41, 27, 39, 17, 31, 17, 23, 20, 37, 39, 29, 20, 31, 38, 22, 20, 40, 67, 33, 20, 26, 20, 61, 61, 46, 47, 53, 61, 49, 51, 60, 61, 40, 58, 54, 61, 49, 61, 110, 111, 114, 107, 105, 111, 98, 103, 111, 111, 108, 105, 89, 111, 110, 111, 122, 122, 116, 106, 107, 122, 98, 100, 116, 122, 104, 111, 119, 122, 121, 122, 119, 119, 116, 91, 92, 119, 97, 105, 116, 119, 90, 106, 118, 119, 118, 119, 103, 102, 106, 77, 74, 102, 93, 87, 101, 102, 79, 102, 111, 102, 111, 102, 81, 83, 95, 66, 62, 83, 71, 92, 83, 83, 82, 95, 98, 83, 101, 83, 119, 119, 116, 107, 101, 119, 112, 114, 118, 119, 116, 104, 108, 119, 116, 119, 97, 93, 102, 84, 86, 93, 110, 106, 101, 93, 107, 107, 100, 93, 75, 93, 107, 106, 88, 81, 72, 106, 78, 86, 102, 106, 93, 99, 111, 106, 110, 106, 117, 117, 102, 88, 77, 117, 87, 95, 115, 117, 91, 105, 116, 117, 114, 117, 117, 117, 107, 91, 79, 117, 91, 97, 116, 117, 88, 101, 106, 117, 115, 117, 120, 120, 116, 110, 94, 120, 95, 111, 120, 120, 116, 107, 112, 120, 119, 120, 81, 85, 101, 88, 93, 85, 104, 87, 82, 85, 99, 107, 95, 85, 87, 85, 111, 110, 106, 88, 77, 110, 100, 94, 107, 110, 109, 111, 111, 110, 113, 110, 114, 114, 104, 101, 76, 114, 91, 97, 112, 114, 104, 118, 117, 114, 112, 114, 100, 102, 100, 83, 70, 102, 78, 95, 101, 102, 104, 113, 109, 102, 109, 102, 114, 114, 113, 103, 84, 114, 104, 96, 112, 114, 117, 120, 119, 114, 121, 114, 95, 92, 94, 71, 74, 92, 100, 104, 97, 92, 103, 90, 85, 92, 70, 92, 31, 31, 31, 25, 29, 31, 26, 40, 31, 31, 37, 27, 29, 31, 24, 31, 27, 26, 52, 29, 29, 26, 31, 22, 26, 26, 42, 23, 26, 26, 25, 26, 43, 41, 51, 35, 34, 41, 35, 42, 42, 41, 33, 36, 33, 41, 40, 41, 118, 118, 116, 115, 96, 118, 94, 103, 116, 118, 106, 92, 97, 118, 112, 118, 93, 99, 61, 72, 83, 99, 78, 84, 91, 99, 103, 102, 86, 99, 85, 99, 33, 33, 35, 35, 30, 33, 29, 39, 37, 33, 50, 84, 64, 33, 31, 33, 44, 45, 35, 38, 36, 45, 57, 45, 46, 45, 92, 94, 91, 45, 40, 45, 40, 39, 30, 40, 52, 39, 39, 56, 45, 39, 90, 91, 88, 39, 32, 39, 92, 94, 89, 78, 83, 94, 86, 76, 93, 94, 108, 111, 101, 94, 95, 94, 75, 70, 102, 72, 84, 70, 63, 71, 77, 70, 93, 62, 64, 70, 59, 70, 48, 49, 49, 38, 40, 49, 62, 41, 48, 49, 65, 43, 64, 49, 43, 49, 78, 77, 62, 58, 55, 77, 60, 64, 75, 77, 74, 77, 99, 77, 61, 77, 74, 74, 66, 65, 56, 74, 70, 67, 74, 74, 82, 93, 89, 74, 56, 74, 110, 109, 93, 91, 85, 109, 84, 91, 108, 109, 103, 111, 113, 109, 106, 109};
    int id2 = 2;


    User u1(n1, s1, pin1, dob1, pno1, e1, bio1);
    User u2(n2, s2, pin2, dob2, pno2, e2, bio2);



    EncryptedUser enc1(&u1, &batch_encoder, &public_key, &encryptor, &evaluator, id1);

    EncryptedUser enc2(&u2, &batch_encoder, &public_key, &encryptor, &evaluator, id2);


    // writing objects to file.
    writeUser(&enc1);    
    writeUser(&enc2);
    cout << "Database generated successfully!" << endl;
}





