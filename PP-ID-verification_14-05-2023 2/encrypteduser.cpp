/**
 * Class file for the EncryptedUser class
 *
 **/

#include "encrypteduser.h"

using namespace std;
using namespace seal;


EncryptedUser::EncryptedUser(User* user, BatchEncoder* be, PublicKey* pk, Encryptor* enc, Evaluator* eval, int id){

    batch_encoder = be;
    public_key = pk;
    encryptor = enc;
    evaluator = eval;
    ID = id;

    // Separate fields for demo data
    // vector<uint64_t> name(batch_encoder->slot_count(), 0ULL);
    // vector<uint64_t> sex(batch_encoder->slot_count(), 0ULL);
    // vector<uint64_t> pincode(batch_encoder->slot_count(), 0ULL);
    // vector<uint64_t> dateofbirth(batch_encoder->slot_count(), 0ULL);
    // vector<uint64_t> phonenumber(batch_encoder->slot_count(), 0ULL);
    // vector<uint64_t> email(batch_encoder->slot_count(), 0ULL);
    // vector<uint64_t> biometric_template(batch_encoder->slot_count(), 0ULL);

    // Combining demo data
    vector<uint64_t> demographic(batch_encoder->slot_count()/2, 0ULL);
    // vector<uint64_t> dateofbirth(batch_encoder->slot_count()/2, 0ULL);
    vector<uint64_t> biometric_template(batch_encoder->slot_count()/2, 0ULL);


    string tname = user->getName();
    string temail = user->getEmail();
    string tdob = user->getDOB();
    int temp_dob = stoi(tdob);
    int tdob_year = temp_dob/1000;
    int tdob_day = temp_dob%1000;
    string tpno = user->getPno();
    string tpincode = user->getPincode();
    char tsex = user->getSex();
    vector<int> tbio = user->getTemplate();
    // Plaintext pname, pemail, pdob, ppno, ppincode, psex, pbio;
    Plaintext pdemo, pbio;

    // For the plaintext vector for demographic data:-
    // [0, 399] -> Name
    // [400, 407] -> Sex
    // [408, 455] -> Pincode
    // [456, 559] -> Phone number
    // [560, 799] -> Email ID
    // [800, 1199] -> DoB years from pivot
    // [1200, 1599] -> DoB days from pivot
    // Everything is still encrypted as binary. Will give us a 
    // lot more flexibility down the line.

    // For the biometric template vector
    // Template size = 640
    // Each vector index is 1 byte
    // Euclidean distance for comparison
    // Threshold value set at 3000 <To be researched later with more data>

    for(int i = 0; i < 50; i++){
        int temp = int(tname.at(i));
        for (int j = 0; j < 8; j++){
            int index = (8*(i+1)) - (j+1);
            // name[index] = size_t(temp%2);
            demographic[index] = size_t(temp%2);
            temp = temp/2;
        }
    }
    

    // batch_encoder->encode(name, pname);
    // encryptor->encrypt(pname, enc_name);
    int sex = int(tsex);
    for (int i = 0; i < 7; i++){
        demographic[407-i] = size_t(sex%2);
        sex = sex/2;
    }
    // batch_encoder->encode(sex, psex);
    // encryptor->encrypt(psex, enc_sex);

    for(int i = 0; i < 6; i++){
        int temp = tpincode[i];
        for (int j = 0; j < 8; j++){
            int index = (8*(i+1)) - (j+1);
            // pincode[index] = size_t(temp%2);
            demographic[408+index] = size_t(temp%2);
            temp = temp/2;
        }
    }
    // batch_encoder->encode(pincode, ppincode);
    // encryptor->encrypt(ppincode, enc_pincode);

    for(int i = 0; i < 13; i++){
        // phonenumber[i] = size_t(tpno[i]);
        int temp = tpno[i];
        for (int j = 0; j < 8; j++){
            int index = (8*(i+1)) - (j+1);
            // phonenumber[index] = size_t(temp%2);
            demographic[456+index] = size_t(temp%2);
            temp = temp/2;
        }
    }
    // batch_encoder->encode(phonenumber, ppno);
    // encryptor->encrypt(ppno, enc_phonenumber);

    for(int i = 0; i < 30; i++){
        // email[i] = size_t(temail[i]);
        int temp = temail[i];
        for (int j = 0; j < 8; j++){
            int index = (8*(i+1)) - (j+1);
            // email[index] = size_t(temp%2);
            demographic[560+index] = size_t(temp%2);
            temp = temp/2;
        }
    }
    // batch_encoder->encode(email, pemail);
    // encryptor->encrypt(pemail, enc_email);
    // for(int i = 0; i < 4096; i++){
    //     cout << demographic[i];
    // } 
    // cout << endl;

    // Encoding DoB data. Encoded as number of years as no. of 1s in bits 800-1200, and (no. of days), (nod + 1), ..., (nod + 400) in slots 1200-1600.
    for (int i = 800; i < 1200; i++){
        if (tdob_year > 0){
            tdob_year -= 1;
            demographic[i] = size_t(1);
        }
        else
            demographic[i] = size_t(0);
    }

    for (int i = 1200; i < 1600; i++){
        int temp = i - 1200;
        demographic[i] = tdob_day + temp;
    }

    // for (int i = 800; i < 1600; i++){
    //     cout << demographic[i] << " ";
    // }


    batch_encoder->encode(demographic, pdemo);
    encryptor->encrypt(pdemo, enc_demographic);

    
    // for (int i = 0; i < 640; i++){
    //     cout << tbio[i] << " ";
    // }
    // cout << endl;
    for(int i = 0; i < 640; i++){
        biometric_template[i] = size_t(tbio[i]);
    }
    batch_encoder->encode(biometric_template, pbio);
    encryptor->encrypt(pbio, enc_biometric_template);
}
