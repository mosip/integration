/**
 * Codebase for Central Server
 **/

#include "cs.h"
using namespace seal;

int pow(int x, unsigned int p)
    {
    if (p == 0) return 1;
    if (p == 1) return x;
    
    int tmp = pow(x, p/2);
    if (p%2 == 0) return tmp * tmp;
    else return x * tmp * tmp;
}

vector<int> decodeVector(vector<uint64_t> input){
    // cout << "Decrypted Output = ";
    // for (int i = 0; i < 4096; i++){
    //     cout << input[i] << " ";
    // }
    // cout << endl;
    vector<int> outputBinary(512, 0);
    for (int i = 0; i < 512; i++){
        int exit = 0;
        for (int j = 8*i; j < ((8*i)+8); j++){
            if (i < 50){
                if(int(input[j]) != 0){
                    // cout << "i = " << i << endl;
                    exit = 1;
                    break;
                }
            }
            else {
                if (int(input[j]) != 0){
                    exit = 1;
                }
                else {
                    exit = 0;
                    break;
                }
            }
        }
        outputBinary[i] = exit;
        // cout << outputBinary[i] << " ";
    }
    // cout << endl;
    int output = 0;
    for (int i = 0; i < 512; i++){
        if(outputBinary[i] == 1){
            output += pow(2, i);
        }
    }
    return outputBinary;
}

CentralServer::CentralServer(){
    EncryptionParameters parms(scheme_type::bfv);
    size_t poly_modulus_degree = 8192;
    parms.set_poly_modulus_degree(poly_modulus_degree);
    parms.set_coeff_modulus(CoeffModulus::BFVDefault(poly_modulus_degree));    
    parms.set_plain_modulus(PlainModulus::Batching(poly_modulus_degree, 22));
    // Checking the validity of the set parameters
    SEALContext context(parms);
    ifstream file_obj;
    file_obj.open("keys/publickey.pk", ios::in);
    pk.load(context, file_obj);
    file_obj.close();
    file_obj.clear();
    file_obj.open("keys/secretkey.sk", ios::in);
    sk.load(context, file_obj);
    file_obj.close();
    file_obj.clear();
    encryptor = new Encryptor(context, pk);
    decryptor = new Decryptor(context, sk);
    evaluator = new Evaluator(context);
    encoder = new BatchEncoder(context);
};

int CentralServer::encryptInput(string data, int type, Ciphertext* out){
    vector<uint64_t> demographic(encoder->slot_count()/2, 0ULL);
    switch (type)
    {
    case 1: {
        // Data type: Name
        int spaces = 50 - data.length();
        while (spaces > 0){
            data = data + " ";
            spaces = spaces - 1;
        }
        for(int i = 0; i < 50; i++){
            int temp = int(data[i]);
            for (int j = 0; j < 8; j++){
                int index = (8*(i+1)) - (j+1);
                // name[index] = size_t(temp%2);
                demographic[index] = size_t(temp%2);
                temp = temp/2;
            }
        }    
        break;
    }
    
    case 2: {
        // Data type: Sex
        int temp = data[0];
        for (int i = 0; i < 7; i++){
            demographic[407-i] = size_t(temp%2);
            temp = temp/2;
        }
        break;
    }

    case 3:
        // Pincode
        for(int i = 0; i < 6; i++){
            int temp = data[i];
            for (int j = 0; j < 8; j++){
                int index = (8*(i+1)) - (j+1);
                demographic[408+index] = size_t(temp%2);
                temp = temp/2;
            }
        }
        break;
    
    case 5:
        // Phone number
        for(int i = 0; i < 13; i++){
            int temp = data[i];
            for (int j = 0; j < 8; j++){
                int index = (8*(i+1)) - (j+1);
                demographic[456+index] = size_t(temp%2);
                temp = temp/2;
            }
        }
        break;

    case 4: {
        // email ID
        int spaces = 30 - data.length();
        while (spaces > 0){
            data = data + " ";
            spaces = spaces - 1;
        }
        for(int i = 0; i < 30; i++){
            int temp = data[i];
            for (int j = 0; j < 8; j++){
                int index = (8*(i+1)) - (j+1);
                demographic[560+index] = size_t(temp%2);
                temp = temp/2;
            }
        }
        break;
    }

    case 10: {
        for (int i = 0; i < 10; i ++){
            int temp = data[i] - '0';
            demographic[i] = size_t(temp);
        }
        break;
    }

    default:
        break;
    }

    Plaintext pdemo;
    // cout << "recorded demographic = " << endl;
    // for(int i = 0; i < 4096; i++){
    //     cout << demographic[i];
    // } 
    encoder->encode(demographic, pdemo);
    encryptor->encrypt(pdemo, *out);
    return 0;
}

vector<int> CentralServer::decrypt(Ciphertext* c){
    cout << "noise budget = " << decryptor->invariant_noise_budget(*c) << " bits" << endl;
    Plaintext plain_result;
    vector<uint64_t> result_vector;
    decryptor->decrypt(*c, plain_result);
    encoder->decode(plain_result, result_vector);
    vector<int> result = decodeVector(result_vector);
    // Conditional Checking of result for various cases
    return result;
}

void CentralServer::printVector(Ciphertext* out){
    Plaintext plain_result;
    vector<uint64_t> result_vector;
    cout << "noise budget in freshly encrypted x: " << decryptor->invariant_noise_budget(*out) << " bits"
         << endl;
    decryptor->decrypt(*out, plain_result);
    encoder->decode(plain_result, result_vector);
    for (int i = 0; i < 10; i++){
        cout << result_vector[i];
    }
    cout << endl;
}


int main(){
    cout << "Welcome to MOSIP SEAL Demo" << endl;
    cout << "1: Generate Database" << endl;
    cout << "2: Compare data" << endl;
    cout << "Enter your choice: ";
    int choice;
    cin >> choice;
    if (choice == 1){
        generateDatabase();
    }
    else if (choice == 2){
        TPP server;
        CentralServer cs;
        int qchoice = 6;

        while(qchoice == 6){
            cout << "\nEnter ID of user you want to verify: ";
            int id;
            cin >> id;
            int found = server.findUser(id);
            if (found == 1){
                cout << "User found successfully!" << endl;
            }
            else{
                cout << "User with given ID not found. Try Again." << endl;
                continue;
            }
            qchoice = 0;
            while(qchoice <= 8){
                cout << "\nChoose your query type:-" << endl;
                cout << "1: Compare Name" << endl;
                cout << "2: Compare Gender" << endl;
                cout << "3: Compare pincode" << endl;
                cout << "4: Compare email address" << endl;
                cout << "5: Compare Phone Number" << endl;
                cout << "6: Compare Date of Birth" << endl;
                cout << "7: Compare Biometric Data" << endl;
                cout << "8: Enter New User ID" << endl;
                cout << "9: Exit" << endl;
                cout << "Choice: ";
                cin.ignore();
                cin >> qchoice;
                if (qchoice == 9){
                    return 0;
                }
                else if (qchoice == 8){
                    break;
                }

                Ciphertext* enc_input = new Ciphertext();
                // Biometric Comparison
                if (qchoice == 7){
                    ifstream is("biometric_input.txt");
                    istream_iterator<int> start(is), end;
                    vector<int> input(start, end);
                    cout << "Input data read from biometric_input.txt" << endl;
                    // for (int i = 0; i < 640 ; i++){
                    //     cout << input[i] << " ";
                    // }
                    // cout << endl;
                    vector<uint64_t> biometric(cs.encoder->slot_count()/2, 0ULL);
                    for (int i = 0; i < 640; i++){
                        biometric[i] = size_t(input[i]);
                    }
                    Plaintext pinp;
                    cs.encoder->encode(biometric, pinp);
                    cs.encryptor->encrypt(pinp, *enc_input);
                    Ciphertext* output = new Ciphertext();
                    // server.compareBiometric(enc_input, id, output);
                    server.compareBiometricSingle(enc_input, id, output);
                    enc_input = output;
                }
                else{
                    cout << "Enter data: ";
                    string inp_data;
                    cin.ignore();
                    getline(cin, inp_data);
                    cout << "The data entered: " << inp_data << endl;
                    cs.encryptInput(inp_data, qchoice, enc_input);
                    
                    if(qchoice == 1){
                        server.compareName(enc_input, id);
                    }
                    else if(qchoice == 2){
                        server.compareSex(enc_input, id);
                    }
                    else if(qchoice == 3){
                        server.comparePincode(enc_input, id);
                    }
                    else if(qchoice == 4){
                        server.compareEmail(enc_input, id);
                    }
                    else if(qchoice == 5){
                        server.comparePhonenumber(enc_input, id);
                    }
                    else if(qchoice == 6){
                        server.compareDOB(inp_data, id, enc_input);
                    }
                }


                cout << "Computation Successful" << endl;
                chrono::high_resolution_clock::time_point time_start, time_end;
                chrono::microseconds time_diff;
                time_start = chrono::high_resolution_clock::now();
                vector<int> out = cs.decrypt(enc_input);
                time_end = chrono::high_resolution_clock::now();
                time_diff = chrono::duration_cast<chrono::microseconds>(time_end - time_start);
                cout << "Done [" << time_diff.count() << " microseconds at CS]" << endl;
                if(qchoice == 6){
                    int exit1 = 0;
                    int exit2 = 1;
                    for(int i = 0; i < 50; i++){
                        if (out[i] != 0){
                            exit1 = 1;
                        }
                    }
                    for(int i = 50; i <100; i++){
                        if (out[i] == 0){
                            exit2 = 0;
                        }
                    }
                    if (exit1 == 0 && exit2 == 0){
                        cout << "Input DoB comes after user's DoB" << endl;
                    }
                    else
                        cout << "Input DoB comes before user's DoB" << endl;
                }

                else if (qchoice == 7){
                    int exit = 0;
                    for (int i = 50; i < 425; i++){
                        if (out[i] == 0){
                            cout << "Biometric input is a Match!" << endl;
                            exit = 1;
                            break;
                        }
                    }
                    if (exit == 0)
                        cout << "Biometric input is not a Match" << endl;
                }

                else{
                    int exit = 0;
                    for (int i = 0; i < 512; i++){
                        if (out[i] != 0){
                            exit = 1;
                            break;
                        }
                    }
                    if (exit == 0)
                        cout << "Inpu data is a match!" << endl;
                    else
                        cout << "Match failed!" << endl;
                }
                
                cout << endl;
                // cout << "Decrypted Output = ";
                // for (int i = 0; i < 4096; i++){
                //     cout << input[i] << " ";
                // }
                // cout << endl;
                cout << "End of computation" << endl;
            }
        }
    }

    //  Trial code for logic gates.

    // TPP server;
    // CentralServer cs;
    // Ciphertext* enc_input1 = new Ciphertext();
    // Ciphertext* enc_input2 = new Ciphertext();
    // Ciphertext* out = new Ciphertext();
    // cs.encryptInput("1111111111", 10, enc_input1);
    // cs.encryptInput("1111001111", 10, enc_input2);

    // out = server.XOR(enc_input1, enc_input2);
    // cs.printVector(out);

    return 0;
}
