#
# Owners: Deep Inder Singh, Srinivas Vivek, Shyam Murthy
#         IIIT Bangalore
#
# THIS LIBRARY HAS BEEN TESTED WITH MICROSOFT SEAL VERSION 3.6
#

# Installation and run instructions

### Installing MS Seal

Refer to the video on Microsoft's Youtube channel: https://www.microsoft.com/en-us/research/video/installing-microsoft-seal-on-linux-macos/

Alternatively, follow the instructions below:

* Make sure your compiler supports C++ 17
* Clone the MS SEAL repo:   ```git clone https://github.com/microsoft/SEAL```
* navigate to SEAL/native/src
* run ```cmake .```
* run ```make -j ```
* To install SEAL globally, execute ``` sudo make install ```
* If you want to install SEAL locally, please refer to README.md in the SEAL directory. You will also need to provide a path to the SEAL install directory in the project's CMakeLists.txt file.
* (Optional) Install HEXL to use Intel's AVX-512 instruction set in supported machines: https://github.com/intel/hexl.


### Executing SEAL code
* Clone the current repo and navigate to the /SEAL directory.
* Create new directories named /userData and /keys in the /SEAL directory.
* Execute ```cmake .```
* If build files are successfully generated, execute ```make```
* A new executable called sealdemo should be generated. Run ``` ./sealdemo ```
* Choose the option to generate database. This should populate the keys and userData directories.
* Now you can use the library as required. 

### SEAL Code - Compare data

All the user data from the "Generate database" step is stored in the userData directory. Since each user's data is 2 encrypted vectors (demographic and biometric), these vectors are stored as separate files with the numbering corresponding to each user. Currently, the data from two users has been hardcoded into the system. The details of this user data can be found in the file ``` dbgen.cpp```.

On choosing "2 - Compare Data", the system will prompt you to enter the ID of the user whose data must be verified. As there are only two users in the *database* at the moment, the choice for this is either 1 or 2. On entering this ID, the user will be prompted with a list of options as follows:-

* **Compare Name** - This option prompts you to enter the string of the name as input. The string may contain whitespaces. The input is case sensitive. The output will be "Match successful" only if the entered name is an exact match with the name on record. E.g., for user 1, the input will match only if the name entered is "Deep Inder Mohan".
* **Compare Gender** - Takes input as a single uppercase character - "M" or "F".
* **Compare Pincode** - Input is a 6-digit pincode, Eg. "134112".
* **Compare Phone number** - Input is a 13 digit phone number including country code.
* **Compare Email Address** - Input is a email address without whitespaces.
* **Compare Date of Birth** - Every date of birth is encoded as two 3-digit numbers, each representing a distance from the pivot 1 Jan 1900. So for instance, the DoB 18th Feb, 1997 can be thought of as occouring 97 years after 1900, and 49 days after 1 Jan. Therefore, 18th Feb, 1997 is represented as 097 049. The expected input for DoB comparison must be a 6 digit number created from the DoB as described above, Eg. "097049". The output will indicate if this DoB comes before or after the DoB on record.
* **Compare Biometric Data** - Biometric data is represented as a fingercodes vector, which is a vector of size 640, with each index containing an 8-bit number. The template vectors for users 1 and 2 can be found in ```dbgen.cpp```. Due to impracticality of taking such a large input from the console, the input to this query-type is read from the file ```biometric_input.txt```, in which each new line contains one index of the fingercodes vector.  


### Option 2 - Docker
* Pull and build the following docker image https://hub.docker.com/r/ibmcom/fhe-toolkit-ubuntu
* Link the SEAL directory in the current repo as a virtual volume for this image.
* Follow the same instructions as above to execute the code.


# Files
* CMakeLists.txt - CMake instructions to compile the code. Only edit in case you have a local install of SEAL or want to enable HEXL support.
* cs.cpp/cs.h - Codebase for the Central Server. 
* dbgen.cpp/dbgen.h - Script for generating and storing the user data and keys.
* user.cpp/user.h - Class files for the User class.
* encrypteduser.cpp/encrypteduser.h - Class files for the EncryptedUser class.
* tpp.cpp/tpp.h - Third party server routines.



