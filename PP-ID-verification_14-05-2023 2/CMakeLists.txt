cmake_minimum_required(VERSION 3.10)
project (SEALDemo VERSION 1.0)

add_executable(sealdemo cs.cpp encrypteduser.cpp dbgen.cpp user.cpp tpp.cpp)

find_package(SEAL)
# find_package(HEXL 1.2.3 REQUIRED)
target_link_libraries(sealdemo SEAL::seal)
