cmake_minimum_required(VERSION 3.12) 
project(SEALDemo VERSION 1.0) 
add_executable(sealdemo_performance sealdemo_performance.cpp) 
add_executable(sealdemo_millionaire sealdemo_millionaire.cpp) 

find_package(SEAL 3.5 REQUIRED) 
target_link_libraries(sealdemo_performance SEAL::seal) 
target_link_libraries(sealdemo_millionaire SEAL::seal)
