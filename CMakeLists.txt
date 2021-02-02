cmake_minimum_required(VERSION 2.8)
project(Program_4 C)

set(CMAKE_C_FLAGS_DEBUG "${CMAKE_C_FLAGS_DEBUG} -std=gnu99 -Wall -pedantic")

set(CMAKE_C_STANDARD 99)

add_executable(otp_enc_d
        otp_enc_d.c)

add_executable(otp_enc
        otp_enc.c)

add_executable(otp_dec_d
        otp_dec_d.c)

add_executable(otp_dec
        otp_dec.c)

add_executable(keygen
        keygen.c)