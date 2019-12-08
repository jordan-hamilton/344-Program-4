#!/bin/bash

gcc -std=gnu99 -o keygen keygen.c -Wall -pedantic
gcc -std=gnu99 -o otp_dec otp_dec.c -Wall -pedantic
gcc -std=gnu99 -o otp_dec_d otp_dec_d.c -Wall -pedantic
gcc -std=gnu99 -o otp_enc otp_enc.c -Wall -pedantic
gcc -std=gnu99 -o otp_enc_d otp_enc_d.c -Wall -pedantic
chmod u+x keygen otp_dec otp_dec_d otp_enc otp_enc_d

exit 0