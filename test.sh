#!/bin/bash

gcc -o test.out json.c gpgme_json.c test.c -lgpgme -lm 
./test.out | jq
rm test.out
