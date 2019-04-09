#!/bin/bash
# My first script

gcc -Iphc-winner-argon2/include lab3.c -o lab3_gdb -lncurses -L./phc-winner-argon2 -largon2 -lpthread -g
gcc -Iphc-winner-argon2/include lab3.c -o lab3 -lncurses -L./phc-winner-argon2 -largon2 -lpthread
