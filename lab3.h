#include <stdio.h>
#include <stdbool.h>
#include <unistd.h> // for sleep9)
#include <stdlib.h>
#include <string.h>
#include "argon2.h"
#include <termios.h>
#include <stdint.h>

#define MAXNAMELEN 128
#define MINNAMELEN 1
#define MINPWDLEN  8
#define MAXPWDLEN  MAXNAMELEN
#define HASHLEN 32
#define SALTLEN 16
#define INITIAL     1
#define SIGNUP_NAME 2
#define SIGNUP_PWD  3
#define LOGIN       (SIGNUP_PWD+1)
#define LOGOUT      (LOGIN+1)
#define NAME        1
#define PWD         NAME+1
#define VERIFY      1
#define NEW         VERIFY+1

typedef struct
{
    char name[MAXNAMELEN];
    uint8_t salt[SALTLEN];
    uint8_t hash[HASHLEN];
} secret;

void prompt(int sta);
bool signup(void);
bool login(bool * login);
bool logout(bool * login);
bool get_name(char * name, secret * scrt);
bool get_pwd(char * pwd);
bool retry(void);
void clrbuf(void);
bool authen(char * pwd, secret * scrt, int flag);
bool rcv_name_pwd(int flag, char * str);
bool fsearch(char *pstr, int len, secret * scrt);
