#include "lab3.h"

int main(void)
{
    int choice = 0,sta = INITIAL;
    bool blogin = false;
    bool quit = false;

    while(!quit)
    {
        prompt(sta);
        read(STDIN_FILENO,&choice,1);
        clrbuf();
        switch (choice)
        {
            case 's':
            case 'S':
                if (blogin)
                   break;
                while(!signup())
                {
                    if (!retry())
                        break;
                    else
                        continue;
                }
                sta = INITIAL;
                break;
            case 'i':
            case 'I':
                if (blogin)
                    break;
                while(!login(&blogin))
                {
                    if (!retry())
                       break;
                    else
                        continue;
                }
                if (blogin)
                    sta = LOGIN;
                break;
            case 'o':
            case 'O':
                logout(&blogin);
                sta = INITIAL;
                break;
            case 'x':
            case 'X':
                 quit = true;
                 break;
            default:
                printf("Invalid Input\n");
                break;
        }
    }
    return 0;
}

void prompt(int sta)
{
    switch(sta)
    {
        case INITIAL:
        case LOGOUT:
        printf("Eneter Your Choice:\n");
        printf("[s] - Sign Up;\n");
        printf("[i] - User login;\n");
        printf("[o] - User logout;\n");
        printf("[x] - quit the application\n");
        break;
        case SIGNUP_NAME:
        printf("Enter an user nmae:\n");
        printf("Note: - a : only contain letters and numbers:\n");
        printf("      - b : 1 to 128 characters\n");
        break;
        case SIGNUP_PWD:
        printf("Enter your password:\n");
        printf("Note: - a : contain at least 1 upper case letter;\n");
        printf("      - b : contain at least 1 lower case letter;\n");
        printf("      - c : contain at least 1 number\n");
        printf("      - d : length should be from 8 to 128\n");
        break;
        case LOGIN:
        printf("Eneter Your Choice:\n");
        printf("[o] - User logout;\n");
        printf("[x] - quit the application\n");
        break;

        default:
        break;
    }
}

bool signup(void)
{
    FILE * fid = NULL;
    secret scrt;
    char pwd[MAXNAMELEN];

    memset(&scrt, 0, sizeof(scrt));
    memset(pwd, 0, MAXNAMELEN);

    if (!get_name(pwd, &scrt))
        return false;
    memset(&scrt, 0, sizeof(scrt));
    memcpy(scrt.name,pwd,strlen(pwd));
    memset(pwd, 0, MAXNAMELEN);

    if (!get_pwd(pwd))
    {
        printf("Invalid Input\n");
        return false;
    }

    if (!authen(pwd, &scrt, NEW))
        return false;

    memset(pwd, 0, MAXNAMELEN);

    fid = fopen("profile.bin","ab+");
    fwrite(&scrt, sizeof(secret), 1, fid);
    fclose(fid);
    printf("Sign Up Success!\n");
    return true;
}

bool login(bool* pblogin)
{
    FILE * fid = NULL;
    int len = 0;
    struct termios echo_on, echo_off;
    char str[MAXNAMELEN+MAXPWDLEN];
    secret record;

    if (*pblogin)
    {
        printf("You should logout first\n");
        return false;
    }
    memset(str,0,MAXNAMELEN+MAXPWDLEN);
    memset(&record,0,sizeof(secret));

    if (!rcv_name_pwd(NAME,str))
        return false;
    len = strlen(str);

    if (tcgetattr( fileno(stdin), &echo_on) != 0 )
        return false;
    echo_off = echo_on;
    echo_off.c_lflag &= ~ECHO;
    if  (tcsetattr( fileno(stdin), TCSAFLUSH, &echo_off) != 0)
        return false;
    if (!rcv_name_pwd(PWD,str+len))
        return false;
    if  (tcsetattr( fileno(stdin), TCSAFLUSH, &echo_on) != 0)
        return false;

    if ( fsearch(str, len, &record) && authen(str+len, &record, VERIFY))
    {
        printf("\nWelcome %s\n",record.name);
        *pblogin = true;
        return true;
    }
    else
    {
        printf("Your credential is incorrect.\n ");
        return false;
    }
}

bool logout(bool* login)
{
    if (!(*login))
    {
        printf("You should login first. \n");
        return false;
    }
    *login = false;
    printf("See you next time!\n");
    return true;
}

bool get_name(char * name, secret * record)
{
    int i;
    char c = 0;
    bool bother_c = false;
    bool bexist = false;

    prompt(SIGNUP_NAME);
    for ( read(STDIN_FILENO,&c,1), i = 0; c != '\n' && i < MAXNAMELEN; i++)
    {
        if ( (c >= 97 && c <= 122) \
             || (c >= 65 && c <= 90) \
             || (c >= 48 && c <= 57) )
        {
            *(name+i) = c;
            read(STDIN_FILENO,&c,1);
        }
        else
        {
            bother_c = true;
            break;
        }
    }

    if (c != '\n' && c !=  EOF)
        clrbuf();
    if (i < MINNAMELEN  || i >= MAXNAMELEN || bother_c)
        return false;

    if (fsearch(name,i,record))
        bexist = true;

    if (bexist)
    {
        printf("The user name is used!\n");
        return false;
    }
    return true;
}

bool get_pwd(char * pwd)
{
    char ptr1[MINPWDLEN];
    char ptr2[MINPWDLEN];
    char c = 0;
    int i, j;
    struct termios echo_on, echo_off;
    bool bupper=false, blower=false, bnum=false, bsafe=false;

    prompt(SIGNUP_PWD);
    if (tcgetattr( fileno(stdin), &echo_on) != 0 )
        return false;
    echo_off = echo_on;
    echo_off.c_lflag &= ~ECHO;
    if  (tcsetattr( fileno(stdin), TCSAFLUSH, &echo_off) != 0)
        return false;

    for ( read(STDIN_FILENO,&c,1), i = 0; c != '\n' && i < MAXPWDLEN; i++)
    {
        if (c >= 97 && c <= 122)
            blower = true;

        if (c >= 65 && c <= 90)
            bupper = true;

        if (c >= 48 && c <= 57)
            bnum = true;

        ptr1[i] = c;
        read(STDIN_FILENO,&c,1);
    }
    bsafe = blower & bupper &bnum;

    if  (tcsetattr( fileno(stdin), TCSAFLUSH, &echo_on) != 0)
        return false;
    if (i < MINPWDLEN || i >= MAXPWDLEN || !bsafe)
        return false;

    printf("\n");
    setvbuf(stdout, NULL, _IONBF, 0);
    printf("Please repeat your password: ");
    setvbuf(stdout, NULL, _IOLBF, 0);
    if  (tcsetattr( fileno(stdin), TCSAFLUSH, &echo_off) != 0)
        return false;
    for ( read(STDIN_FILENO,&c,1), j = 0; c != '\n' && j < MAXPWDLEN; j++)
    {
        ptr2[j] = c;
        read(STDIN_FILENO,&c,1);
    }
    if  (tcsetattr( fileno(stdin), TCSAFLUSH, &echo_on) != 0)
        return false;
    if (j < MINPWDLEN || j >= MAXPWDLEN)
        return false;
    printf("\n");

    if (i != j)
        return false;

    if (memcmp(ptr1,ptr2,j) != 0)
        return false;

    memcpy(pwd, ptr1, j);
    return true;
}

bool retry(void)
{
    char c=0;
    while (true)
    {
        setvbuf(stdout, NULL, _IONBF, 0); // non buffer model for output
        printf("Do you want to try it agin?[y/n]");
        setvbuf(stdout, NULL, _IOLBF, 0); // non buffer model for output
        read(STDIN_FILENO,&c,1);
        clrbuf();
        printf("\n");
        if (c == 'y' || c == 'Y')
            return true;
        else if (c == 'n' || c == 'N')
            return false;
        else
            printf("Invalid Input!\n");
    }
}
#if 1
void clrbuf(void)
{
    char c = 0;
    do {
        c = getchar();
    } while( c != '\n'&& c != EOF );
    return;
}
#endif
bool authen(char* pwd, secret * scrt, int flag)
{
    FILE * fid;
    uint8_t * hash;
    int rc;
    uint32_t t_cost = 2;            // 1-pass computation
    uint32_t m_cost = (1<<16);      // 64 mebibytes memory usage
    uint32_t parallelism = 1;       // number of threads and lanes

    if (flag == NEW)
    {
        fid = fopen("/dev/urandom", "r");
        fread(&(scrt->salt), sizeof(uint8_t), SALTLEN, fid);
        fclose(fid);
        hash = scrt->hash;
    }
    if (flag == VERIFY)
    {
        hash = malloc(HASHLEN*sizeof(uint8_t));
    }

    argon2_context context = {
        hash,  /* output array, at least HASHLEN in size */
        HASHLEN, /* digest length */
        pwd, /* password array */
        strlen(pwd), /* password length */
        scrt->salt,  /* salt array */
        SALTLEN, /* salt length */
        NULL, 0, /* optional secret data */
        NULL, 0, /* optional associated data */
        t_cost, m_cost, parallelism, parallelism,
        ARGON2_VERSION_13, /* algorithm version */
        NULL, NULL, /* custom memory allocation / deallocation functions */
        /* by default only internal memory is cleared (pwd is not wiped) */
        ARGON2_DEFAULT_FLAGS
    };

    rc = argon2i_ctx( &context );
    if(ARGON2_OK != rc) {
//        printf("Error: %s\n", argon2_error_message(rc));
        return false;
    }
    if (flag == VERIFY)
    {
        if( !memcmp(hash,scrt->hash,HASHLEN) )
        {
            free(hash);
            return true;
        }
        free(hash);
        return false;
    }
    if (flag == NEW)
        return true;
}

bool rcv_name_pwd(int flag, char * str)
{
    char c=0;
    int i, len;
    while(true)
    {
        if (flag == NAME)
        {
            len = MAXNAMELEN;
            setvbuf(stdout, NULL, _IONBF, 0); // non buffer model for output
            printf("Enter your user name:");
            setvbuf(stdout, NULL, _IOLBF, 0); // buffer model for output
        }
        else
        {
            len = MAXPWDLEN;
            setvbuf(stdout, NULL, _IONBF, 0);
            printf("Enter your password:");
            setvbuf(stdout, NULL, _IOLBF, 0);
        }

        for (read(STDIN_FILENO,&c,1), i = 0; c != '\n' && i < len; i++)
        {
            *(str+i) = c;
            read(STDIN_FILENO,&c,1);
        }

        if (i >= len)
        {
            printf("Invalid Input\n");
            if (!retry())
                return false;
        }
        else
        {
            return true;
        }
    }
}

bool fsearch(char * pstr, int len, secret * record)
{
    FILE * fid = NULL;
    int nlen = 0;
    size_t rc = 0;

    fid = fopen("profile.bin","ab+");
    fseek(fid, 0, SEEK_SET);
    while (true)
    {
        rc = fread(record, sizeof(secret), 1,fid);
        if (rc < 1)
        {
            fclose(fid);
            return false;
        }
        nlen = strlen(record->name);
        if (!memcmp(pstr,record->name,(nlen >= len) ? nlen : len))
        {
            fclose(fid);
            return true;
        }
        else
        {
            fseek(fid, 0, SEEK_CUR);
            continue;
        }
    }
}
