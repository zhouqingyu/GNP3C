#ifndef _USER_PASSWORD_

#define _USER_PASSWORD_

struct UPInformation{
    int tcpid;
    char url[100];
    char user[100];
    char password[100];
};

extern void user_password_analysis_init();


#endif 

