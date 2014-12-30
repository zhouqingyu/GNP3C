#ifndef _COOKIES_ANALYSIS_H_

#define _COOKIES_ANALYSIS_H_

struct CookiesInformation{
    int ishavecookies; // 1 have  2 don't have
    int tcpid;
    char url[1000];
    char cookies[1000];
    char cookies_url[1000];
};

extern void cookie_analysis_init();

#endif