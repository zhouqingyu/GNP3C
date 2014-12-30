#ifndef _TELNET_ANALYSIS_H_

#define _TELNET_ANALYSIS_H_

extern void telnet_analysis_init();

struct TelnetInformation{
   char *password;
   char *content;
   char *command;
};

#endif 