#ifndef SAVE_ENVIRONMENT_H

#define SAVE_ENVIRONMENT_H

extern struct Configuration configuration;
extern pthread_mutex_t tcp_lost_mutex;

extern struct Tcp_Data *tcp_data_table[];
extern pthread_mutex_t mutex_tcp_data_table;// mutex lock for tcp_data_table
extern void save_environment_init();
#endif
