#ifndef CONFIGURATION_H

#include "project.h"
#define CONFIGURATION_H


extern struct Configuration configuration;
extern struct project_prm project_params;

extern int read_configuration();
extern int read_file(char *file_path,struct File_data *file_data);

#endif
