#ifndef MYPCRE_H
#define MYPCRE_H

#include <pcre.h>
#include <string.h>
#include <stdio.h>

#define DEFAULT_VECTOR_SIZE 300

extern int pcre_match(const char *pattern, 
                      const char*source, 
                      int src_len, 
                      int *ovector, 
                      int ov_size, 
                      int options);
                       
extern int pcre_matall(const char *pattern, 
                       const char*source, 
                       int src_len, 
                       int *ovector, 
                       int ov_size, 
                       int options);

extern int pcre_repl(const char *pattern, 
                     const char *replacement, 
                     const char *source, 
                     int src_len, 
                     char *buffer, 
                     int options);

extern int pcre_matall(const char *pattern, 
                       const char *source, 
                       int src_len, 
                       int *ovector, 
                       int ov_size, 
                       int options);

extern int pcre_is_matched(const char *pattern, 
		    const char *source, 
		    int src_len, 
		    int options);

#endif
