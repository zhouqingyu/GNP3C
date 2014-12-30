#include "mypcre.h"

int pcre_repl(const char *pattern, const char *replacement, const char *source, int src_len, char *buffer, int options)
{
      pcre *regex = NULL;
      const char *error = NULL;
      int ovector[30], erroffset, buf_len = -1;
      int rc;
      
    /* compile regex_pattern */
      regex = pcre_compile( pattern, options, &error, &erroffset, NULL);
    /* fail to compile, export error */
      if( regex == NULL )
      {
           printf("PCER compilation failure at offset %d: %s\n", erroffset, error);       
           free( regex );
           return -28;
      }
     /* execute matching */ 
       rc = pcre_exec( regex, NULL, source, src_len, 0, 0, ovector, 30);
     /* release storage of regex */
       free( regex );
       
       if( rc > 0 )
       {
           char *dest = (char*)malloc( (src_len - ovector[1]) * sizeof(char) );
           memcpy(dest, source + ovector[1], src_len - ovector[1]);
           memcpy(buffer, source, ovector[0]);
           memcpy(buffer + ovector[0], replacement, strlen(replacement));
           memcpy(buffer + ovector[0] + strlen(replacement), dest, src_len - ovector[1]);
           buf_len = src_len + strlen(replacement) - (ovector[1] - ovector[0]);
           free(dest);
       }
       return buf_len;           
}

