#include "mypcre.h"

int pcre_matall(const char *pattern, const char *source, int src_len, int *ovector, int ov_size, int options)
{
      pcre *regex = NULL;
      const char *error = NULL;
      int erroffset, rc, mat_count = 0, i_temp[30] = {0}, endoffset = 0;
      
      if(strlen(pattern)==0)
      {
          return mat_count;
      }
      do
      {
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
          rc = pcre_exec( regex, NULL, source + endoffset, src_len - endoffset, 0, 0, i_temp, sizeof(i_temp) );

       /* release storage of regex */
          free( regex );
          
          if(rc > 0)
          {
              if( ov_size < 2 * mat_count + 2 )
              {
                  printf("error : ovector[] overflow\n");
                  return -29;
              }
              ovector[2 * mat_count] = i_temp[0] + endoffset;
              ovector[2 * mat_count + 1] = i_temp[1] + endoffset;
              endoffset += i_temp[1];
              mat_count++;
          }          
          
      }while(rc > 0);
      
      return mat_count;      
}

