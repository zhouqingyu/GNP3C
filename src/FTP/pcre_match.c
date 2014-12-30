#include "mypcre.h"

int pcre_match(const char *pattern, const char*source, int src_len, 
	       int *ovector, int ov_size, int options)
{ 
      pcre *regex = NULL;
      const char *error = NULL;
      int erroffset;
      int rc;

    /* compile regex_pattern */
      regex = pcre_compile( pattern, options, &error, &erroffset, NULL);

    /* fail to compile, export error */
      if( regex == NULL )
      {
           printf("PCER compilation failure at offset %d: %s\n", 
		  erroffset, error);       
           free( regex );
           return -28;
       }

     /* execute matching */ 
       rc = pcre_exec( regex, NULL, source, src_len, 0, 0, ovector, ov_size);

      /* release storage of regex */
       free( regex );
       return rc;
}

int pcre_is_matched(const char *pattern, const char *source, int src_len, 
		  int options)
{
      int ovector[DEFAULT_VECTOR_SIZE];
      int rc;
      
      rc = pcre_match(pattern, source, src_len, ovector, DEFAULT_VECTOR_SIZE, 
		      options);
      
      if (rc > 0)
	return 1;
      else
	return 0;
}
