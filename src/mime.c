#include <pcre.h>
#include <stdio.h>
#include <string.h>
#include <malloc.h>

#include "mime.h"
#include "tools.h"

char *mime_fields_patt[MIME_FIELDS_PATT_MAX];
#define OV_SIZE 300

static void mime_fields_patt_init() 
{
  mime_fields_patt[FIELDS_FROM] = "^from:\\s+(.*?)\r\n";
  mime_fields_patt[FIELDS_TO]	= "^to:\\s+(.*?)\r\n";
  mime_fields_patt[FIELDS_DATE]	= "^date:\\s+(.*?)\r\n";
  mime_fields_patt[FIELDS_SUBJECT] = "^subject:\\s+(.*?)\r\n";
  mime_fields_patt[FIELDS_CONTENT_TYPE] = "^content-type:\\s+(.*?\r\n)";
  mime_fields_patt[FIELDS_TRANSFER_ENCODING] = "Content-Transfer-Encoding:\\s(.*?)\r\n";
}

static int unfolding(char *src, int len)
{
  int l;

  l = pcre_repl_all("\r\n(\b|\t| |\f|\v)", " ", src, len, 
		    PCRE_MULTILINE);
  if ( l != -1 ) 
    return l;

  return len;
}

static int convert_body(const char *source, int len, 
			 char *out_str, const char *encoding)
{
  int l;

  switch ( *encoding ) {
    case 'b': case 'B':
      l = base64_decode(source, len, out_str);
      break;
    case 'q': case 'Q':
      l = qp_decode(source, len, out_str);
      break;
// 	case '7':
// 	  l = len;
// 	  printf("%d\n", l);
// 	  break;
    default: 
      l = len;
      break;
  }
  
  return l;
}

static void decoded_word(char **emp, const char *source, int len)
{
  int ovector[OV_SIZE], rc, temp_len = 0;
  
  if ( *emp != NULL ) {
//     printf("*emp != NULL\n");
    return;
  }
  *emp = (char*)malloc( (len+1) * sizeof(char) );
printf("default len : %d\n", len);
  do {
    rc = pcre_match("=\\?(.*?)\\?(.*?)\\?(.*?)\\?=", 
		    source, len, ovector, OV_SIZE, PCRE_CASELESS);
    printf("rc %d \n", rc);
    if ( rc <= 0 )
      break;
    printf("0: %d\n", ovector[0]);
    printf("1: %d\n", ovector[1]);
    temp_len += convert_body(source + ovector[6], ovector[7] - ovector[6], 
			     *emp + temp_len, source + ovector[4]);
    source += ovector[1];
    len -= ovector[1];
    printf("len %d\n", len);
    printf("temp_len1 %d\n", temp_len);
    (*emp)[temp_len++] = ' ';
    printf("temp_len2 %d\n", temp_len);
  } while ( 1 );  
  memcpy(*emp+temp_len, source, len);
  (*emp)[len+temp_len]='\0';
}

static void parse_envelope(struct Email_info *email_info, 
			   const char **ptr, int *len, 
			   struct mime_head_fields *mp)
{
  int ret, ovector[OV_SIZE], fields_len, i;
  char *fields  = NULL;
  
  mp->content_type = NULL;
  mp->content_transfer_encoding = NULL;
  ret = pcre_match("^(.*?\r\n\r\n)",
		   *ptr, *len, ovector, OV_SIZE, 
		   PCRE_DOTALL|PCRE_MULTILINE);
  if ( ret != 2 )
    return;
  fields = (char*)malloc( (ovector[3]-ovector[2]) * sizeof(char));
  memcpy(fields, *ptr+ovector[2], ovector[3]-ovector[2]); 
  fields_len = unfolding(fields, ovector[3]-ovector[2]);
  *ptr += ovector[1];
  *len -= ovector[1];
  
  for ( i = 0; i < MIME_FIELDS_PATT_MAX; i++ ) {
    ret = pcre_match(mime_fields_patt[i], fields, fields_len, ovector, 
		     OV_SIZE, PCRE_CASELESS|PCRE_MULTILINE|
		     PCRE_NEWLINE_CRLF);
    if ( ret != 2 )
      continue;
    
    switch (i) {
      case FIELDS_FROM:
 		printf("FROM:\t");
// 		copy_into_email_info_member(&email_info->from, fields + ovector[2], 
// 			     ovector[3] - ovector[2]);
 		decoded_word(&email_info->from, fields + ovector[2], 
 			     ovector[3] - ovector[2]);
// 		printf("%s\n", email_info->from);
		break;
      case FIELDS_TO:
 		printf("TO:\t");
		decoded_word(&email_info->to, fields + ovector[2], 
			     ovector[3] - ovector[2]);	
// 		copy_into_email_info_member(&email_info->to, fields + ovector[2], 
// 			     ovector[3] - ovector[2]);
// 		printf("%s\n", email_info->to);
		break;
      case FIELDS_SUBJECT:
 		printf("SUBJT:\t");
		decoded_word(&email_info->subject, fields + ovector[2], 
			     ovector[3] - ovector[2]);
// 		copy_into_email_info_member(&email_info->subject, fields + ovector[2], 
// 			     ovector[3] - ovector[2]);
// 		printf("%s\n", email_info->subject);
		break;
      case FIELDS_DATE:
// 		printf("DATE:\t%.*s\n", ovector[3]-ovector[2], fields+ovector[2]);
		break;
      case FIELDS_CONTENT_TYPE:
 		mp->content_type = (char*)malloc( (ovector[3]-ovector[2]+1) * 
				sizeof (char));
		memset(mp->content_type, '\0', ovector[3]-ovector[2]+1);
 		memcpy(mp->content_type, fields+ovector[2], ovector[3]-ovector[2]);
		break;
      case FIELDS_TRANSFER_ENCODING:
		mp->content_transfer_encoding = (char*)malloc( (ovector[3]-
						ovector[2]+1) * sizeof (char));
		memset(mp->content_transfer_encoding, '\0', ovector[3]-ovector[2]+1);
 		memcpy(mp->content_transfer_encoding, fields+ovector[2], 
	       		ovector[3]-ovector[2]);
		break;
      default: break;
    }
  }
  free(fields);
}

static int is_text_plain_entity(const char *type, int len)
{
  int ovector[OV_SIZE];
  int ret = pcre_match("plain", type, len, ovector, 
		       OV_SIZE, PCRE_CASELESS);
  return ret == 1?ret:0;
}

static int is_single_entity(const char *type, int len)
{
  int ovector[OV_SIZE];
  int ret = pcre_match("(?:text|image|audio|video|application)", 
		       type, len, ovector, OV_SIZE, PCRE_CASELESS);
  return ret == 1?ret:0;
}

static void mime_struct_free(struct mime_head_fields *mp) 
{
  if ( mp->content_type != NULL )
    free(mp->content_type);
  if ( mp->content_transfer_encoding != NULL )
    free(mp->content_transfer_encoding);
}

int mime_entity(struct Email_info *email_info, 
		const char *source, int length)
{
  struct mime_head_fields mime;
  const char *pointer = source;
  int new_len = length, ovector[OV_SIZE], ret, i, body_len;
  char boundary[100] = {0};
//     printf("entity length :%d\n", length);
  mime_fields_patt_init();
  parse_envelope(email_info, &pointer, &new_len, &mime);
  if ( mime.content_type == NULL )
    return 0;
  ret = pcre_match("(\\w+)/(\\w+);\\s+"
		   "(.*?)=(?:\"?(.*?)\"?)\\s+", 
		   mime.content_type, strlen(mime.content_type), 
		   ovector, OV_SIZE, PCRE_CASELESS);
  if ( ret != 5 )
    return 0;
  if ( is_single_entity(mime.content_type+ovector[2], 
				  ovector[3]-ovector[2]) ) {
//     printf("single entity\n");
    if ( email_info->content != NULL ) {
//       printf("content not NULL\n");
      mime_struct_free(&mime);
      return 0;
    }
    if ( !is_text_plain_entity(mime.content_type+ovector[4], 
      ovector[5]-ovector[4]) ) {
//       printf("not plain\n");
      mime_struct_free(&mime);
      return 0;
    }
    printf("BODY:\t");
    email_info->content = (char*)malloc( (new_len+1) * sizeof(char) );
    memset(email_info->content, '\0', new_len+1);
    if ( mime.content_transfer_encoding != NULL )
       convert_body(pointer, new_len, email_info->content, 
		    mime.content_transfer_encoding);
    else
	memcpy(email_info->content, pointer, new_len);
    printf("%d\n", strlen(email_info->content));
    mime_struct_free(&mime);
    return 0;
  }
  memcpy(boundary, "--", 2);
  memcpy(boundary + 2, mime.content_type + ovector[8], 
	 ovector[9] - ovector[8]);
  
  ret = pcre_matall(boundary, pointer, new_len, ovector, OV_SIZE, 0);
  for ( i = 0; i < ret - 1; i++ ) {
    body_len = ovector[2*(i+1)] - ovector[2*i+1];
    mime_entity(email_info, pointer + ovector[2*i+1], body_len); 
  }
  
  mime_struct_free(&mime); 
  return 0;
}
