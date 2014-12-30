#ifndef TOOLS_H

#define TOOLS_H

#include "./Email/email_attachment_match.h"

extern struct project_prm project_params;
extern int read_file(char *file_path,struct File_data *file_data);
extern struct project_prm project_params;
extern struct Configuration configuration;
extern int base64_decode(const char *in_str, int in_len, char *out_str);
extern int qp_decode(const char *in_str, int in_len, char *out_str);
extern int _7bit_decode(const unsigned char* pSrc, int nSrcLength, char* pDst); 
extern int pcre_match(char *pattern,const char *source, int length, 
		      int ovector[], int ov_size, int options);
extern int pcre_matall(const char *pattern, const char *source, 
						int src_len, int *ovector, int ov_size, int options);
extern void copy_into_email_info_member(char **mem, char *src, int len);
extern int url_decode(const char *src, int src_len, char *dest, int *dest_len);
extern void email_reference_init(struct Email_reference *er);
extern void email_reference_free(struct Email_reference *er);
extern void printf_http_entity_parameter_info_detail(struct Http *http);
extern void free_list_node(struct List_Node *value);
extern int get_first_value_from_name(struct Http *http,char *name,struct List_Node *value);
extern int match_one_substr_no_mem(char *pattern,char *source,int length,char **result);
extern void email_info_init(struct Email_info *email_info);





#endif
