#ifndef _MIME_H_

#define _MIME_H_
#include "project.h"

struct mime_head_fields
{
  char *content_type;
  char *content_transfer_encoding;
};

enum mime_fields_patt_index{
  FIELDS_FROM = 0,
  FIELDS_TO,
  FIELDS_DATE,
  FIELDS_SUBJECT,
  FIELDS_CONTENT_TYPE,
  FIELDS_TRANSFER_ENCODING
};

#define MIME_FIELDS_PATT_MAX 6

//for pop3 smtp imap
extern char *mime_fields_patt[MIME_FIELDS_PATT_MAX];

extern int mime_entity(struct Email_info *, const char *source, int length);

#endif
