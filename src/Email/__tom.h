#ifndef __TOM_H

extern int __tom_send_content(struct Http *http,struct Email_info *email_info);
extern int __tom_send_attachment(struct Http *http,struct Email_info *email_info);
extern int __tom_receive_content(struct Http *http,struct Email_info *email_info);
extern int __tom_receive_attachment(struct Http *http,struct Email_info *email_info);

#define __TOM_H 

#endif
