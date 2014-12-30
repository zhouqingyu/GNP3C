#ifndef __qq_H

extern int __qq_send_content(struct Http *http,struct Email_info *email_info);
extern int __qq_send_attachment(struct Http *http,struct Email_info *email_info);
extern int __qq_receive_content(struct Http *http,struct Email_info *email_info);
extern int __qq_receive_attachment(struct Http *http,struct Email_info *email_info);

#define __qq_H

#endif
