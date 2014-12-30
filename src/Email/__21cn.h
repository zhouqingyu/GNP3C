#ifndef __21CN_H

extern int __21cn_send_content(struct Http *http,struct Email_info *email_info);
extern int __21cn_send_attachment(struct Http *http,struct Email_info *email_info);
extern int __21cn_receive_content(struct Http *http,struct Email_info *email_info);
extern int __21cn_receive_attachment(struct Http *http,struct Email_info *email_info);

#define __21CN_H

#endif
