#ifndef __SOHU_H

extern int __sohu_send_content(struct Http *http,struct Email_info *email_info);
extern int __sohu_send_attachment(struct Http *http,struct Email_info *email_info);
extern int __sohu_receive_content(struct Http *http,struct Email_info *email_info);
extern int __sohu_receive_attachment(struct Http *http,struct Email_info *email_info);

#define __SOHU_H

#endif
