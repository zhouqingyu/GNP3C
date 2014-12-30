/*
 * Copyright (c) 2003-2009 Chelsio, Inc. All rights reserved.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the LICENSE file included in this
 * release for licensing terms and conditions.
 */

#ifndef __LINUX_2_4_COMPAT_WORKQUEUE_H__
#define __LINUX_2_4_COMPAT_WORKQUEUE_H__

#include <linux/workqueue.h>

#include <stddef.h>
#include <linux/list.h>
#include <linux/timer.h>

/******************************************************************************
 * work queue compatibility
 ******************************************************************************/

#ifndef PREPARE_WORK
#define PREPARE_WORK(_work, _func, _data)                       \
        do {                                                    \
                (_work)->func = _func;                          \
                (_work)->data = _data;                          \
        } while (0)
#endif

#ifndef INIT_WORK
#define INIT_WORK(_work, _func, _data)                          \
        do {                                                    \
                INIT_LIST_HEAD(&(_work)->entry);                \
                (_work)->pending = 0;                           \
                PREPARE_WORK((_work), (_func), (_data));        \
                init_timer(&(_work)->timer);                    \
        } while (0)
#endif

struct workqueue_struct * create_singlethread_workqueue(const char *name);
void destroy_workqueue(struct workqueue_struct *wq);
int queue_work(struct workqueue_struct *cwq, struct work_struct *work);
int queue_delayed_work(struct workqueue_struct *wq,
                        struct work_struct *work, unsigned long delay);
void cancel_rearming_delayed_workqueue(struct workqueue_struct *wq,
                                       struct work_struct *work);
void flush_workqueue(struct workqueue_struct *wq);

int schedule_work(struct work_struct *work);

#endif /* __LINUX_2_4_COMPAT_WORKQUEUE_H__ */
