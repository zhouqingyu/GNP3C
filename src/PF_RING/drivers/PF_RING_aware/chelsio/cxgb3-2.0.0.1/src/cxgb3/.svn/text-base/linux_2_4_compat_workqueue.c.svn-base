/*
 * Copyright (c) 2003-2009 Chelsio, Inc. All rights reserved.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the LICENSE file included in this
 * release for licensing terms and conditions.
 */

#include <linux/kernel.h>
#include <linux/workqueue.h>

#include "osdep.h"
#include "linux_2_4_compat_workqueue.h"

#include <linux/mm.h>
#include <linux/spinlock.h>
#include <linux/wait.h>
#include <linux/sched.h>
#include <linux/completion.h>
#include <asm/semaphore.h>

extern struct workqueue_struct *cxgb3_wq;

struct workqueue_struct {
        spinlock_t lock;

        long remove_sequence;   /* Least-recently added (next to run) */
        long insert_sequence;   /* Next to add */

        struct list_head worklist;
        wait_queue_head_t more_work;
        wait_queue_head_t work_done;

        struct workqueue_struct *wq;
        struct task_struct *thread;
	struct completion th_exit;

        int run_depth;          /* Detect run_workqueue() recursion depth */
        const char *name;
} ____cacheline_aligned;

static struct semaphore workqueue_mutex = __MUTEX_INITIALIZER(workqueue_mutex);

static void run_workqueue(struct workqueue_struct *cwq)
{
        unsigned long flags;

        /*
         * Keep taking off work from the queue until
         * done.
         */
        spin_lock_irqsave(&cwq->lock, flags);
        cwq->run_depth++;
        if (cwq->run_depth > 3) {
                /* morton gets to eat his hat */
                printk("%s: recursion depth exceeded: %d\n",
                        __FUNCTION__, cwq->run_depth);
                dump_stack();
        }

        while (!list_empty(&cwq->worklist)) {
                struct work_struct *work = list_entry(cwq->worklist.next,
                                                struct work_struct, entry);
                void (*f) (void *) = work->func;
                void *data = work->data;

                list_del_init(cwq->worklist.next);
                spin_unlock_irqrestore(&cwq->lock, flags);

                BUG_ON(work->wq_data != cwq);
                clear_bit(0, &work->pending);
                f(data);

                spin_lock_irqsave(&cwq->lock, flags);
                cwq->remove_sequence++;
                wake_up(&cwq->work_done);
        }
        cwq->run_depth--;
        spin_unlock_irqrestore(&cwq->lock, flags);
}

static int worker_thread(void *__cwq)
{
        struct workqueue_struct *cwq = __cwq;
        DECLARE_WAITQUEUE(wait, current);

	cwq->thread = current;

        daemonize();
        reparent_to_init();
	sprintf(current->comm, cwq->name);

	sigdelset(&current->blocked, SIGTERM);
        flush_signals(current);

        set_current_state(TASK_INTERRUPTIBLE);
	init_waitqueue_entry(&wait, current);
	add_wait_queue(&cwq->more_work, &wait);
        while (1) {
		if (signal_pending(current))
			break;

                if (list_empty(&cwq->worklist))
			schedule();
		else
                        __set_current_state(TASK_RUNNING);


                if (!list_empty(&cwq->worklist))
                        run_workqueue(cwq);
                set_current_state(TASK_INTERRUPTIBLE);
        }

        __set_current_state(TASK_RUNNING);
	remove_wait_queue(&cwq->more_work, &wait);

        complete_and_exit(&cwq->th_exit, 0);
	return 0;
}

static int create_workqueue_thread(struct workqueue_struct *cwq)
{
        spin_lock_init(&cwq->lock);
        cwq->thread = NULL;
        cwq->insert_sequence = 0;
        cwq->remove_sequence = 0;
        INIT_LIST_HEAD(&cwq->worklist);
        init_waitqueue_head(&cwq->more_work);
        init_waitqueue_head(&cwq->work_done);
	init_completion (&cwq->th_exit);
	if (kernel_thread(worker_thread, (void *) (long) cwq,
			  CLONE_FS | CLONE_FILES) < 0)
                return 0;

        return 1;
}

struct workqueue_struct * create_singlethread_workqueue(const char *name)
{
        struct workqueue_struct *wq;

        wq = kzalloc(sizeof(*wq), GFP_KERNEL);
        if (!wq)
                return NULL;

        wq->name = name;
        mutex_lock(&workqueue_mutex);

	if (create_workqueue_thread(wq) == 0) {
		kfree(wq);
		wq = NULL;
	}

        mutex_unlock(&workqueue_mutex);

        return wq;
}

static void cleanup_workqueue_thread(struct workqueue_struct *cwq)
{
        unsigned long flags;
        struct task_struct *p;

        spin_lock_irqsave(&cwq->lock, flags);
        p = cwq->thread;
        cwq->thread = NULL;
        spin_unlock_irqrestore(&cwq->lock, flags);
        if (p)
                send_sig(SIGTERM, p, 0);

	wait_for_completion(&cwq->th_exit);
}

void destroy_workqueue(struct workqueue_struct *wq)
{
        flush_workqueue(wq);

        mutex_lock(&workqueue_mutex);
	cleanup_workqueue_thread(wq);
        mutex_unlock(&workqueue_mutex);
        kfree(wq);
}

static void flush_cpu_workqueue(struct workqueue_struct *cwq)
{
        if (cwq->thread == current) {
                run_workqueue(cwq);
        } else {
		wait_queue_t __wait;
                long sequence_needed;
		unsigned long flags;

		init_waitqueue_entry(&__wait, current);

                spin_lock_irqsave(&cwq->lock, flags);
                sequence_needed = cwq->insert_sequence;

		init_waitqueue_entry(&__wait, current);
		add_wait_queue(&cwq->work_done, &__wait);
                while (sequence_needed - cwq->remove_sequence > 0) {
                        spin_unlock_irqrestore(&cwq->lock, flags);
			schedule();
                        spin_lock_irqsave(&cwq->lock, flags);
                }
		remove_wait_queue(&cwq->work_done, &__wait);
                spin_unlock_irqrestore(&cwq->lock, flags);
        }
}

void flush_workqueue(struct workqueue_struct *wq)
{
        cond_resched();
	flush_cpu_workqueue(wq);
}

static void __queue_work(struct workqueue_struct *cwq, struct work_struct *work)
{
        unsigned long flags;

        spin_lock_irqsave(&cwq->lock, flags);
        work->wq_data = cwq;
        list_add_tail(&work->entry, &cwq->worklist);
        cwq->insert_sequence++;
        wake_up(&cwq->more_work);
        spin_unlock_irqrestore(&cwq->lock, flags);
}

int queue_work(struct workqueue_struct *cwq, struct work_struct *work)
{
        int ret = 0;

        if (!test_and_set_bit(0, &work->pending)) {
                BUG_ON(!list_empty(&work->entry));
                __queue_work(cwq, work);
                ret = 1;
        }
        return ret;
}

int schedule_work(struct work_struct *work)
{
        return queue_work(cxgb3_wq, work);
}

static void delayed_work_timer_fn(unsigned long __data)
{
        struct work_struct *work = (struct work_struct *)__data;
        struct workqueue_struct *wq = work->wq_data;

        __queue_work(wq, work);
}

int queue_delayed_work(struct workqueue_struct *wq,
                        struct work_struct *work, unsigned long delay)
{
        int ret = 0;
        struct timer_list *timer = &work->timer;

        if (!test_and_set_bit(0, &work->pending)) {
                BUG_ON(timer_pending(timer));
                BUG_ON(!list_empty(&work->entry));

                /* This stores wq for the moment, for the timer_fn */
                work->wq_data = wq;
                timer->expires = jiffies + delay;
                timer->data = (unsigned long)work;
                timer->function = delayed_work_timer_fn;
                add_timer(timer);
                ret = 1;
        }
        return ret;
}

static int cancel_delayed_work(struct work_struct *work)
{
        int ret;

        ret = del_timer_sync(&work->timer);
        if (ret)
                clear_bit(0, &work->pending);
        return ret;
}

void cancel_rearming_delayed_workqueue(struct workqueue_struct *wq,
                                       struct work_struct *work)
{
        while (!cancel_delayed_work(work))
                flush_workqueue(wq);
}
