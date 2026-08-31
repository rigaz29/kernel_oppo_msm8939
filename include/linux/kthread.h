#ifndef _LINUX_KTHREAD_H
#define _LINUX_KTHREAD_H
/* Simple interface for creating and stopping kernel threads without mess. */
#include <linux/err.h>
#include <linux/timer.h>
#include <linux/sched.h>

__printf(4, 5)
struct task_struct *kthread_create_on_node(int (*threadfn)(void *data),
					   void *data,
					   int node,
					   const char namefmt[], ...);

#define kthread_create(threadfn, data, namefmt, arg...) \
	kthread_create_on_node(threadfn, data, -1, namefmt, ##arg)


struct task_struct *kthread_create_on_cpu(int (*threadfn)(void *data),
					  void *data,
					  unsigned int cpu,
					  const char *namefmt);

/**
 * kthread_run - create and wake a thread.
 * @threadfn: the function to run until signal_pending(current).
 * @data: data ptr for @threadfn.
 * @namefmt: printf-style name for the thread.
 *
 * Description: Convenient wrapper for kthread_create() followed by
 * wake_up_process().  Returns the kthread or ERR_PTR(-ENOMEM).
 */
#define kthread_run(threadfn, data, namefmt, ...)			   \
({									   \
	struct task_struct *__k						   \
		= kthread_create(threadfn, data, namefmt, ## __VA_ARGS__); \
	if (!IS_ERR(__k))						   \
		wake_up_process(__k);					   \
	__k;								   \
})

void kthread_bind(struct task_struct *k, unsigned int cpu);
int kthread_stop(struct task_struct *k);
bool kthread_should_stop(void);
bool kthread_should_park(void);
bool kthread_freezable_should_stop(bool *was_frozen);
void *kthread_data(struct task_struct *k);
void *probe_kthread_data(struct task_struct *k);
int kthread_park(struct task_struct *k);
void kthread_unpark(struct task_struct *k);
void kthread_parkme(void);

int kthreadd(void *unused);
extern struct task_struct *kthreadd_task;
extern int tsk_fork_get_node(struct task_struct *tsk);

/*
 * Simple work processor based on kthread.
 *
 * This provides easier way to make use of kthreads.  A kthread_work
 * can be queued and flushed using queue/flush_kthread_work()
 * respectively.  Queued kthread_works are processed by a kthread
 * running kthread_worker_fn().
 */
struct kthread_work;
typedef void (*kthread_work_func_t)(struct kthread_work *work);

struct kthread_worker {
	spinlock_t		lock;
	struct list_head	work_list;
	struct task_struct	*task;
	struct kthread_work	*current_work;
};

struct kthread_work {
	struct list_head	node;
	kthread_work_func_t	func;
	wait_queue_head_t	done;
	struct kthread_worker	*worker;
};

#define KTHREAD_WORKER_INIT(worker)	{				\
	.lock = __SPIN_LOCK_UNLOCKED((worker).lock),			\
	.work_list = LIST_HEAD_INIT((worker).work_list),		\
	}

#define KTHREAD_WORK_INIT(work, fn)	{				\
	.node = LIST_HEAD_INIT((work).node),				\
	.func = (fn),							\
	.done = __WAIT_QUEUE_HEAD_INITIALIZER((work).done),		\
	}

#define DEFINE_KTHREAD_WORKER(worker)					\
	struct kthread_worker worker = KTHREAD_WORKER_INIT(worker)

#define DEFINE_KTHREAD_WORK(work, fn)					\
	struct kthread_work work = KTHREAD_WORK_INIT(work, fn)

/*
 * kthread_worker.lock and kthread_work.done need their own lockdep class
 * keys if they are defined on stack with lockdep enabled.  Use the
 * following macros when defining them on stack.
 */
#ifdef CONFIG_LOCKDEP
# define KTHREAD_WORKER_INIT_ONSTACK(worker)				\
	({ init_kthread_worker(&worker); worker; })
# define DEFINE_KTHREAD_WORKER_ONSTACK(worker)				\
	struct kthread_worker worker = KTHREAD_WORKER_INIT_ONSTACK(worker)
# define KTHREAD_WORK_INIT_ONSTACK(work, fn)				\
	({ init_kthread_work((&work), fn); work; })
# define DEFINE_KTHREAD_WORK_ONSTACK(work, fn)				\
	struct kthread_work work = KTHREAD_WORK_INIT_ONSTACK(work, fn)
#else
# define DEFINE_KTHREAD_WORKER_ONSTACK(worker) DEFINE_KTHREAD_WORKER(worker)
# define DEFINE_KTHREAD_WORK_ONSTACK(work, fn) DEFINE_KTHREAD_WORK(work, fn)
#endif

extern void __init_kthread_worker(struct kthread_worker *worker,
			const char *name, struct lock_class_key *key);

#define init_kthread_worker(worker)					\
	do {								\
		static struct lock_class_key __key;			\
		__init_kthread_worker((worker), "("#worker")->lock", &__key); \
	} while (0)

#define init_kthread_work(work, fn)					\
	do {								\
		memset((work), 0, sizeof(struct kthread_work));		\
		INIT_LIST_HEAD(&(work)->node);				\
		(work)->func = (fn);					\
		init_waitqueue_head(&(work)->done);			\
	} while (0)

int kthread_worker_fn(void *worker_ptr);

bool queue_kthread_work(struct kthread_worker *worker,
			struct kthread_work *work);

/*
 * --- kthread_work bertunda: lapisan tipis di atas primitif 3.10 ---
 *
 * fs/crypto bukan satu-satunya yang perlu dibawa maju: PSI
 * (kernel/sched/psi.c) memakai API kthread worker gaya 4.9 --
 * kthread_create_worker(), kthread_queue_delayed_work(), dan kawan-kawan.
 *
 * Mengganti inti kthread_worker ke bentuk 4.9 BUKAN pilihan yang murah di
 * pohon ini: struct-nya tidak kompatibel (4.9 menambah delayed_work_list dan
 * canceling, serta membuang kthread_work.done), dan renamenya menyentuh 11
 * pemakai lama termasuk drivers/gpu/msm/kgsl.c dan adreno_dispatch.c. Itu
 * permukaan risiko yang jauh lebih besar daripada manfaatnya.
 *
 * Jadi yang ditambahkan di sini hanya apa yang benar-benar dibutuhkan, di atas
 * primitif yang sudah ada. Semuanya BARU -- tidak ada satu pun API lama yang
 * berubah nama atau perilaku.
 */
struct kthread_delayed_work {
	struct kthread_work work;
	struct timer_list timer;
	/*
	 * work->worker baru terisi saat pekerjaan benar-benar diantrekan,
	 * sedangkan timer perlu tahu tujuannya sebelum itu.
	 */
	struct kthread_worker *kdw_worker;
};

void kthread_delayed_work_timer_fn(unsigned long __data);

#define kthread_init_delayed_work(dwork, fn)					do {										init_kthread_work(&(dwork)->work, (fn));				init_timer(&(dwork)->timer);						(dwork)->timer.function =							kthread_delayed_work_timer_fn;					(dwork)->timer.data = (unsigned long)(dwork);				(dwork)->kdw_worker = NULL;					} while (0)

/* Nama gaya 4.9 untuk primitif yang sudah ada, supaya psi.c tetap utuh. */
#define kthread_init_work(work, fn)	init_kthread_work(work, fn)
#define kthread_init_worker(worker)	init_kthread_worker(worker)
#define kthread_queue_work(w, work)	queue_kthread_work(w, work)
#define kthread_flush_work(work)	flush_kthread_work(work)
#define kthread_flush_worker(w)		flush_kthread_worker(w)

struct kthread_worker *
kthread_create_worker(unsigned int flags, const char namefmt[], ...);
void kthread_destroy_worker(struct kthread_worker *worker);
bool kthread_queue_delayed_work(struct kthread_worker *worker,
				struct kthread_delayed_work *dwork,
				unsigned long delay);
bool kthread_cancel_delayed_work_sync(struct kthread_delayed_work *dwork);
void flush_kthread_work(struct kthread_work *work);
void flush_kthread_worker(struct kthread_worker *worker);

#endif /* _LINUX_KTHREAD_H */
