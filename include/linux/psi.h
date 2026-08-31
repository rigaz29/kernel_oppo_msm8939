#ifndef _LINUX_PSI_H
#define _LINUX_PSI_H

#include <linux/psi_types.h>
#include <linux/sched.h>
#include <linux/poll.h>

/*
 * Diadaptasi dari acroreiser/android_kernel_lenovo_a6010 (kernel 3.10.108 yang
 * sama) dengan dua penyesuaian:
 *
 *  1. DUKUNGAN CGROUP DIBUANG. PSI hulu terikat cgroup v2 -- ia memakai
 *     cgroup_psi(), cgroup_parent(), dan <linux/cgroup-defs.h>, tak satu pun
 *     ada di 3.10 ini (cgroup kita masih v1, dan cgroup-defs.h baru muncul di
 *     4.2). Yang dibutuhkan lmkd hanyalah berkas tingkat sistem di
 *     /proc/pressure/*, bukan tekanan per-cgroup. Lihat PLAN-PSI-EBPF.md §2:
 *     "PSI tanpa cgroup".
 *
 *  2. static_key -> bool biasa. psi_disabled memakai DEFINE_STATIC_KEY_FALSE
 *     dan static_branch_likely(), API jump_label gaya 4.3 yang belum ada di
 *     sini. Membawa jump_label baru berarti menyentuh kode arch; menggantinya
 *     dengan bool hanya menukar lompatan yang ditambal dengan satu pembacaan
 *     memori -- dan pembacaan itu terjadi pada jalur yang memang sudah
 *     memegang rq->lock.
 */

struct seq_file;

#ifdef CONFIG_PSI

extern bool psi_disabled;

void psi_task_change(struct task_struct *task, int clear, int set);

void psi_memstall_tick(struct task_struct *task, int cpu);
void psi_memstall_enter(unsigned long *flags);
void psi_memstall_leave(unsigned long *flags);

int psi_show(struct seq_file *s, struct psi_group *group, enum psi_res res);

struct psi_trigger *psi_trigger_create(struct psi_group *group,
			char *buf, size_t nbytes, enum psi_res res);
void psi_trigger_destroy(struct psi_trigger *t);

unsigned int psi_trigger_poll(void **trigger_ptr, struct file *file,
			      poll_table *wait);

#else /* CONFIG_PSI */

static inline void psi_memstall_enter(unsigned long *flags) {}
static inline void psi_memstall_leave(unsigned long *flags) {}

#endif /* CONFIG_PSI */

#endif /* _LINUX_PSI_H */
