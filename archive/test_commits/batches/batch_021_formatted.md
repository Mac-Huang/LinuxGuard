# Linux Kernel Commit Batch Analysis

## Commit 1: 97d8e8e5

**Author:** David Howells
**Date:** 2025-07-01 22:37:13
**Files Changed:** fs/netfs/write_retry.c

**Message:**
```
netfs: Fix ref leak on inserted extra subreq in write retry

The write-retry algorithm will insert extra subrequests into the list if it
can't get sufficient capacity to split the range that needs to be retried
into the sequence of subrequests it currently has (for instance, if the
cifs credit pool has fewer credits available than it did when the range was
originally divided).

However, the allocator furnishes each new subreq with 2 refs and then
another is added for resubmission, causing one to be leaked.

Fix this by replacing the ref-getting line with a neutral trace line.

Fixes: 288ace2f57c9 ("netfs: New writeback implementation")
Signed-off-by: David Howells <dhowells@redhat.com>
Link: https://lore.kernel.org/20250701163852.2171681-6-dhowells@redhat.com
Tested-by: Steve French <sfrench@samba.org>
Reviewed-by: Paulo Alcantara <pc@manguebit.org>
cc: netfs@lists.linux.dev
cc: linux-fsdevel@vger.kernel.org
Signed-off-by: Christian Brauner <brauner@kernel.org>
```

**Diff:**
```diff
diff --git a/fs/netfs/write_retry.c b/fs/netfs/write_retry.c
index 9d1d8a8bab72..7158657061e9 100644
--- a/fs/netfs/write_retry.c
+++ b/fs/netfs/write_retry.c
@@ -153,7 +153,7 @@ static void netfs_retry_write_stream(struct netfs_io_request *wreq,
 			trace_netfs_sreq_ref(wreq->debug_id, subreq->debug_index,
 					     refcount_read(&subreq->ref),
 					     netfs_sreq_trace_new);
-			netfs_get_subrequest(subreq, netfs_sreq_trace_get_resubmit);
+			trace_netfs_sreq(subreq, netfs_sreq_trace_split);
 
 			list_add(&subreq->rreq_link, &to->rreq_link);
 			to = list_next_entry(to, rreq_link);
```

---

## Commit 2: 8c44dac8

**Author:** Nam Cao
**Date:** 2025-07-01 22:31:51
**Files Changed:** fs/eventpoll.c

**Message:**
```
eventpoll: Fix priority inversion problem

The ready event list of an epoll object is protected by read-write
semaphore:

  - The consumer (waiter) acquires the write lock and takes items.
  - the producer (waker) takes the read lock and adds items.

The point of this design is enabling epoll to scale well with large number
of producers, as multiple producers can hold the read lock at the same
time.

Unfortunately, this implementation may cause scheduling priority inversion
problem. Suppose the consumer has higher scheduling priority than the
producer. The consumer needs to acquire the write lock, but may be blocked
by the producer holding the read lock. Since read-write semaphore does not
support priority-boosting for the readers (even with CONFIG_PREEMPT_RT=y),
we have a case of priority inversion: a higher priority consumer is blocked
by a lower priority producer. This problem was reported in [1].

Furthermore, this could also cause stall problem, as described in [2].

To fix this problem, make the event list half-lockless:

  - The consumer acquires a mutex (ep->mtx) and takes items.
  - The producer locklessly adds items to the list.

Performance is not the main goal of this patch, but as the producer now can
add items without waiting for consumer to release the lock, performance
improvement is observed using the stress test from
https://github.com/rouming/test-tools/blob/master/stress-epoll.c. This is
the same test that justified using read-write semaphore in the past.

Testing using 12 x86_64 CPUs:

          Before     After        Diff
threads  events/ms  events/ms
      8       6932      19753    +185%
     16       7820      27923    +257%
     32       7648      35164    +360%
     64       9677      37780    +290%
    128      11166      38174    +242%

Testing using 1 riscv64 CPU (averaged over 10 runs, as the numbers are
noisy):

          Before     After        Diff
threads  events/ms  events/ms
      1         73        129     +77%
      2        151        216     +43%
      4        216        364     +69%
      8        234        382     +63%
     16        251        392     +56%

Reported-by: Frederic Weisbecker <frederic@kernel.org>
Closes: https://lore.kernel.org/linux-rt-users/20210825132754.GA895675@lothringen/ [1]
Reported-by: Valentin Schneider <vschneid@redhat.com>
Closes: https://lore.kernel.org/linux-rt-users/xhsmhttqvnall.mognet@vschneid.remote.csb/ [2]
Signed-off-by: Nam Cao <namcao@linutronix.de>
Link: https://lore.kernel.org/20250527090836.1290532-1-namcao@linutronix.de
Tested-by: K Prateek Nayak <kprateek.nayak@amd.com>
Acked-by: Frederic Weisbecker <frederic@kernel.org>
Signed-off-by: Christian Brauner <brauner@kernel.org>
```

**Diff:**
```diff
diff --git a/fs/eventpoll.c b/fs/eventpoll.c
index d4dbffdedd08..a97a771a459c 100644
--- a/fs/eventpoll.c
+++ b/fs/eventpoll.c
@@ -137,13 +137,7 @@ struct epitem {
 	};
 
 	/* List header used to link this structure to the eventpoll ready list */
-	struct list_head rdllink;
-
-	/*
-	 * Works together "struct eventpoll"->ovflist in keeping the
-	 * single linked chain of items.
-	 */
-	struct epitem *next;
+	struct llist_node rdllink;
 
 	/* The file descriptor information this item refers to */
 	struct epoll_filefd ffd;
@@ -191,22 +185,15 @@ struct eventpoll {
 	/* Wait queue used by file->poll() */
 	wait_queue_head_t poll_wait;
 
-	/* List of ready file descriptors */
-	struct list_head rdllist;
-
-	/* Lock which protects rdllist and ovflist */
-	rwlock_t lock;
+	/*
+	 * List of ready file descriptors. Adding to this list is lockless. Items can be removed
+	 * only with eventpoll::mtx
+	 */
+	struct llist_head rdllist;
 
 	/* RB tree root used to store monitored fd structs */
 	struct rb_root_cached rbr;
 
-	/*
-	 * This is a single linked list that chains all the "struct epitem" that
-	 * happened while transferring ready events to userspace w/out
-	 * holding ->lock.
-	 */
-	struct epitem *ovflist;
-
 	/* wakeup_source used when ep_send_events or __ep_eventpoll_poll is running */
 	struct wakeup_source *ws;
 
@@ -361,10 +348,14 @@ static inline int ep_cmp_ffd(struct epoll_filefd *p1,
 	        (p1->file < p2->file ? -1 : p1->fd - p2->fd));
 }

... (truncated 677 lines)
```

---

## Commit 3: 0d519bb0

**Author:** Yu Kuai
**Date:** 2025-07-01 08:14:01
**Files Changed:** drivers/block/brd.c

**Message:**
```
brd: fix sleeping function called from invalid context in brd_insert_page()

__xa_cmpxchg() is called with rcu_read_lock(), and it will allocate
memory if necessary.

Fix the problem by moving rcu_read_lock() after __xa_cmpxchg(), meanwhile,
it still should be held before xa_unlock(), prevent returned page to be
freed by concurrent discard.

Fixes: bbcacab2e8ee ("brd: avoid extra xarray lookups on first write")
Reported-by: syzbot+ea4c8fd177a47338881a@syzkaller.appspotmail.com
Closes: https://lore.kernel.org/all/685ec4c9.a00a0220.129264.000c.GAE@google.com/
Signed-off-by: Yu Kuai <yukuai3@huawei.com>
Reviewed-by: Christoph Hellwig <hch@lst.de>
Link: https://lore.kernel.org/r/20250630112828.421219-1-yukuai1@huaweicloud.com
Signed-off-by: Jens Axboe <axboe@kernel.dk>
```

**Diff:**
```diff
diff --git a/drivers/block/brd.c b/drivers/block/brd.c
index b1be6c510372..0c2eabe14af3 100644
--- a/drivers/block/brd.c
+++ b/drivers/block/brd.c
@@ -64,13 +64,15 @@ static struct page *brd_insert_page(struct brd_device *brd, sector_t sector,
 
 	rcu_read_unlock();
 	page = alloc_page(gfp | __GFP_ZERO | __GFP_HIGHMEM);
-	rcu_read_lock();
-	if (!page)
+	if (!page) {
+		rcu_read_lock();
 		return ERR_PTR(-ENOMEM);
+	}
 
 	xa_lock(&brd->brd_pages);
 	ret = __xa_cmpxchg(&brd->brd_pages, sector >> PAGE_SECTORS_SHIFT, NULL,
 			page, gfp);
+	rcu_read_lock();
 	if (ret) {
 		xa_unlock(&brd->brd_pages);
 		__free_page(page);
```

---

## Commit 4: 009836b4

**Author:** Peter Zijlstra
**Date:** 2025-07-01 15:02:03
**Files Changed:** kernel/sched/core.c, kernel/stop_machine.c

**Message:**
```
sched/core: Fix migrate_swap() vs. hotplug

On Mon, Jun 02, 2025 at 03:22:13PM +0800, Kuyo Chang wrote:

> So, the potential race scenario is:
>
> 	CPU0							CPU1
> 	// doing migrate_swap(cpu0/cpu1)
> 	stop_two_cpus()
> 							  ...
> 							 // doing _cpu_down()
> 							      sched_cpu_deactivate()
> 								set_cpu_active(cpu, false);
> 								balance_push_set(cpu, true);
> 	cpu_stop_queue_two_works
> 	    __cpu_stop_queue_work(stopper1,...);
> 	    __cpu_stop_queue_work(stopper2,..);
> 	stop_cpus_in_progress -> true
> 		preempt_enable();
> 								...
> 							1st balance_push
> 							stop_one_cpu_nowait
> 							cpu_stop_queue_work
> 							__cpu_stop_queue_work
> 							list_add_tail  -> 1st add push_work
> 							wake_up_q(&wakeq);  -> "wakeq is empty.
> 										This implies that the stopper is at wakeq@migrate_swap."
> 	preempt_disable
> 	wake_up_q(&wakeq);
> 	        wake_up_process // wakeup migrate/0
> 		    try_to_wake_up
> 		        ttwu_queue
> 		            ttwu_queue_cond ->meet below case
> 		                if (cpu == smp_processor_id())
> 			         return false;
> 			ttwu_do_activate
> 			//migrate/0 wakeup done
> 		wake_up_process // wakeup migrate/1
> 	           try_to_wake_up
> 		    ttwu_queue
> 			ttwu_queue_cond
> 		        ttwu_queue_wakelist
> 			__ttwu_queue_wakelist
> 			__smp_call_single_queue
> 	preempt_enable();
>
> 							2nd balance_push
> 							stop_one_cpu_nowait
> 							cpu_stop_queue_work
> 							__cpu_stop_queue_work
> 							list_add_tail  -> 2nd add push_work, so the double list add is detected
> 							...
> 							...
> 							cpu1 get ipi, do sched_ttwu_pending, wakeup migrate/1
>

So this balance_push() is part of schedule(), and schedule() is supposed
to switch to stopper task, but because of this race condition, stopper
task is stuck in WAKING state and not actually visible to be picked.

Therefore CPU1 can do another schedule() and end up doing another
balance_push() even though the last one hasn't been done yet.

This is a confluence of fail, where both wake_q and ttwu_wakelist can
cause crucial wakeups to be delayed, resulting in the malfunction of
balance_push.

Since there is only a single stopper thread to be woken, the wake_q
doesn't really add anything here, and can be removed in favour of
direct wakeups of the stopper thread.

Then add a clause to ttwu_queue_cond() to ensure the stopper threads
are never queued / delayed.

Of all 3 moving parts, the last addition was the balance_push()
machinery, so pick that as the point the bug was introduced.

Fixes: 2558aacff858 ("sched/hotplug: Ensure only per-cpu kthreads run during hotplug")
Reported-by: Kuyo Chang <kuyo.chang@mediatek.com>
Signed-off-by: Peter Zijlstra (Intel) <peterz@infradead.org>
Tested-by: Kuyo Chang <kuyo.chang@mediatek.com>
Link: https://lkml.kernel.org/r/20250605100009.GO39944@noisy.programming.kicks-ass.net
```

**Diff:**
```diff
diff --git a/kernel/sched/core.c b/kernel/sched/core.c
index cd80b66a960a..ec68fc686bd7 100644
--- a/kernel/sched/core.c
+++ b/kernel/sched/core.c
@@ -3943,6 +3943,11 @@ static inline bool ttwu_queue_cond(struct task_struct *p, int cpu)
 	if (!scx_allow_ttwu_queue(p))
 		return false;
 
+#ifdef CONFIG_SMP
+	if (p->sched_class == &stop_sched_class)
+		return false;
+#endif
+
 	/*
 	 * Do not complicate things with the async wake_list while the CPU is
 	 * in hotplug state.
diff --git a/kernel/stop_machine.c b/kernel/stop_machine.c
index 5d2d0562115b..3fe6b0c99f3d 100644
--- a/kernel/stop_machine.c
+++ b/kernel/stop_machine.c
@@ -82,18 +82,15 @@ static void cpu_stop_signal_done(struct cpu_stop_done *done)
 }
 
 static void __cpu_stop_queue_work(struct cpu_stopper *stopper,
-					struct cpu_stop_work *work,
-					struct wake_q_head *wakeq)
+				  struct cpu_stop_work *work)
 {
 	list_add_tail(&work->list, &stopper->works);
-	wake_q_add(wakeq, stopper->thread);
 }
 
 /* queue @work to @stopper.  if offline, @work is completed immediately */
 static bool cpu_stop_queue_work(unsigned int cpu, struct cpu_stop_work *work)
 {
 	struct cpu_stopper *stopper = &per_cpu(cpu_stopper, cpu);
-	DEFINE_WAKE_Q(wakeq);
 	unsigned long flags;
 	bool enabled;
 
@@ -101,12 +98,13 @@ static bool cpu_stop_queue_work(unsigned int cpu, struct cpu_stop_work *work)
 	raw_spin_lock_irqsave(&stopper->lock, flags);
 	enabled = stopper->enabled;
 	if (enabled)
-		__cpu_stop_queue_work(stopper, work, &wakeq);
+		__cpu_stop_queue_work(stopper, work);
 	else if (work->done)
 		cpu_stop_signal_done(work->done);
 	raw_spin_unlock_irqrestore(&stopper->lock, flags);
 

... (truncated 37 lines)
```

---

## Commit 5: d6811074

**Author:** Geliang Tang
**Date:** 2025-07-01 08:17:02
**Files Changed:** drivers/nvme/host/multipath.c

**Message:**
```
nvme-multipath: fix suspicious RCU usage warning

When I run the NVME over TCP test in virtme-ng, I get the following
"suspicious RCU usage" warning in nvme_mpath_add_sysfs_link():

'''
[    5.024557][   T44] nvmet: Created nvm controller 1 for subsystem nqn.2025-06.org.nvmexpress.mptcp for NQN nqn.2014-08.org.nvmexpress:uuid:f7f6b5e0-ff97-4894-98ac-c85309e0bc77.
[    5.027401][  T183] nvme nvme0: creating 2 I/O queues.
[    5.029017][  T183] nvme nvme0: mapped 2/0/0 default/read/poll queues.
[    5.032587][  T183] nvme nvme0: new ctrl: NQN "nqn.2025-06.org.nvmexpress.mptcp", addr 127.0.0.1:4420, hostnqn: nqn.2014-08.org.nvmexpress:uuid:f7f6b5e0-ff97-4894-98ac-c85309e0bc77
[    5.042214][   T25]
[    5.042440][   T25] =============================
[    5.042579][   T25] WARNING: suspicious RCU usage
[    5.042705][   T25] 6.16.0-rc3+ #23 Not tainted
[    5.042812][   T25] -----------------------------
[    5.042934][   T25] drivers/nvme/host/multipath.c:1203 RCU-list traversed in non-reader section!!
[    5.043111][   T25]
[    5.043111][   T25] other info that might help us debug this:
[    5.043111][   T25]
[    5.043341][   T25]
[    5.043341][   T25] rcu_scheduler_active = 2, debug_locks = 1
[    5.043502][   T25] 3 locks held by kworker/u9:0/25:
[    5.043615][   T25]  #0: ffff888008730948 ((wq_completion)async){+.+.}-{0:0}, at: process_one_work+0x7ed/0x1350
[    5.043830][   T25]  #1: ffffc900001afd40 ((work_completion)(&entry->work)){+.+.}-{0:0}, at: process_one_work+0xcf3/0x1350
[    5.044084][   T25]  #2: ffff888013ee0020 (&head->srcu){.+.+}-{0:0}, at: nvme_mpath_add_sysfs_link.part.0+0xb4/0x3a0
[    5.044300][   T25]
[    5.044300][   T25] stack backtrace:
[    5.044439][   T25] CPU: 0 UID: 0 PID: 25 Comm: kworker/u9:0 Not tainted 6.16.0-rc3+ #23 PREEMPT(full)
[    5.044441][   T25] Hardware name: Bochs Bochs, BIOS Bochs 01/01/2011
[    5.044442][   T25] Workqueue: async async_run_entry_fn
[    5.044445][   T25] Call Trace:
[    5.044446][   T25]  <TASK>
[    5.044449][   T25]  dump_stack_lvl+0x6f/0xb0
[    5.044453][   T25]  lockdep_rcu_suspicious.cold+0x4f/0xb1
[    5.044457][   T25]  nvme_mpath_add_sysfs_link.part.0+0x2fb/0x3a0
[    5.044459][   T25]  ? queue_work_on+0x90/0xf0
[    5.044461][   T25]  ? lockdep_hardirqs_on+0x78/0x110
[    5.044466][   T25]  nvme_mpath_set_live+0x1e9/0x4f0
[    5.044470][   T25]  nvme_mpath_add_disk+0x240/0x2f0
[    5.044472][   T25]  ? __pfx_nvme_mpath_add_disk+0x10/0x10
[    5.044475][   T25]  ? add_disk_fwnode+0x361/0x580
[    5.044480][   T25]  nvme_alloc_ns+0x81c/0x17c0
[    5.044483][   T25]  ? kasan_quarantine_put+0x104/0x240
[    5.044487][   T25]  ? __pfx_nvme_alloc_ns+0x10/0x10
[    5.044495][   T25]  ? __pfx_nvme_find_get_ns+0x10/0x10
[    5.044496][   T25]  ? rcu_read_lock_any_held+0x45/0xa0
[    5.044498][   T25]  ? validate_chain+0x232/0x4f0
[    5.044503][   T25]  nvme_scan_ns+0x4c8/0x810
[    5.044506][   T25]  ? __pfx_nvme_scan_ns+0x10/0x10
[    5.044508][   T25]  ? find_held_lock+0x2b/0x80
[    5.044512][   T25]  ? ktime_get+0x16d/0x220
[    5.044517][   T25]  ? kvm_clock_get_cycles+0x18/0x30
[    5.044520][   T25]  ? __pfx_nvme_scan_ns_async+0x10/0x10
[    5.044522][   T25]  async_run_entry_fn+0x97/0x560
[    5.044523][   T25]  ? rcu_is_watching+0x12/0xc0
[    5.044526][   T25]  process_one_work+0xd3c/0x1350
[    5.044532][   T25]  ? __pfx_process_one_work+0x10/0x10
[    5.044536][   T25]  ? assign_work+0x16c/0x240
[    5.044539][   T25]  worker_thread+0x4da/0xd50
[    5.044545][   T25]  ? __pfx_worker_thread+0x10/0x10
[    5.044546][   T25]  kthread+0x356/0x5c0
[    5.044548][   T25]  ? __pfx_kthread+0x10/0x10
[    5.044549][   T25]  ? ret_from_fork+0x1b/0x2e0
[    5.044552][   T25]  ? __lock_release.isra.0+0x5d/0x180
[    5.044553][   T25]  ? ret_from_fork+0x1b/0x2e0
[    5.044555][   T25]  ? rcu_is_watching+0x12/0xc0
[    5.044557][   T25]  ? __pfx_kthread+0x10/0x10
[    5.044559][   T25]  ret_from_fork+0x218/0x2e0
[    5.044561][   T25]  ? __pfx_kthread+0x10/0x10
[    5.044562][   T25]  ret_from_fork_asm+0x1a/0x30
[    5.044570][   T25]  </TASK>
'''

This patch uses sleepable RCU version of helper list_for_each_entry_srcu()
instead of list_for_each_entry_rcu() to fix it.

Fixes: 4dbd2b2ebe4c ("nvme-multipath: Add visibility for round-robin io-policy")
Signed-off-by: Geliang Tang <tanggeliang@kylinos.cn>
Reviewed-by: Keith Busch <kbusch@kernel.org>
Reviewed-by: Hannes Reinecke <hare@suse.de>
Reviewed-by: Nilay Shroff <nilay@linux.ibm.com>
Signed-off-by: Christoph Hellwig <hch@lst.de>
```

**Diff:**
```diff
diff --git a/drivers/nvme/host/multipath.c b/drivers/nvme/host/multipath.c
index e03f3a29bd75..5d1ad28986e9 100644
--- a/drivers/nvme/host/multipath.c
+++ b/drivers/nvme/host/multipath.c
@@ -1200,7 +1200,8 @@ void nvme_mpath_add_sysfs_link(struct nvme_ns_head *head)
 	 */
 	srcu_idx = srcu_read_lock(&head->srcu);
 
-	list_for_each_entry_rcu(ns, &head->list, siblings) {
+	list_for_each_entry_srcu(ns, &head->list, siblings,
+				 srcu_read_lock_held(&head->srcu)) {
 		/*
 		 * Ensure that ns path disk node is already added otherwise we
 		 * may get invalid kobj name for target
```

---

