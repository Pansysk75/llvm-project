/*
 * z_HPX_util.cpp -- HPX threading routines.
 */

//#include "hpx/threading_base/
#include "hpx/hpx_init.hpp"
#include "hpx/thread.hpp"

// TODO_HPXMP: Remove unnecessary includes.
#include "kmp.h"
#include "kmp_affinity.h"
#include "kmp_i18n.h"
#include "kmp_io.h"
#include "kmp_itt.h"
#include "kmp_wait_release.h"

#include <ntsecapi.h> // UNICODE_STRING
#include <ntstatus.h>
#include <psapi.h>
#ifdef _MSC_VER
#pragma comment(lib, "psapi.lib")
#endif


// TODO_HPXMP: Note to self, all __kmp_win32 functions are internal, so they can 
// be replaced by their hpxmp counterparts (or inlined altogether).

void __kmp_win32_mutex_init(kmp_win32_mutex_t *mx) {
  InitializeCriticalSection(&mx->cs);
#if USE_ITT_BUILD
  __kmp_itt_system_object_created(&mx->cs, "Critical Section");
#endif /* USE_ITT_BUILD */
}

void __kmp_win32_mutex_destroy(kmp_win32_mutex_t *mx) {
  DeleteCriticalSection(&mx->cs);
}

void __kmp_win32_mutex_lock(kmp_win32_mutex_t *mx) {
  EnterCriticalSection(&mx->cs);
}

int __kmp_win32_mutex_trylock(kmp_win32_mutex_t *mx) {
  return TryEnterCriticalSection(&mx->cs);
}

void __kmp_win32_mutex_unlock(kmp_win32_mutex_t *mx) {
  LeaveCriticalSection(&mx->cs);
}

void __kmp_win32_cond_init(kmp_win32_cond_t *cv) {
  cv->waiters_count_ = 0;
  cv->wait_generation_count_ = 0;
  cv->release_count_ = 0;

  /* Initialize the critical section */
  __kmp_win32_mutex_init(&cv->waiters_count_lock_);

  /* Create a manual-reset event. */
  cv->event_ = CreateEvent(NULL, // no security
                           TRUE, // manual-reset
                           FALSE, // non-signaled initially
                           NULL); // unnamed
#if USE_ITT_BUILD
  __kmp_itt_system_object_created(cv->event_, "Event");
#endif /* USE_ITT_BUILD */
}

void __kmp_win32_cond_destroy(kmp_win32_cond_t *cv) {
  __kmp_win32_mutex_destroy(&cv->waiters_count_lock_);
  __kmp_free_handle(cv->event_);
  memset(cv, '\0', sizeof(*cv));
}

/* TODO associate cv with a team instead of a thread so as to optimize
   the case where we wake up a whole team */

template <class C>
static void __kmp_win32_cond_wait(kmp_win32_cond_t *cv, kmp_win32_mutex_t *mx,
                                  kmp_info_t *th, C *flag) {
  int my_generation;
  int last_waiter;

  /* Avoid race conditions */
  __kmp_win32_mutex_lock(&cv->waiters_count_lock_);

  /* Increment count of waiters */
  cv->waiters_count_++;

  /* Store current generation in our activation record. */
  my_generation = cv->wait_generation_count_;

  __kmp_win32_mutex_unlock(&cv->waiters_count_lock_);
  __kmp_win32_mutex_unlock(mx);

  for (;;) {
    int wait_done = 0;
    DWORD res, timeout = 5000; // just tried to quess an appropriate number
    /* Wait until the event is signaled */
    res = WaitForSingleObject(cv->event_, timeout);

    if (res == WAIT_OBJECT_0) {
      // event signaled
      __kmp_win32_mutex_lock(&cv->waiters_count_lock_);
      /* Exit the loop when the <cv->event_> is signaled and there are still
         waiting threads from this <wait_generation> that haven't been released
         from this wait yet. */
      wait_done = (cv->release_count_ > 0) &&
                  (cv->wait_generation_count_ != my_generation);
      __kmp_win32_mutex_unlock(&cv->waiters_count_lock_);
    } else if (res == WAIT_TIMEOUT || res == WAIT_FAILED) {
      // check if the flag and cv counters are in consistent state
      // as MS sent us debug dump whith inconsistent state of data
      __kmp_win32_mutex_lock(mx);
      typename C::flag_t old_f = flag->set_sleeping();
      if (!flag->done_check_val(old_f & ~KMP_BARRIER_SLEEP_STATE)) {
        __kmp_win32_mutex_unlock(mx);
        continue;
      }
      // condition fulfilled, exiting
      flag->unset_sleeping();
      TCW_PTR(th->th.th_sleep_loc, NULL);
      th->th.th_sleep_loc_type = flag_unset;
      KF_TRACE(50, ("__kmp_win32_cond_wait: exiting, condition "
                    "fulfilled: flag's loc(%p): %u\n",
                    flag->get(), (unsigned int)flag->load()));

      __kmp_win32_mutex_lock(&cv->waiters_count_lock_);
      KMP_DEBUG_ASSERT(cv->waiters_count_ > 0);
      cv->release_count_ = cv->waiters_count_;
      cv->wait_generation_count_++;
      wait_done = 1;
      __kmp_win32_mutex_unlock(&cv->waiters_count_lock_);

      __kmp_win32_mutex_unlock(mx);
    }
    /* there used to be a semicolon after the if statement, it looked like a
       bug, so i removed it */
    if (wait_done)
      break;
  }

  __kmp_win32_mutex_lock(mx);
  __kmp_win32_mutex_lock(&cv->waiters_count_lock_);

  cv->waiters_count_--;
  cv->release_count_--;

  last_waiter = (cv->release_count_ == 0);

  __kmp_win32_mutex_unlock(&cv->waiters_count_lock_);

  if (last_waiter) {
    /* We're the last waiter to be notified, so reset the manual event. */
    ResetEvent(cv->event_);
  }
}

void __kmp_win32_cond_broadcast(kmp_win32_cond_t *cv) {
  __kmp_win32_mutex_lock(&cv->waiters_count_lock_);

  if (cv->waiters_count_ > 0) {
    SetEvent(cv->event_);
    /* Release all the threads in this generation. */

    cv->release_count_ = cv->waiters_count_;

    /* Start a new generation. */
    cv->wait_generation_count_++;
  }

  __kmp_win32_mutex_unlock(&cv->waiters_count_lock_);
}

void __kmp_win32_cond_signal(kmp_win32_cond_t *cv) {
  __kmp_win32_cond_broadcast(cv);
}

// HPXMP TODO: Figure out if these need to coordinate with HPX runtime, or 
// if it's ok to let OS do it's thing
#if 0
void __kmp_enable(int new_state) {
  if (__kmp_init_runtime)
    LeaveCriticalSection(&__kmp_win32_section);
}

void __kmp_disable(int *old_state) {
  *old_state = 0;

  if (__kmp_init_runtime)
    EnterCriticalSection(&__kmp_win32_section);
}

void __kmp_suspend_initialize(void) { /* do nothing */
}
# endif

void __kmp_suspend_initialize_thread(kmp_info_t *th) {
  int old_value = KMP_ATOMIC_LD_RLX(&th->th.th_suspend_init);
  int new_value = TRUE;
  // Return if already initialized
  if (old_value == new_value)
    return;
  // Wait, then return if being initialized
  if (old_value == -1 ||
      !__kmp_atomic_compare_store(&th->th.th_suspend_init, old_value, -1)) {
    while (KMP_ATOMIC_LD_ACQ(&th->th.th_suspend_init) != new_value) {
      KMP_CPU_PAUSE();
    }
  } else {
    // Claim to be the initializer and do initializations
    __kmp_win32_cond_init(&th->th.th_suspend_cv);
    __kmp_win32_mutex_init(&th->th.th_suspend_mx);
    KMP_ATOMIC_ST_REL(&th->th.th_suspend_init, new_value);
  }
}

void __kmp_suspend_uninitialize_thread(kmp_info_t *th) {
  if (KMP_ATOMIC_LD_ACQ(&th->th.th_suspend_init)) {
    /* this means we have initialize the suspension pthread objects for this
       thread in this instance of the process */
    __kmp_win32_cond_destroy(&th->th.th_suspend_cv);
    __kmp_win32_mutex_destroy(&th->th.th_suspend_mx);
    KMP_ATOMIC_ST_REL(&th->th.th_suspend_init, FALSE);
  }
}

int __kmp_try_suspend_mx(kmp_info_t *th) {
  return __kmp_win32_mutex_trylock(&th->th.th_suspend_mx);
}

void __kmp_lock_suspend_mx(kmp_info_t *th) {
  __kmp_win32_mutex_lock(&th->th.th_suspend_mx);
}

void __kmp_unlock_suspend_mx(kmp_info_t *th) {
  __kmp_win32_mutex_unlock(&th->th.th_suspend_mx);
}

/* This routine puts the calling thread to sleep after setting the
   sleep bit for the indicated flag variable to true. */
template <class C>
static inline void __kmp_suspend_template(int th_gtid, C *flag) {
  kmp_info_t *th = __kmp_threads[th_gtid];
  typename C::flag_t old_spin;

  KF_TRACE(30, ("__kmp_suspend_template: T#%d enter for flag's loc(%p)\n",
                th_gtid, flag->get()));

  __kmp_suspend_initialize_thread(th);
  __kmp_lock_suspend_mx(th);

  KF_TRACE(10, ("__kmp_suspend_template: T#%d setting sleep bit for flag's"
                " loc(%p)\n",
                th_gtid, flag->get()));

  /* TODO: shouldn't this use release semantics to ensure that
     __kmp_suspend_initialize_thread gets called first? */
  old_spin = flag->set_sleeping();
  TCW_PTR(th->th.th_sleep_loc, (void *)flag);
  th->th.th_sleep_loc_type = flag->get_type();
  if (__kmp_dflt_blocktime == KMP_MAX_BLOCKTIME &&
      __kmp_pause_status != kmp_soft_paused) {
    flag->unset_sleeping();
    TCW_PTR(th->th.th_sleep_loc, NULL);
    th->th.th_sleep_loc_type = flag_unset;
    __kmp_unlock_suspend_mx(th);
    return;
  }

  KF_TRACE(5, ("__kmp_suspend_template: T#%d set sleep bit for flag's"
               " loc(%p)==%u\n",
               th_gtid, flag->get(), (unsigned int)flag->load()));

  if (flag->done_check_val(old_spin) || flag->done_check()) {
    flag->unset_sleeping();
    TCW_PTR(th->th.th_sleep_loc, NULL);
    th->th.th_sleep_loc_type = flag_unset;
    KF_TRACE(5, ("__kmp_suspend_template: T#%d false alarm, reset sleep bit "
                 "for flag's loc(%p)\n",
                 th_gtid, flag->get()));
  } else {
#ifdef DEBUG_SUSPEND
    __kmp_suspend_count++;
#endif
    /* Encapsulate in a loop as the documentation states that this may "with
       low probability" return when the condition variable has not been signaled
       or broadcast */
    int deactivated = FALSE;

    while (flag->is_sleeping()) {
      KF_TRACE(15, ("__kmp_suspend_template: T#%d about to perform "
                    "kmp_win32_cond_wait()\n",
                    th_gtid));
      // Mark the thread as no longer active (only in the first iteration of the
      // loop).
      if (!deactivated) {
        th->th.th_active = FALSE;
        if (th->th.th_active_in_pool) {
          th->th.th_active_in_pool = FALSE;
          KMP_ATOMIC_DEC(&__kmp_thread_pool_active_nth);
          KMP_DEBUG_ASSERT(TCR_4(__kmp_thread_pool_active_nth) >= 0);
        }
        deactivated = TRUE;
      }

      KMP_DEBUG_ASSERT(th->th.th_sleep_loc);
      KMP_DEBUG_ASSERT(th->th.th_sleep_loc_type == flag->get_type());

      __kmp_win32_cond_wait(&th->th.th_suspend_cv, &th->th.th_suspend_mx, th,
                            flag);

#ifdef KMP_DEBUG
      if (flag->is_sleeping()) {
        KF_TRACE(100,
                 ("__kmp_suspend_template: T#%d spurious wakeup\n", th_gtid));
      }
#endif /* KMP_DEBUG */

    } // while

    // We may have had the loop variable set before entering the loop body;
    // so we need to reset sleep_loc.
    TCW_PTR(th->th.th_sleep_loc, NULL);
    th->th.th_sleep_loc_type = flag_unset;

    KMP_DEBUG_ASSERT(!flag->is_sleeping());
    KMP_DEBUG_ASSERT(!th->th.th_sleep_loc);

    // Mark the thread as active again (if it was previous marked as inactive)
    if (deactivated) {
      th->th.th_active = TRUE;
      if (TCR_4(th->th.th_in_pool)) {
        KMP_ATOMIC_INC(&__kmp_thread_pool_active_nth);
        th->th.th_active_in_pool = TRUE;
      }
    }
  }

  __kmp_unlock_suspend_mx(th);
  KF_TRACE(30, ("__kmp_suspend_template: T#%d exit\n", th_gtid));
}

template <bool C, bool S>
void __kmp_suspend_32(int th_gtid, kmp_flag_32<C, S> *flag) {
  __kmp_suspend_template(th_gtid, flag);
}
template <bool C, bool S>
void __kmp_suspend_64(int th_gtid, kmp_flag_64<C, S> *flag) {
  __kmp_suspend_template(th_gtid, flag);
}
template <bool C, bool S>
void __kmp_atomic_suspend_64(int th_gtid, kmp_atomic_flag_64<C, S> *flag) {
  __kmp_suspend_template(th_gtid, flag);
}
void __kmp_suspend_oncore(int th_gtid, kmp_flag_oncore *flag) {
  __kmp_suspend_template(th_gtid, flag);
}

template void __kmp_suspend_32<false, false>(int, kmp_flag_32<false, false> *);
template void __kmp_suspend_64<false, true>(int, kmp_flag_64<false, true> *);
template void __kmp_suspend_64<true, false>(int, kmp_flag_64<true, false> *);
template void
__kmp_atomic_suspend_64<false, true>(int, kmp_atomic_flag_64<false, true> *);
template void
__kmp_atomic_suspend_64<true, false>(int, kmp_atomic_flag_64<true, false> *);

/* This routine signals the thread specified by target_gtid to wake up
   after setting the sleep bit indicated by the flag argument to FALSE */
template <class C>
static inline void __kmp_resume_template(int target_gtid, C *flag) {
  kmp_info_t *th = __kmp_threads[target_gtid];

#ifdef KMP_DEBUG
  int gtid = TCR_4(__kmp_init_gtid) ? __kmp_get_gtid() : -1;
#endif

  KF_TRACE(30, ("__kmp_resume_template: T#%d wants to wakeup T#%d enter\n",
                gtid, target_gtid));

  __kmp_suspend_initialize_thread(th);
  __kmp_lock_suspend_mx(th);

  if (!flag || flag != th->th.th_sleep_loc) {
    // coming from __kmp_null_resume_wrapper, or thread is now sleeping on a
    // different location; wake up at new location
    flag = (C *)th->th.th_sleep_loc;
  }

  // First, check if the flag is null or its type has changed. If so, someone
  // else woke it up.
  if (!flag || flag->get_type() != th->th.th_sleep_loc_type) {
    // simply shows what flag was cast to
    KF_TRACE(5, ("__kmp_resume_template: T#%d exiting, thread T#%d already "
                 "awake: flag's loc(%p)\n",
                 gtid, target_gtid, NULL));
    __kmp_unlock_suspend_mx(th);
    return;
  } else {
    if (!flag->is_sleeping()) {
      KF_TRACE(5, ("__kmp_resume_template: T#%d exiting, thread T#%d already "
                   "awake: flag's loc(%p): %u\n",
                   gtid, target_gtid, flag->get(), (unsigned int)flag->load()));
      __kmp_unlock_suspend_mx(th);
      return;
    }
  }
  KMP_DEBUG_ASSERT(flag);
  flag->unset_sleeping();
  TCW_PTR(th->th.th_sleep_loc, NULL);
  th->th.th_sleep_loc_type = flag_unset;

  KF_TRACE(5, ("__kmp_resume_template: T#%d about to wakeup T#%d, reset sleep "
               "bit for flag's loc(%p)\n",
               gtid, target_gtid, flag->get()));

  __kmp_win32_cond_signal(&th->th.th_suspend_cv);
  __kmp_unlock_suspend_mx(th);

  KF_TRACE(30, ("__kmp_resume_template: T#%d exiting after signaling wake up"
                " for T#%d\n",
                gtid, target_gtid));
}

template <bool C, bool S>
void __kmp_resume_32(int target_gtid, kmp_flag_32<C, S> *flag) {
  __kmp_resume_template(target_gtid, flag);
}
template <bool C, bool S>
void __kmp_resume_64(int target_gtid, kmp_flag_64<C, S> *flag) {
  __kmp_resume_template(target_gtid, flag);
}
template <bool C, bool S>
void __kmp_atomic_resume_64(int target_gtid, kmp_atomic_flag_64<C, S> *flag) {
  __kmp_resume_template(target_gtid, flag);
}
void __kmp_resume_oncore(int target_gtid, kmp_flag_oncore *flag) {
  __kmp_resume_template(target_gtid, flag);
}

template void __kmp_resume_32<false, true>(int, kmp_flag_32<false, true> *);
template void __kmp_resume_32<false, false>(int, kmp_flag_32<false, false> *);
template void __kmp_resume_64<false, true>(int, kmp_flag_64<false, true> *);
template void
__kmp_atomic_resume_64<false, true>(int, kmp_atomic_flag_64<false, true> *);

void __kmp_yield() { hpx::this_thread::yield(); }

void __kmp_gtid_set_specific(int gtid) {
  // HPXMP TODO: Is TLS used for anything else other that gtid? If not, this is probably cool
  if (__kmp_init_gtid) {
    KA_TRACE(50, ("__kmp_gtid_set_specific: T#%d\n", gtid));
    hpx::this_thread::set_thread_data(gtid);
  } else {
    KA_TRACE(50, ("__kmp_gtid_set_specific: runtime shutdown, returning\n"));
  }
}

int __kmp_gtid_get_specific() {
  int gtid;
  if (!__kmp_init_gtid) {
    KA_TRACE(50, ("__kmp_gtid_get_specific: runtime shutdown, returning "
                  "KMP_GTID_SHUTDOWN\n"));
    return KMP_GTID_SHUTDOWN;
  }
  gtid = hpx::this_thread::get_thread_data();
  if (gtid == 0) {
    gtid = KMP_GTID_DNE;
  } else {
    gtid--;
  }
  KA_TRACE(50, ("__kmp_gtid_get_specific: gtid:%d\n", gtid));
  return gtid;
}

void __kmp_affinity_bind_thread(int proc) {
  // HPXMP TODO: This is disabled for now, figure out if we can enable it
  KMP_ASSERT2(KMP_AFFINITY_CAPABLE(),
              "Illegal set affinity operation when not capable");
}

void __kmp_affinity_determine_capable(const char *env_var) {
  // HPXMP TODO: This is disabled for now, figure out if we can enable it
  KMP_AFFINITY_DISABLE();
}

void __kmp_terminate_thread(int gtid) {
  // HPXMP TODO: Figure out if HPX threads can/need to be "killed"
  KMP_ASSERT2(0, "__kmp_terminate_thread not yet implemented for HPXMP");
  
  //kmp_info_t *th = __kmp_threads[gtid];

  //if (!th)
  //  return;

  //KA_TRACE(10, ("__kmp_terminate_thread: kill (%d)\n", gtid));

  //if (TerminateThread(th->th.th_info.ds.ds_thread, (DWORD)-1) == FALSE) {
  //  /* It's OK, the thread may have exited already */
  //}
  //__kmp_free_handle(th->th.th_info.ds.ds_thread);
}

extern "C" void *__stdcall __kmp_launch_worker(void *arg) {
  volatile void *stack_data;
  void *exit_val;
  void *padding = 0;
  kmp_info_t *this_thr = (kmp_info_t *)arg;
  int gtid;

  gtid = this_thr->th.th_info.ds.ds_gtid;
  __kmp_gtid_set_specific(gtid);
#ifdef KMP_TDATA_GTID
#error "This define causes problems with LoadLibrary() + declspec(thread) " \
        "on Windows* OS.  See CQ50564, tests kmp_load_library*.c and this MSDN " \
        "reference: http://support.microsoft.com/kb/118816"
//__kmp_gtid = gtid;
#endif

#if USE_ITT_BUILD
  __kmp_itt_thread_name(gtid);
#endif /* USE_ITT_BUILD */

  __kmp_affinity_set_init_mask(gtid, FALSE);

#if KMP_ARCH_X86 || KMP_ARCH_X86_64
  // Set FP control regs to be a copy of the parallel initialization thread's.
  __kmp_clear_x87_fpu_status_word();
  __kmp_load_x87_fpu_control_word(&__kmp_init_x87_fpu_control_word);
  __kmp_load_mxcsr(&__kmp_init_mxcsr);
#endif /* KMP_ARCH_X86 || KMP_ARCH_X86_64 */

  if (__kmp_stkoffset > 0 && gtid > 0) {
    padding = KMP_ALLOCA(gtid * __kmp_stkoffset);
    (void)padding;
  }

  KMP_FSYNC_RELEASING(&this_thr->th.th_info.ds.ds_alive);
  this_thr->th.th_info.ds.ds_thread_id = GetCurrentThreadId();
  TCW_4(this_thr->th.th_info.ds.ds_alive, TRUE);

  if (TCR_4(__kmp_gtid_mode) <
      2) { // check stack only if it is used to get gtid
    TCW_PTR(this_thr->th.th_info.ds.ds_stackbase, &stack_data);
    KMP_ASSERT(this_thr->th.th_info.ds.ds_stackgrow == FALSE);
    __kmp_check_stack_overlap(this_thr);
  }
  KMP_MB();
  exit_val = __kmp_launch_thread(this_thr);
  KMP_FSYNC_RELEASING(&this_thr->th.th_info.ds.ds_alive);
  TCW_4(this_thr->th.th_info.ds.ds_alive, FALSE);
  KMP_MB();
  return exit_val;
}

#if KMP_USE_MONITOR
/* The monitor thread controls all of the threads in the complex */

void *__stdcall __kmp_launch_monitor(void *arg) {
    // HPXMP TODO: Figure out if we need this
}
#endif

void __kmp_create_worker(int gtid, kmp_info_t *th, size_t stack_size) {
  // PANOS: gtid --> index of free slot in the __kmp_threads array
  kmp_thread_t handle;
  DWORD idThread;

  KA_TRACE(10, ("__kmp_create_worker: try to create thread (%d)\n", gtid));

  th->th.th_info.ds.ds_gtid = gtid;

    // PANOS: if this is called with gtid of uber thread, it probably means that
    // we are registering the root thread, so just set the appropriate fields and
    // don't create a new thread
  if (KMP_UBER_GTID(gtid)) {

    // PANOS: On Windows, `ds_thread` contains a thread handle (of type kmp_thread_t === HANDLE), while thread id is in `ds_thread_id` (of type DWORD).
    // On linux, only `ds_thread` is used (of type kmp_thread_t === pthread_t). I guess we will fallback to the latter mechanism if USE_OS_THREADING is false,
    // so we only need to set ds_thread here.
    th->th.th_info.ds.ds_thread = hpx::this_thread::get_id();
    KA_TRACE(10, ("__kmp_create_worker: uber thread (%d)\n", gtid));

    // PANOS: HPXMP_TODO: Figure out if we need sth similar for HPXMP
    //if (TCR_4(__kmp_gtid_mode) < 2) { // check stack only if used to get gtid
    //  /* we will dynamically update the stack range if gtid_mode == 1 */
    //  TCW_PTR(th->th.th_info.ds.ds_stackbase, &stack_data);
    //  TCW_PTR(th->th.th_info.ds.ds_stacksize, 0);
    //  TCW_4(th->th.th_info.ds.ds_stackgrow, TRUE);
    //  __kmp_check_stack_overlap(th);
    //}
  } else {
    KMP_MB(); /* Flush all pending memory write invalidates.  */

    KA_TRACE(10,
             ("__kmp_create_worker: stack_size = %" KMP_SIZE_T_SPEC " bytes\n",
              stack_size));

    // PANOS: HPXMP_TODO: Figure out why this offset was used
    //stack_size += gtid * __kmp_stkoffset;
    //TCW_PTR(th->th.th_info.ds.ds_stacksize, stack_size);
    TCW_4(th->th.th_info.ds.ds_stackgrow, FALSE);

    KA_TRACE(10, ("__kmp_create_worker: T#%d, default stacksize = %lu bytes, "
                  "__kmp_stksize = %lu bytes, final stacksize = %lu bytes\n",
                  gtid, KMP_DEFAULT_STKSIZE, __kmp_stksize, stack_size));


    hpx::threads::thread_init_data data(
        hpx::threads::make_thread_function_nullary(
            hpx::util::deferred_call(&__kmp_launch_worker, (void *)th)),
        "__kmp_create_worker");

    data.run_now = true;

    size_t stacksize =
        hpx::get_runtime().get_config().get_stack_size(data.stacksize);
    TCW_PTR(th->th.th_info.ds.ds_stacksize, stacksize);

    hpx::threads::register_thread(data);

    KMP_MB(); /* Flush all pending memory write invalidates.  */
  }

  KA_TRACE(10, ("__kmp_create_worker: done creating thread (%d)\n", gtid));
}

int __kmp_still_running(kmp_info_t *th) {
  // HPXMP TODO: Figure out if we need this
  KMP_ASSERT2(0, "__kmp_still_running not yet implemented for HPXMP");
  return (WAIT_TIMEOUT == WaitForSingleObject(th->th.th_info.ds.ds_thread, 0));
}


/* Check to see if thread is still alive.
   NOTE:  The ExitProcess(code) system call causes all threads to Terminate
   with a exit_val = code.  Because of this we can not rely on exit_val having
   any particular value.  So this routine may return STILL_ALIVE in exit_val
   even after the thread is dead. */

int __kmp_is_thread_alive(kmp_info_t *th, DWORD *exit_val) {
  DWORD rc;
  rc = GetExitCodeThread(th->th.th_info.ds.ds_thread, exit_val);
  if (rc == 0) {
    DWORD error = GetLastError();
    __kmp_fatal(KMP_MSG(FunctionError, "GetExitCodeThread()"), KMP_ERR(error),
                __kmp_msg_null);
  }
  return (*exit_val == STILL_ACTIVE);
}

void __kmp_exit_thread(int exit_status) {
  // HPXMP TODO: Set this thread state to terminated and return to scheduler
  KMP_ASSERT2(0, "__kmp_exit_thread not yet implemented for HPXMP");

} // __kmp_exit_thread


void __kmp_reap_worker(kmp_info_t *th) {
  int status;
  void *exit_val;

  KMP_MB(); /* Flush all pending memory write invalidates.  */

  KA_TRACE(
      10, ("__kmp_reap_worker: try to reap T#%d\n", th->th.th_info.ds.ds_gtid));

    KMP_ASSERT2(0, "__kmp_reap_worker not yet implemented for HPXMP");
  // HPXMP TODO: We should suspend here until the hpx thread completes
  // (do like `pthread_join(th->th.th_info.ds.ds_thread, &exit_val);`)

  KA_TRACE(10, ("__kmp_reap_worker: done reaping T#%d\n",
                th->th.th_info.ds.ds_gtid));

  KMP_MB(); /* Flush all pending memory write invalidates.  */
}


/* Put the thread to sleep for a time period */
void __kmp_thread_sleep(int millis) {
  hpx::this_thread::sleep_for(std::chrono::milliseconds(millis));
}


/* Free handle and check the error code */
void __kmp_free_handle(kmp_thread_t tHandle) {
  // TODO: delete this for HPXMP
}

// Functions for hidden helper task
void __kmp_hidden_helper_worker_thread_wait() {
  KMP_ASSERT(0 && "Hidden helper task is not supported on Windows");
}

void __kmp_do_initialize_hidden_helper_threads() {
  KMP_ASSERT(0 && "Hidden helper task is not supported on Windows");
}

void __kmp_hidden_helper_threads_initz_wait() {
  KMP_ASSERT(0 && "Hidden helper task is not supported on Windows");
}

void __kmp_hidden_helper_initz_release() {
  KMP_ASSERT(0 && "Hidden helper task is not supported on Windows");
}

void __kmp_hidden_helper_main_thread_wait() {
  KMP_ASSERT(0 && "Hidden helper task is not supported on Windows");
}

void __kmp_hidden_helper_main_thread_release() {
  KMP_ASSERT(0 && "Hidden helper task is not supported on Windows");
}

void __kmp_hidden_helper_worker_thread_signal() {
  KMP_ASSERT(0 && "Hidden helper task is not supported on Windows");
}

void __kmp_hidden_helper_threads_deinitz_wait() {
  KMP_ASSERT(0 && "Hidden helper task is not supported on Windows");
}

void __kmp_hidden_helper_threads_deinitz_release() {
  KMP_ASSERT(0 && "Hidden helper task is not supported on Windows");
}