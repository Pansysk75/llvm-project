/*
 * z_HPX_util.cpp -- HPX threading routines.
 */

// #include "hpx/threading_base/
#include "hpx/hpx_init.hpp"
#include "hpx/thread.hpp"

#include "kmp_wait_release.h"

#if KMP_HANDLE_SIGNALS
typedef void (*sig_func_t)(int);
static sig_func_t __kmp_sighldrs[NSIG];
static int __kmp_siginstalled[NSIG];
#endif

#define COMPLAIN_UNIMPLEMENTED(f_name)                                         \
  KMP_ASSERT2(0, f_name##" not yet implemented for HPXMP")


void __kmp_enable(int new_state) { COMPLAIN_UNIMPLEMENTED(__FUNCTION__); }

void __kmp_disable(int *old_state) { COMPLAIN_UNIMPLEMENTED(__FUNCTION__); }

void __kmp_suspend_initialize(void) { /* do nothing */
  COMPLAIN_UNIMPLEMENTED(__FUNCTION__);
}

void __kmp_suspend_initialize_thread(kmp_info_t *th) {
  COMPLAIN_UNIMPLEMENTED(__FUNCTION__);
}

void __kmp_suspend_uninitialize_thread(kmp_info_t *th) {}

int __kmp_try_suspend_mx(kmp_info_t *th) {
  COMPLAIN_UNIMPLEMENTED(__FUNCTION__);
  return 0;
}

void __kmp_lock_suspend_mx(kmp_info_t *th) {
  COMPLAIN_UNIMPLEMENTED(__FUNCTION__);
}

void __kmp_unlock_suspend_mx(kmp_info_t *th) {
  COMPLAIN_UNIMPLEMENTED(__FUNCTION__);
}

/* This routine puts the calling thread to sleep after setting the
   sleep bit for the indicated flag variable to true. */
template <class C>
static inline void __kmp_suspend_template(int th_gtid, C *flag) {
  COMPLAIN_UNIMPLEMENTED(__FUNCTION__);
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
  COMPLAIN_UNIMPLEMENTED(__FUNCTION__);
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

void __kmp_yield() { COMPLAIN_UNIMPLEMENTED(__FUNCTION__); }

void __kmp_gtid_set_specific(int gtid) { COMPLAIN_UNIMPLEMENTED(__FUNCTION__); }

int __kmp_gtid_get_specific() {
  COMPLAIN_UNIMPLEMENTED(__FUNCTION__);
  return 0;
}

void __kmp_affinity_bind_thread(int proc) {
  COMPLAIN_UNIMPLEMENTED(__FUNCTION__);
}

void __kmp_affinity_determine_capable(const char *env_var) {
  COMPLAIN_UNIMPLEMENTED(__FUNCTION__);
}

double __kmp_read_cpu_time(void) {
  COMPLAIN_UNIMPLEMENTED(__FUNCTION__);
  return 0;
}

int __kmp_read_system_info(struct kmp_sys_info *info) {
  COMPLAIN_UNIMPLEMENTED(__FUNCTION__);
  return 0;
}

void __kmp_runtime_initialize(void) {
  COMPLAIN_UNIMPLEMENTED(__FUNCTION__);
} // __kmp_runtime_initialize

void __kmp_runtime_destroy(void) { COMPLAIN_UNIMPLEMENTED(__FUNCTION__); }

void __kmp_terminate_thread(int gtid) { COMPLAIN_UNIMPLEMENTED(__FUNCTION__); }

void __kmp_clear_system_time(void) { COMPLAIN_UNIMPLEMENTED(__FUNCTION__); }

void __kmp_initialize_system_tick(void) {
  COMPLAIN_UNIMPLEMENTED(__FUNCTION__);
}

/* Calculate the elapsed wall clock time for the user */

void __kmp_elapsed(double *t) { COMPLAIN_UNIMPLEMENTED(__FUNCTION__); }

void __kmp_elapsed_tick(double *t) { COMPLAIN_UNIMPLEMENTED(__FUNCTION__); }

void __kmp_read_system_time(double *delta) {
  COMPLAIN_UNIMPLEMENTED(__FUNCTION__);
}

/* Return the current time stamp in nsec */
kmp_uint64 __kmp_now_nsec() {
  COMPLAIN_UNIMPLEMENTED(__FUNCTION__);
  return 0;
}

extern "C" void *__stdcall __kmp_launch_worker(void *arg) {
  COMPLAIN_UNIMPLEMENTED(__FUNCTION__);
  return 0;
}

#if KMP_USE_MONITOR
/* The monitor thread controls all of the threads in the complex */

void *__stdcall __kmp_launch_monitor(void *arg) {
  COMPLAIN_UNIMPLEMENTED(__FUNCTION__);
  // HPXMP TODO: Figure out if we need this
}
#endif

void __kmp_create_worker(int gtid, kmp_info_t *th, size_t stack_size) {
  COMPLAIN_UNIMPLEMENTED(__FUNCTION__);
}

int __kmp_still_running(kmp_info_t *th) {
  COMPLAIN_UNIMPLEMENTED(__FUNCTION__);
  //// HPXMP TODO: Figure out if we need this
  // return (WAIT_TIMEOUT == WaitForSingleObject(th->th.th_info.ds.ds_thread,
  // 0));
  return 0;
}

/* Check to see if thread is still alive.
   NOTE:  The ExitProcess(code) system call causes all threads to Terminate
   with a exit_val = code.  Because of this we can not rely on exit_val having
   any particular value.  So this routine may return STILL_ALIVE in exit_val
   even after the thread is dead. */

int __kmp_is_thread_alive(kmp_info_t *th, DWORD *exit_val) {
  COMPLAIN_UNIMPLEMENTED(__FUNCTION__);
  return 0;
}

void __kmp_exit_thread(int exit_status) {
  COMPLAIN_UNIMPLEMENTED(__FUNCTION__);
  // HPXMP TODO: Set this thread state to terminated and return to scheduler?
} // __kmp_exit_thread

void __kmp_reap_worker(kmp_info_t *th) { COMPLAIN_UNIMPLEMENTED(__FUNCTION__); }

#if KMP_HANDLE_SIGNALS

static void __kmp_team_handler(int signo) {
  COMPLAIN_UNIMPLEMENTED(__FUNCTION__);
} // __kmp_team_handler

static sig_func_t __kmp_signal(int signum, sig_func_t handler) {
  COMPLAIN_UNIMPLEMENTED(__FUNCTION__);
  return 0;
}

static void __kmp_install_one_handler(int sig, sig_func_t handler,
                                      int parallel_init) {
  COMPLAIN_UNIMPLEMENTED(__FUNCTION__);
} // __kmp_install_one_handler

static void __kmp_remove_one_handler(int sig) {
  COMPLAIN_UNIMPLEMENTED(__FUNCTION__);
} // __kmp_remove_one_handler

void __kmp_install_signals(int parallel_init) {
  COMPLAIN_UNIMPLEMENTED(__FUNCTION__);
} // __kmp_install_signals

void __kmp_remove_signals(void) {
  COMPLAIN_UNIMPLEMENTED(__FUNCTION__);
} // __kmp_remove_signals

#endif // KMP_HANDLE_SIGNALS

/* Put the thread to sleep for a time period */
void __kmp_thread_sleep(int millis) {
  COMPLAIN_UNIMPLEMENTED(__FUNCTION__);
  // hpx::this_thread::sleep_for(std::chrono::milliseconds(millis));
}

// Determine whether the given address is mapped into the current address space.
int __kmp_is_address_mapped(void *addr) {
  COMPLAIN_UNIMPLEMENTED(__FUNCTION__);

  return 0;
}

kmp_uint64 __kmp_hardware_timestamp(void) {
  COMPLAIN_UNIMPLEMENTED(__FUNCTION__);
  return 0;
}

/* Free handle and check the error code */
void __kmp_free_handle(kmp_thread_t tHandle) {
  COMPLAIN_UNIMPLEMENTED(__FUNCTION__);
  // TODO: delete this for HPXMP
}

int __kmp_get_load_balance(int max) {
  COMPLAIN_UNIMPLEMENTED(__FUNCTION__);
  return 0;
}

// Find symbol from the loaded modules
void *__kmp_lookup_symbol(const char *name, bool next) {
  COMPLAIN_UNIMPLEMENTED(__FUNCTION__);
  return 0;
}

// Functions for hidden helper task
void __kmp_hidden_helper_worker_thread_wait() {
  COMPLAIN_UNIMPLEMENTED(__FUNCTION__);
}

void __kmp_do_initialize_hidden_helper_threads() {
  COMPLAIN_UNIMPLEMENTED(__FUNCTION__);
}

void __kmp_hidden_helper_threads_initz_wait() {
  COMPLAIN_UNIMPLEMENTED(__FUNCTION__);
}

void __kmp_hidden_helper_initz_release() {
  COMPLAIN_UNIMPLEMENTED(__FUNCTION__);
}

void __kmp_hidden_helper_main_thread_wait() {
  COMPLAIN_UNIMPLEMENTED(__FUNCTION__);
}

void __kmp_hidden_helper_main_thread_release() {
  COMPLAIN_UNIMPLEMENTED(__FUNCTION__);
}

void __kmp_hidden_helper_worker_thread_signal() {
  COMPLAIN_UNIMPLEMENTED(__FUNCTION__);
}

void __kmp_hidden_helper_threads_deinitz_wait() {
  COMPLAIN_UNIMPLEMENTED(__FUNCTION__);
}

void __kmp_hidden_helper_threads_deinitz_release() {
  COMPLAIN_UNIMPLEMENTED(__FUNCTION__);
}


#if (KMP_ARCH_X86 || KMP_ARCH_X86_64 || KMP_ARCH_AARCH64 || KMP_ARCH_ARM)
/* Only 32-bit "add-exchange" instruction on IA-32 architecture causes us to
   use compare_and_store for these routines */

kmp_int8 __kmp_test_then_or8(volatile kmp_int8 *p, kmp_int8 d) {
  return 0;
}

kmp_int8 __kmp_test_then_and8(volatile kmp_int8 *p, kmp_int8 d) {
  return 0;
}

kmp_uint32 __kmp_test_then_or32(volatile kmp_uint32 *p, kmp_uint32 d) {
  return 0;
}

kmp_uint32 __kmp_test_then_and32(volatile kmp_uint32 *p, kmp_uint32 d) {
  return 0;
}

#if KMP_ARCH_X86 || KMP_ARCH_X86_64
kmp_int8 __kmp_test_then_add8(volatile kmp_int8 *p, kmp_int8 d) {
  return 0;
}

#if KMP_ARCH_X86
kmp_int64 __kmp_test_then_add64(volatile kmp_int64 *p, kmp_int64 d) {
  return 0;
}
#endif /* KMP_ARCH_X86 */
#endif /* KMP_ARCH_X86 || KMP_ARCH_X86_64 */

kmp_uint64 __kmp_test_then_or64(volatile kmp_uint64 *p, kmp_uint64 d) {
  return 0;
}

kmp_uint64 __kmp_test_then_and64(volatile kmp_uint64 *p, kmp_uint64 d) {
  return 0;
}

#if KMP_ARCH_AARCH64 && KMP_COMPILER_MSVC
// For !KMP_COMPILER_MSVC, this function is provided in assembly form
// by z_Linux_asm.S.
int __kmp_invoke_microtask(microtask_t pkfn, int gtid, int tid, int argc,
                           void *p_argv[]
#if OMPT_SUPPORT
                           ,
                           void **exit_frame_ptr
#endif
) {
  return 0;
}
#endif

#endif /* KMP_ARCH_X86 || KMP_ARCH_X86_64 || KMP_ARCH_AARCH64 || KMP_ARCH_ARM  \
        */
