#ifndef PLATFORM_H
#define PLATFORM_H

#include <stddef.h>
#include <stdlib.h>
#include <pthread.h>
#include <signal.h>

/*
 * Memory
 */

static inline void *
memory_alloc(size_t size)
{
    return calloc(1, size);
}

static inline void
memory_free(void *ptr)
{
    free(ptr);
}

/*
 * Mutex
 */

typedef pthread_mutex_t mutex_t;

#define MUTEX_INITIALIZER PTHREAD_MUTEX_INITIALIZER

static inline int
mutex_init(mutex_t *mutex)
{
    return pthread_mutex_init(mutex, NULL);
}

static inline int
mutex_lock(mutex_t *mutex)
{
    return pthread_mutex_lock(mutex);
}

static inline int
mutex_unlock(mutex_t *mutex)
{
    return pthread_mutex_unlock(mutex);
}

// Linuxでは SIGRTMIN ～ SIGRTMAX（34～64）までのシグナルをアプリケーションが任意の目的で利用できる。
// ※ SIGRTMIN（34）に関しては glibc が内部的に利用しているため +1 した番号から利用するようにしている。
#define INTR_IRQ_BASE (SIGRTMIN + 1)
// SIGUSR1 は標準的な定数で、UNIX系のシステムでのシグナル処理において特定の意味を持っている
// 直接SIGUSR1として使うこともできるがより具体的な定数にするためにINTR_IRQ_SOFTIRQとしている？
#define INTR_IRQ_SOFTIRQ SIGUSR1
#define INTR_IRQ_EVENT SIGUSR2

#define INTR_IRQ_SHARED 0x0001

extern int
intr_request_irq(unsigned int irq, int (*handler)(unsigned int irq, void *id), int flags, const char *name, void *dev);
extern int
intr_raise_irq(unsigned int irq);

extern int
intr_run(void);
extern void
intr_shutdown(void);
extern int
intr_init(void);

// スケジューリングの構造体
struct sched_ctx
{
    // pthread_cond_t は、POSIXスレッド（pthreads）ライブラリで定義されているデータ型
    // 条件変数は、スレッド間の同期メカニズムの一つ
    pthread_cond_t cond;// スレッドを休止させるために使用する条件変数
    int interrupted;// シグナルに割り込まれたことを示すフラグ
    int wc; // 休止中のタスクの数
};

#define SCHED_CTX_INITIALIZER          \
    {                                  \
        PTHREAD_COND_INITIALIZER, 0, 0 \
    }

extern int
sched_ctx_init(struct sched_ctx *ctx);
extern int
sched_ctx_destroy(struct sched_ctx *ctx);
extern int
sched_sleep(struct sched_ctx *ctx, mutex_t *mutex, const struct timespec *abstime);
extern int
sched_wakeup(struct sched_ctx *ctx);
extern int
sched_interrupt(struct sched_ctx *ctx);

#endif
