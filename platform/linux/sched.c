#include <pthread.h>
#include <time.h>
#include <errno.h>

#include "platform.h"

/**
 * スケジューリング構造体の初期化関数
 *
 * @param ctx [out] 初期化するスケジューリングコンテキストのポインタ
 * @return 成功時は0を返す
 */
int sched_ctx_init(struct sched_ctx *ctx)
{
    pthread_cond_init(&ctx->cond, NULL);
    ctx->interrupted = 0;
    ctx->wc = 0;
    return 0;
}

/**
 * スケジューリングコンテキストの破棄関数
 *
 * @param ctx [in] 破棄するスケジューリングコンテキストのポインタ
 * @return 成功時は0、エラー時はエラーコードを返す
 */
int sched_ctx_destroy(struct sched_ctx *ctx)
{
    // pthread_cond_destroyは、条件変数を破棄するために使用する標準関数
    return pthread_cond_destroy(&ctx->cond);
}


/**
 * スケジューリングコンテキストを使用して、指定された時間までスレッドを休止させます。
 * 
 * @param ctx       スケジューリングコンテキストへのポインタ。
 * @param mutex     休止中にロックを解除するミューテックスへのポインタ。
 * @param abstime   スレッドを再開する絶対時刻。NULLの場合、条件変数の通知が来るまで待機します。
 * 
 * @return 成功時は0、エラー時は-1を返します。エラーの詳細はerrnoに設定されます。
 */
int sched_sleep(struct sched_ctx *ctx, mutex_t *mutex, const struct timespec *abstime)
{
    int ret;

    if (ctx->interrupted)
    {
        errno = EINTR;
        return -1;
    }
    ctx->wc++;
    if (abstime)
    {
        // 指定された時間まで待つ
        // pthread_cond_wait: 指定された条件変数にシグナルが送られるまで、呼び出し元のスレッドをブロック（一時停止）
        ret = pthread_cond_timedwait(&ctx->cond, mutex, abstime);
    }
    else
    {
        // 条件が満たされるまで待つ
        // pthread_cond_timedwait: 指定された時間が経過すると、たとえシグナルが送られてこなくてもスレッドが再開
        ret = pthread_cond_wait(&ctx->cond, mutex);
    }
    ctx->wc--;
    if (ctx->interrupted)
    {
        if (!ctx->wc)
        {
            ctx->interrupted = 0;
        }
        errno = EINTR;
        return -1;
    }
    return ret;
}

/**
 * @brief すべての待機中のスレッドを再開させます。
 *
 * @param ctx スケジュールコンテキストへのポインタ。
 * @return pthread_cond_broadcastの結果を返します。
 */
int sched_wakeup(struct sched_ctx *ctx)
{
    // pthread_cond_broadcast: 指定された条件変数で待機しているすべてのスレッドにシグナルを送ります。待機しているすべてのスレッドが再開
    return pthread_cond_broadcast(&ctx->cond);
}

/**
 * @brief 割り込みをフラグを立てた上で、すべての待機中のスレッドを再開させます。
 *
 * @param ctx スケジュールコンテキストへのポインタ。
 * @return pthread_cond_broadcastの結果を返します。
 */
int sched_interrupt(struct sched_ctx *ctx)
{
    ctx->interrupted = 1;
    return pthread_cond_broadcast(&ctx->cond);
}
