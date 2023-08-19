#include <stdio.h>
#include <string.h>
#include <signal.h>
#include <pthread.h>
#include <time.h>
#include <errno.h>

#include "platform.h"

#include "util.h"
#include "net.h"

// 割り込みの情報を保持するための構造体
struct irq_entry
{
    struct irq_entry *next;                      // 次の割り込みエントリへのポインタ
    unsigned int irq;                            // 割り込み番号
    int (*handler)(unsigned int irq, void *dev); // 割り込みが発生したときに呼び出される関数
    int flags;                                   // 割り込みのフラグ（特性を示す）
    char name[16];                               // 割り込みの名前
    void *dev;                                   // 割り込みに関連するデバイス情報
};

// 割り込みエントリのリスト（最初のエントリを指すポインタ）
static struct irq_entry *irqs;

static sigset_t sigmask; // シグナルマスク（どのシグナルをブロックするかの情報）

static pthread_t tid;             // スレッドID
static pthread_barrier_t barrier; // スレッド間の同期のためのバリア

// 割り込みをリクエストする関数
int intr_request_irq(unsigned int irq, int (*handler)(unsigned int irq, void *dev), int flags, const char *name, void *dev)
{
    struct irq_entry *entry;

    debugf("割り込みハンドラ登録1 : irq=%u, flags=%d, name=%s", irq, flags, name);
    // 同じ割り込み番号が登録されているかをチェック
    for (entry = irqs; entry; entry = entry->next)
    {
        if (entry->irq == irq)
        {
            // 既存のエントリとフラグが異なる場合はエラー
            if (entry->flags ^ INTR_IRQ_SHARED || flags ^ INTR_IRQ_SHARED)
            {
                errorf("conflicts with already registered IRQs");
                return -1;
            }
        }
    }

    // 新しい割り込みエントリのメモリを確保
    entry = memory_alloc(sizeof(*entry));
    if (!entry)
    {
        errorf("memory_alloc() failure");
        return -1;
    }
    // 割り込みエントリの情報を設定
    entry->irq = irq;
    entry->handler = handler;
    entry->flags = flags;
    strncpy(entry->name, name, sizeof(entry->name) - 1);
    entry->dev = dev;
    // 新しいエントリをリストの先頭に追加
    entry->next = irqs;
    irqs = entry;
    // シグナルマスクに割り込み番号を追加
    sigaddset(&sigmask, irq);
    debugf("割り込みハンドラ登録2 : registered: irq=%u, name=%s", irq, name);

    return 0;
}

// 指定された割り込み番号の割り込みを発生させる関数
int intr_raise_irq(unsigned int irq)
{
    // スレッドにシグナルを送信して、割り込みを発生
    return pthread_kill(tid, (int)irq);
}

/**
 * インターバルタイマを設定する。
 *
 * この関数は、指定された間隔でタイマを設定します。タイマはCLOCK_REALTIMEクロックを使用します。
 *
 * @param interval タイマの間隔と期限を示すitimerspec構造体へのポインタ。
 * @return 成功時は0、失敗時は-1を返す。
 */
static int intr_timer_setup(struct itimerspec *interval)
{
    timer_t id; // POSIXタイマの格納場所

    // POSIXタイマの生成(CLOCK_REALTIMEは実時間を基準にするクロック)
    // 第二引数にNULLを指定すると期限切れ時にシグナルを送信
    if (timer_create(CLOCK_REALTIME, NULL, &id) == -1)
    {
        errorf("timer_create: %s", strerror(errno));
        return -1;
    }
    // 期限切れ時間を設定
    if (timer_settime(id, 0, interval, NULL) == -1)
    {
        errorf("timer_settime: %s", strerror(errno));
        return -1;
    }
    return 0;
}

/**
 * 割り込みを処理するスレッド関数。
 *
 * このスレッドは、特定のシグナルを待ち受け、それに応じた処理を実行します。
 * 例えば、`SIGALRM` はタイマハンドラを、`SIGUSR1` はネットワークのソフト割り込みハンドラを呼び出します。
 * また、`SIGHUP` はスレッドの終了フラグを立てるために使用されます。
 *
 * @param arg
 * @return NULL
 */
static void *intr_thread(void *arg)
{
    // インターバルの設定
    const struct timespec ts = {0, 1000000}; /* 1ms */
    struct itimerspec interval = {ts, ts};

    int terminate = 0, sig, err; // terminateは終了フラグ、sigは受け取ったシグナル、errはエラーコード
    struct irq_entry *entry;     // 割り込みエントリ

    debugf("割り込みスレッド起動: start...");
    // スレッドの同期のためのバリアを待つ。
    pthread_barrier_wait(&barrier);

    // POSIXタイマの生成と設定
    if (intr_timer_setup(&interval) == -1)
    {
        errorf("intr_timer_setup() failure");
        return NULL;
    }
    while (!terminate)
    {
        // シグナル待ち
        // intr_initでsigmaskに追加したシグナルをブロックしているので
        // sigwaitでブロックしているシグナルを自分のタイミングで取得する。
        err = sigwait(&sigmask, &sig);
        if (err)
        {
            errorf("sigwait() %s", strerror(err));
            break;
        }
        // 発生したシグナルの種類に応じた処理を記述
        switch (sig)
        {

        case SIGHUP: // SIGHUPシグナルが受け取られた場合、終了フラグを立てる
            terminate = 1;
            break;
        case SIGUSR1:
            net_softirq_handler();
            break;
        case SIGUSR2:
            net_event_handler();
            break;
        case SIGALRM:
            net_timer_handler();
            break;

        default: // それ以外のシグナルが受け取られた場合、該当する割り込みハンドラを呼び出す
                 // IRQリストを巡回
            for (entry = irqs; entry; entry = entry->next)
            {
                // IRQ番号が一致するエントリの割り込みハンドラを呼び出す
                if (entry->irq == (unsigned int)sig)
                {
                    debugf("割り込みハンドラ呼び出し : irq=%d, name=%s", entry->irq, entry->name);
                    entry->handler(entry->irq, entry->dev);
                }
            }
            break;
        }
    }
    debugf("割り込みスレッド終了 : terminated");
    return NULL;
}

// 割り込みを処理するスレッドを開始する関数
int intr_run(void)
{
    int err;

    // このスレッドで指定したシグナルをブロック
    err = pthread_sigmask(SIG_BLOCK, &sigmask, NULL);
    if (err)
    {
        errorf("pthread_sigmask() %s", strerror(err));
        return -1;
    }
    // 割り込みを処理するスレッドを作成
    err = pthread_create(&tid, NULL, intr_thread, NULL);
    if (err)
    {
        errorf("pthread_create() %s", strerror(err));
        return -1;
    }
    // スレッドの同期のためのバリアを待ち
    pthread_barrier_wait(&barrier);
    return 0;
}

// 割り込みを処理するスレッドを終了する関数
void intr_shutdown(void)
{
    // 現在のスレッドが割り込みを処理するスレッドでない場合、何もしない
    if (pthread_equal(tid, pthread_self()) != 0)
    {
        return;
    }
    // 割り込みを処理するスレッドに終了シグナルを送信
    pthread_kill(tid, SIGHUP);
    // 割り込みを処理するスレッドの終了待ち
    pthread_join(tid, NULL);
}

/**
 * 割り込み処理の初期化関数。
 *
 * @return 常に0を返します。
 */
int intr_init(void)
{
    // 現在のスレッドIDを取得
    tid = pthread_self();
    // 同期のためのバリアを初期化
    pthread_barrier_init(&barrier, NULL, 2);
    // シグナルマスクを空
    sigemptyset(&sigmask);
    // sigaddsetでシグナルマスクに指定したシグナルを追加する
    // sigmaskに以下のシグナルを追加することで、予期しないタイミング、場所で処理されるのをブロックする
    sigaddset(&sigmask, SIGHUP);
    sigaddset(&sigmask, SIGUSR1);
    sigaddset(&sigmask, SIGUSR2);
    sigaddset(&sigmask, SIGALRM);

    return 0;
}
