#include <stdio.h>
#include <signal.h>
#include <unistd.h>

#include "util.h"
#include "net.h"

#include "driver/dummy.h"

#include "test.h"

// volatileでコンパイラによる最適化の対象から除外する。
// これは、その変数がプログラムの実行中に予期せず変更される可能性がある変数につける
// C言語では、int型の変数は論理式の中で真偽値として評価可能。値が0=false、0以外=true
static volatile sig_atomic_t terminate;

static void
on_signal(int s)
{
    (void)s;
    terminate = 1;
}

int main(int argc, char *argv[])
{

    struct net_device *dev;

    // Ctrl+Cを押すと、ターミナルは現在実行中のプロセスに対してSIGINT（割り込みシグナル）を送信するので
    // その送信シグナルを受信するとon_signalが動くようにする
    signal(SIGINT, on_signal);
    // プロトコルスタックの初期化
    if (net_init() == -1)
    {
        errorf("net_init() failure");
        return -1;
    }
    // ダミーデバイスの初期化（デバイスドライバがプロトコルスタックへの登録まで済ませる）
    dev = dummy_init();
    if (!dev)
    {
        errorf("dummy_init() failure");
        return -1;
    }
    // プロトコルスタックの起動
    if (net_run() == -1)
    {
        errorf("net_run() failure");
        return -1;
    }
    // Ctrl+C が押されるとシグナルハンドラ on_signal() の中で terminate に 1 が設定される
    while (!terminate)
    {
        // 1秒おきにデバイスにパケットを書き込む
        // ・まだパケットを自力で生成できないのでテストデータを用いる
        if (net_device_output(dev, 0x0800, test_data, sizeof(test_data), NULL) == -1)
        {
            errorf("net_device_output() failure");
            break;
        }
        sleep(1);
    }
    net_shutdown(); // プロトコルスタックの停止
    return 0;
}
