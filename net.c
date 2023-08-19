#include <stdio.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <sys/time.h>

#include "platform.h"

#include "util.h"
#include "net.h"
#include "ip.h"
#include "icmp.h"
#include "arp.h"
#include "udp.h"

#define PRIV(x) ((struct net_protocol *)x->priv)

/*
■==このモジュールの役割==
このモジュールは、ネットワークデバイス、プロトコル、タイマーなどのネットワーク関連のリソースや処理を一元的に管理する。
*/

struct net_protocol
{
    struct net_protocol *next;
    uint16_t type;
    struct queue_head queue; /* input queue */
    // プロトコルの入力関数へのポインタ
    void (*handler)(const uint8_t *data, size_t len, struct net_device *dev);
};

struct net_protocol_queue_entry
{
    struct net_device *dev;
    size_t len;
    uint8_t data[];
};

// タイマーの構造体
struct net_timer
{
    struct net_timer *next;
    struct timeval interval; // 発火間隔
    struct timeval last;     // 前回の発火時間
    void (*handler)(void);   // 発火時に呼び出す関数のポインタ
};

// ネットワークデバイスのリストの先頭を指す変数
static struct net_device *devices;
// 登録されているプロトコルのリスト（グローバル変数）※リンクリストの概念
// リストといいつつもリスト型ではなく、リストの先頭の構造体を指す、nextを追うことで結果的にリストになる
static struct net_protocol *protocols;
// タイマーリスト
static struct net_timer *timers;

// ネットワークデバイスのメモリを確保する
struct net_device *
net_device_alloc(void)
{
    struct net_device *dev;

    // デバイス構造体のサイズのメモリを確保
    // ・memory_alloc() で確保したメモリ領域は0で初期化されている
    // ・メモリが確保できなかったらエラーとしてNULLを返す
    dev = memory_alloc(sizeof(*dev));
    if (!dev)
    {
        errorf("memory_alloc() failure");
        return NULL;
    }
    return dev;
}

// ネットワークデバイスを登録する関数
int net_device_register(struct net_device *dev)
{
    static unsigned int index = 0;
    dev->index = index++;                                        // デバイスのインデックス番号を設定
    snprintf(dev->name, sizeof(dev->name), "net%d", dev->index); // デバイス名を生成（net0, net1, net2 …）
    // デバイスリストの先頭に追加
    dev->next = devices;
    devices = dev;
    infof("registered, dev=%s, type=0x%04x", dev->name, dev->type);
    return 0;
}

// ネットワークデバイスを開始する関数
static int
net_device_open(struct net_device *dev)
{
    // デバイスの状態を確認（既にUP状態の場合はエラーを返す）
    if (NET_DEVICE_IS_UP(dev))
    {
        errorf("already opened, dev=%s", dev->name);
        return -1;
    }

    // デバイスドライバのオープン関数を呼び出す
    // ・オープン関数が設定されてない場合は呼び出しをスキップ
    if (dev->ops->open)
    {
        if (dev->ops->open(dev) == -1)
        {
            // ・エラーが返されたらこの関数もエラーを返す
            errorf("failure, dev=%s", dev->name);
            return -1;
        }
    }
    dev->flags |= NET_DEVICE_FLAG_UP; // UPフラグを立てる
    infof("dev=%s, state=%s", dev->name, NET_DEVICE_STATE(dev));
    return 0;
}

// ネットワークデバイスを閉じる関数
static int
net_device_close(struct net_device *dev)
{
    // デバイスの状態を確認（UP状態でない場合はエラーを返す）
    if (!NET_DEVICE_IS_UP(dev))
    {
        errorf("not opened, dev=%s", dev->name);
        return -1;
    }
    // デバイスドライバのクローズ関数を呼び出す
    // ・クローズ関数が設定されてない場合は呼び出しをスキップ
    if (dev->ops->close)
    {
        if (dev->ops->close(dev) == -1)
        {
            // ・エラーが返されたらこの関数もエラーを返す// ・エラーが返されたらこの関数もエラーを返す
            errorf("failure, dev=%s", dev->name);
            return -1;
        }
    }
    dev->flags &= ~NET_DEVICE_FLAG_UP; //  UPフラグを落とす
    infof("dev=%s, state=%s", dev->name, NET_DEVICE_STATE(dev));
    return 0;
}

// ネットワークデバイスにインターフェースを追加する関数
int net_device_add_iface(struct net_device *dev, struct net_iface *iface)
{
    // 一時的にインターフェースの情報を保持するための変数
    struct net_iface *entry;

    // 重複登録のチェック
    for (entry = dev->ifaces; entry; entry = entry->next)
    {
        if (entry->family == iface->family)
        {
            errorf("already exists, dev=%s, family=%d", dev->name, entry->family);
            return -1;
        }
    }
    // exercise7-1
    // 既存のifacesの先頭ポインタを、追加するifaceのnextに設定。つまり先頭に追加
    iface->next = dev->ifaces;
    // 追加するインターフェースのデバイス情報を設定する
    iface->dev = dev;
    // デバイスのインターフェイスリストの先頭を追加後に更新
    dev->ifaces = iface;

    return 0;
}

// 引数のデバイスとファミリーに対応するインターフェースを返却する関数
struct net_iface *
net_device_get_iface(struct net_device *dev, int family)
{
    // exercise7-2
    struct net_iface *entry;

    // リストの終わりまで行くとNULLになるので、一致するインターフェイスが無ければNULLを返す
    for (entry = dev->ifaces; entry; entry = entry->next)
    {
        if (entry->family == family)
        {
            break;
        }
    }
    return entry;
}

// データをネットワークデバイスに出力する関数
int net_device_output(struct net_device *dev, uint16_t type, const uint8_t *data, size_t len, const void *dst)
{
    // デバイスの状態を確認（UP状態でなければ送信できないのでエラーを返す）
    if (!NET_DEVICE_IS_UP(dev))
    {
        errorf("not opened, dev=%s", dev->name);
        return -1;
    }
    // データのサイズを確認（デバイスのMTUを超えるサイズのデータは送信できないのでエラーを返す）
    if (len > dev->mtu)
    {
        errorf("too long, dev=%s, mtu=%u, len=%zu", dev->name, dev->mtu, len);
        return -1;
    }
    debugf("dev=%s, type=0x%04x, len=%zu", dev->name, type, len);
    debugdump(data, len);
    // デバイスドライバの出力関数を呼び出す（エラーが返されたらこの関数もエラーを返す）
    if (dev->ops->transmit(dev, type, data, len, dst) == -1)
    {
        errorf("device transmit failure, dev=%s, len=%zu", dev->name, len);
        return -1;
    }
    return 0;
}

// ネットワークプロトコルを登録する関数
int net_protocol_register(uint16_t type, void (*handler)(const uint8_t *data, size_t len, struct net_device *dev))
{
    struct net_protocol *proto;

    // リストの先頭から、末尾(nextの値がnull)までループする※protoがnullになるとfalse
    for (proto = protocols; proto; proto = proto->next)
    {
        if (type == proto->type)
        {
            // タイプが一致してすでに登録済みの時はエラーを返却
            errorf("already registered, type=0x%04x", type);
            return -1;
        }
    }

    proto = memory_alloc(sizeof(*proto));
    if (!proto)
    {
        errorf("memory_alloc() failure");
        return -1;
    }

    proto->type = type;
    // 入力関数を設定
    proto->handler = handler;
    // プロトコルリストの先頭に追加
    proto->next = protocols;
    protocols = proto;
    infof("registered, type=0x%04x", type);
    return 0;
}

/**
 * ネットワークタイマを登録する。
 *
 * @param interval タイマの間隔を示すtimeval構造体。
 * @param handler タイマが期限切れになったときに呼び出されるハンドラ関数。
 * @return 成功時は0、メモリ確保に失敗した場合は-1を返す。
 */
int net_timer_register(struct timeval interval, void (*handler)(void))
{
    struct net_timer *timer;

    // exercise16
    timer = memory_alloc(sizeof(*timer));
    if (!timer)
    {
        errorf("memory_alloc() failure");
        return -1;
    }
    timer->interval = interval;

    // 第一引数のポインタに現在時刻を格納する標準関数
    // ※第二引数には本来タイムゾーンを格納するが現在では非推奨となっているので基本的にはNULLが格納される
    gettimeofday(&timer->last, NULL);
    timer->handler = handler;
    timer->next = timers;
    timers = timer;

    infof("registered: interval={%d, %d}", interval.tv_sec, interval.tv_usec);
    return 0;
}

/**
 * 登録されたネットワークタイマのハンドラを実行する。
 *
 * この関数は、各タイマが指定された間隔を超えているかどうかを確認し、
 * 超えている場合はそのタイマのハンドラを実行します。
 *
 */
int net_timer_handler(void)
{
    struct net_timer *timer;
    struct timeval now, diff;

    for (timer = timers; timer; timer = timer->next)
    {
        gettimeofday(&now, NULL);
        // 第一引数と第二引数の差を計算、結果を第三引数に格納する関数
        timersub(&now, &timer->last, &diff);
        // 発火間隔と比べて、差分が大きい時1、小さい時0を返却
        if (timercmp(&timer->interval, &diff, <) != 0)
        {
            // exercise16
            timer->handler();
            timer->last = now;
        }
    }
    return 0;
}

/**
 * @brief ネットワークデータの受信処理を行う関数。
 *
 * この関数は、指定されたタイプのネットワークプロトコルに対応する処理を行います。
 * 対応するプロトコルが見つかった場合、データはそのプロトコルのキューに追加され、
 * ソフトウェア割り込みが発生します。
 *
 * @param type ネットワークデータのタイプ（例：IPv4やARPなど）。
 * @param data 受信したデータの先頭を指すポインタ。
 * @param len 受信したデータの長さ（バイト単位）。
 * @param dev データを受信したネットワークデバイスを指すポインタ。
 * @return データの処理が成功した場合は0、失敗した場合は-1。
 */
int net_input_handler(uint16_t type, const uint8_t *data, size_t len, struct net_device *dev)
{
    struct net_protocol *proto;
    struct net_protocol_queue_entry *entry;

    for (proto = protocols; proto; proto = proto->next)
    {
        if (proto->type == type)
        {

            // excercise4-1
            // (1)
            entry = memory_alloc(sizeof(*entry) + len);
            if (!entry)
            {
                errorf("memory_alloc() failure");
                return -1;
            }
            // (2)
            entry->dev = dev;
            entry->len = len;
            memcpy(entry->data, data, len);
            // (3) 不正解
            if (!queue_push(&proto->queue, entry))
            {
                errorf("queue_push() failure");
                memory_free(entry);
                return -1;
            }
            debugf("queue pushed (num:%u), dev=%s, type=0x%04x, len=%zu",
                   proto->queue.num, dev->name, type, len);
            debugdump(data, len);
            // キューへエントリ追加後、ソフトウェア割り込み発生
            intr_raise_irq(INTR_IRQ_SOFTIRQ);
            return 0;
        }
    }

    return 0;
}

// ソフトウェア割り込みが発生した際に呼び出す関数
int net_softirq_handler(void)
{
    struct net_protocol *proto;
    struct net_protocol_queue_entry *entry;

    for (proto = protocols; proto; proto = proto->next)
    {
        while (1)
        {
            entry = queue_pop(&proto->queue);
            if (!entry)
            {
                break;
            }
            debugf("queue popped (num:%u), dev=%s, type=0x%04x, len=%zu", proto->queue.num, entry->dev->name, proto->type, entry->len);
            debugdump(entry->data, entry->len);
            proto->handler(entry->data, entry->len, entry->dev);
            memory_free(entry);
        }
    }
    return 0;
}

// ネットワークを開始する関数
int net_run(void)
{
    struct net_device *dev;
    // 割り込み機構の起動
    if (intr_run() == -1)
    {
        errorf("intr_run() failure");
        return -1;
    }

    debugf("open all devices...");
    // 登録済みの全デバイスをオープン
    for (dev = devices; dev; dev = dev->next)
    {
        net_device_open(dev);
    }
    debugf("running...");
    return 0;
}

// ネットワークを停止する関数
void net_shutdown(void)
{
    struct net_device *dev;

    debugf("close all devices...");
    // 登録済みの全デバイスをクローズ
    for (dev = devices; dev; dev = dev->next)
    {
        net_device_close(dev);
    }
    // 割り込み機構の終了
    intr_shutdown();
    debugf("shutting down");
}

// ネットワークを初期化する関数
int net_init(void)
{
    // 割り込み機構の初期化
    if (intr_init() == -1)
    {
        errorf("intr_init() failure");
        return -1;
    }
    // exercise13
    if (arp_init() == -1)
    {
        errorf("arp_init() failure");
        return -1;
    }

    // プロトコルスタック初期化時にIPの初期化関数を呼び出す
    if (ip_init() == -1)
    {
        errorf("ip_init() failure");
        return -1;
    }
    // exercise9
    // ICMPの初期化関数を呼び出す
    if (icmp_init() == -1)
    {
        errorf("icmp_init() failure");
        return -1;
    }
    // exercise18
    if (udp_init() == -1)
    {
        errorf("udp_init() failure");
        return -1;
    }
    infof("initialized");
    return 0;
}
