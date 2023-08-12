#include <stdio.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "platform.h"

#include "util.h"
#include "net.h"

// デバイスが扱える最大のデータサイズを定義
#define LOOPBACK_MTU UINT16_MAX
// キューの最大数を定義
#define LOOPBACK_QUEUE_LIMIT 16
// デバイスの割り込み番号を定義
#define LOOPBACK_IRQ (INTR_IRQ_BASE + 1)
// デバイスの固有情報を取得するためのマクロ
// 引数x内のprivメンバをloopback型にキャスト
#define PRIV(x) ((struct loopback *)x->priv)

// 固有情報を保持するための構造体
struct loopback
{
    int irq; // 割り込み番号
    // mutexを使用すると、一度に1つのスレッドだけが特定のコードセクションを実行できるようになる
    mutex_t mutex;           // 排他制御のためのミューテックス
    struct queue_head queue; // データのキュー
};

// キューに格納されるデータの構造体
struct loopback_queue_entry
{
    uint16_t type;
    size_t len;
    // 構造体の最後にだけ配置できるサイズ不明の配列
    // 　メンバ変数としてアクセスできるが構造体のサイズには含まれない（必ずデータ部分も含めてメモリを確保すること）
    uint8_t data[]; /* flexible array member */
};

// loopbackデバイスにデータを送信する関数
static int
loopback_transmit(struct net_device *dev, uint16_t type, const uint8_t *data, size_t len, const void *dst)
{
    // 送信データをキューに格納するための構造体
    struct loopback_queue_entry *entry;
    unsigned int num;

    // ＆で変数のアドレスを取得
    mutex_lock(&PRIV(dev)->mutex);
    // キューが上限に達しているかを確認
    if (PRIV(dev)->queue.num >= LOOPBACK_QUEUE_LIMIT)
    {
        // ロックを解放してエラー返却
        mutex_unlock(&PRIV(dev)->mutex);
        errorf("queue is full");
        return -1;
    }
    // sizeofだけだと,data[]分が確保出来ないのでlenを加算
    entry = memory_alloc(sizeof(*entry) + len);
    if (!entry)
    {
        mutex_unlock(&PRIV(dev)->mutex);
        errorf("memory_alloc() failure");
        return -1;
    }

    // 送信データの情報を構造体にセット
    entry->type = type;
    entry->len = len;
    // 第一引数がコピー先、第二引数がコピー対象、第三引数がコピーサイズ
    memcpy(entry->data, data, len);

    // 送信データをキューに追加
    queue_push(&PRIV(dev)->queue, entry);

    // 現在のキューのサイズを取得
    num = PRIV(dev)->queue.num;
    mutex_unlock(&PRIV(dev)->mutex);
    debugf("queue pushed (num:%u), dev=%s, type=0x%04x, len=%zd", num, dev->name, type, len);
    debugdump(data, len);

    // 割り込みを発生させて、データがキューに追加されたことを通知
    intr_raise_irq(PRIV(dev)->irq);
    return 0;
}

static int
loopback_isr(unsigned int irq, void *id)
{
    struct net_device *dev;
    struct loopback_queue_entry *entry;

    // idをネットワークデバイスの構造体にキャストして、devに格納
    dev = (struct net_device *)id;
    mutex_lock(&PRIV(dev)->mutex);
    // キューからデータを取り出す処理を繰り返す
    while (1)
    {
        // キューからデータを1つ取り出す
        entry = queue_pop(&PRIV(dev)->queue);
        // 空ならループを抜ける
        if (!entry)
        {
            break;
        }
        debugf("queue popped (num:%u), dev=%s, type=0x%04x, len=%zd", PRIV(dev)->queue.num, dev->name, entry->type, entry->len);
        debugdump(entry->data, entry->len);
        net_input_handler(entry->type, entry->data, entry->len, dev);
        memory_free(entry);
    }
    mutex_unlock(&PRIV(dev)->mutex);
    return 0;
}

static struct net_device_ops loopback_ops = {
    .transmit = loopback_transmit,
};

// ループバックデバイスを初期化
struct net_device *
loopback_init(void)
{
    // ネットワークデバイスの情報を保持する変数
    struct net_device *dev;
    // ループバックデバイスの固有情報を保持する変数
    struct loopback *lo;

    // exercise 3-1
    // デバイスを生成
    dev = net_device_alloc();
    if (!dev)
    {
        errorf("net_device_alloc() failure");
        return NULL;
    }
    dev->type = NET_DEVICE_TYPE_LOOPBACK;
    dev->mtu = LOOPBACK_MTU;
    dev->hlen = 0;
    dev->alen = 0;
    dev->flags = NET_DEVICE_FLAG_LOOPBACK;
    dev->ops = &loopback_ops;
    // ループバックデバイスのメモリを確保
    lo = memory_alloc(sizeof(*lo));
    if (!lo)
    {
        errorf("memory_alloc() failure");
        return NULL;
    }
    // ループバックデバイスの割り込み番号を設定
    lo->irq = LOOPBACK_IRQ;
    // ミューテックス（排他制御のためのツール）を初期化
    mutex_init(&lo->mutex);
    // キューを初期化
    queue_init(&lo->queue);
    // デバイスの固有情報として、ループバックの情報を設定
    dev->priv = lo;

    if (net_device_register(dev) == -1)
    {
        errorf("net_device_register() failure");
        return NULL;
    }

    // exercise 3-2
    intr_request_irq(lo->irq, loopback_isr, INTR_IRQ_SHARED, dev->name, dev);
    debugf("initialized, dev=%s", dev->name);
    return dev;
}
