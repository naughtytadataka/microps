#include <stdio.h>
#include <stddef.h>
#include <stdint.h>

#include "platform.h"

#include "util.h"
#include "net.h"

#define DUMMY_MTU UINT16_MAX    // ダミーデバイスの最大転送ユニット
#define DUMMY_IRQ INTR_IRQ_BASE // ダミーデバイスの割り込み番号

// データを送信する関数
static int
dummy_transmit(struct net_device *dev, uint16_t type, const uint8_t *data, size_t len, const void *dst)
{
    debugf("dev=%s, type=0x%04x, len=%zu", dev->name, type, len);
    debugdump(data, len);      // 送信データの内容をデバッグ出力
    intr_raise_irq(DUMMY_IRQ); // 割り込みを発生
    return 0;
}

// 割り込みが発生したときの処理
static int
dummy_isr(unsigned int irq, void *id)
{
    debugf("割り込み発生 : irq=%u, dev=%s", irq, ((struct net_device *)id)->name);
    return 0;
}

// デバイス操作関数の定義
static struct net_device_ops dummy_ops = {
    .transmit = dummy_transmit, // 送信関数（transmit）のみ設定
};

// ダミーデバイスの初期化関数
struct net_device *
dummy_init(void)
{
    struct net_device *dev;

    // デバイスを生成
    dev = net_device_alloc();
    if (!dev)
    {
        errorf("net_device_alloc() failure");
        return NULL;
    }
    dev->type = NET_DEVICE_TYPE_DUMMY; // 種別は net.h に定義してある

    dev->mtu = DUMMY_MTU;
    // ヘッダもアドレスも存在しない（明示的に0を設定）
    dev->hlen = 0;
    dev->alen = 0;
    dev->ops = &dummy_ops;
    // デバイスを登録
    if (net_device_register(dev) == -1)
    {
        errorf("net_device_register() failure");
        return NULL;
    }
    // 割り込み処理をシステムに登録
    intr_request_irq(DUMMY_IRQ, dummy_isr, INTR_IRQ_SHARED, dev->name, dev);
    debugf("initialized, dev=%s", dev->name);
    return dev;
}
