#include <stdio.h>
#include <stddef.h>
#include <stdint.h>

#include "platform.h"

#include "util.h"
#include "net.h"

// ネットワークデバイスのリストの先頭を指す変数
static struct net_device *devices;

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

// データを受信するための関数
int net_input_handler(uint16_t type, const uint8_t *data, size_t len, struct net_device *dev)
{
    debugf("dev=%s, type=0x%04x, len=%zu", dev->name, type, len);
    debugdump(data, len);
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

    infof("initialized");
    return 0;
}
