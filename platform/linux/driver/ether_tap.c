#define _GNU_SOURCE /* for F_SETSIG */
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/poll.h>
#include <linux/if.h>
#include <linux/if_tun.h>

#include "platform.h"

#include "util.h"
#include "net.h"
#include "ether.h"

#include "driver/ether_tap.h"

#define CLONE_DEVICE "/dev/net/tun"

#define ETHER_TAP_IRQ (INTR_IRQ_BASE + 2)

struct ether_tap
{
    char name[IFNAMSIZ]; // TAPデバイスの名前
    int fd;              // ファイルディスクリプタ
    // Interrupt Requestの略、割り込みハンドラを特定するために使う？
    unsigned int irq; // IRQ番号
};

// 引数xのprivメンバをether_tapのポインタにキャスト
#define PRIV(x) ((struct ether_tap *)x->priv)

/**
 * TAPデバイスのMACアドレスを取得して、ネットワークデバイス構造体に設定する関数。
 *
 * この関数は、指定されたネットワークデバイスのハードウェアアドレス（MACアドレス）を取得する。
 * 具体的には、TAPデバイスのMACアドレスを取得して、デバイス構造体にそのアドレスを設定します。
 *
 * @param dev ネットワークデバイス構造体のポインタ。この構造体にMACアドレスが設定されます。
 *
 * @return 成功時は0、失敗時は-1を返します。
 */
static int ether_tap_addr(struct net_device *dev)
{
    int soc;
    struct ifreq ifr = {};

    // ソケットオープン
    // 通信するわけでもないのにソケットをオープンしている理由
    // →ioctl() の SIOCGIFHWADDR 要求がソケットとして開かれたディスクリプタでのみ有効なため
    soc = socket(AF_INET, SOCK_DGRAM, 0);
    if (soc == -1)
    {
        errorf("socket: %s, dev=%s", strerror(errno), dev->name);
        return -1;
    }

    // ハードウェアアドレスを取得したいデバイスの名前をコピー
    strncpy(ifr.ifr_name, PRIV(dev)->name, sizeof(ifr.ifr_name) - 1);
    // ハードウェアアドレスの取得を要求
    if (ioctl(soc, SIOCGIFHWADDR, &ifr) == -1)
    {
        errorf("ioctl [SIOCGIFHWADDR]: %s, dev=%s", strerror(errno), dev->name);
        close(soc);
        return -1;
    }
    // 取得したアドレスをデバイス構造体へコピー
    memcpy(dev->addr, ifr.ifr_hwaddr.sa_data, ETHER_ADDR_LEN);
    // ソケットクローズ
    close(soc);
    return 0;
}

/**
 * @brief Ethernetデバイス（TAP）を開く関数。
 *
 * Ethernetデバイス（TAP）は仮想的なネットワークデバイスで、この関数を通じてそのデバイスを開きます。
 * また、シグナル駆動I/Oを設定して、データが入力可能な状態になったときにシグナルを受け取るようにします。
 *
 * @param dev 開きたいEthernetデバイス（TAP）に関連付けられたネットワークデバイスを指すポインタ。
 *
 * @return 成功時は0、失敗時は-1を返します。
 */
static int ether_tap_open(struct net_device *dev)
{
    struct ether_tap *tap;
    // interface request=ネットワークインターフェースに関連する操作を行うためのデータ構造体
    struct ifreq ifr = {};

    // devのprivをキャスト
    tap = PRIV(dev);
    // CLONE_DEVICEを読み書きモードで開く(opneはC言語の標準ライブラリ)、開けたらFDを、失敗なら-1を返却
    tap->fd = open(CLONE_DEVICE, O_RDWR);
    if (tap->fd == -1)
    {
        errorf("open: %s, dev=%s", strerror(errno), dev->name);
        return -1;
    }

    // TAPデバイスの設定
    // Ethernetデバイス（TAP）の名前をifr>ifr_nameにコピー
    // -1でnull文字を考慮しているらしい、いまいちわかってない。
    strncpy(ifr.ifr_name, tap->name, sizeof(ifr.ifr_name) - 1);
    ifr.ifr_flags = IFF_TAP | IFF_NO_PI;
    // ioctl()関数は、デバイス固有の操作を行うためのインターフェースを提供
    if (ioctl(tap->fd, TUNSETIFF, &ifr) == -1)
    {
        errorf("ioctl [TUNSETIFF]: %s, dev=%s", strerror(errno), dev->name);
        close(tap->fd);
        return -1;
    }

    // シグナル駆動I/Oの設定(シグナル駆動I/Oとは、データが入力可能な状態になったらシグナルを発生して知らせる)
    // シグナルの配送先を設定
    if (fcntl(tap->fd, F_SETOWN, getpid()) == -1)
    {
        errorf("fcntl(F_SETOWN): %s, dev=%s", strerror(errno), dev->name);
        close(tap->fd);
        return -1;
    }
    // シグナル駆動I/Oを有効化
    if (fcntl(tap->fd, F_SETFL, O_ASYNC) == -1)
    {
        errorf("fcntl(F_SETFL): %s, dev=%s", strerror(errno), dev->name);
        close(tap->fd);
        return -1;
    }
    // 送信シグナルを指定
    if (fcntl(tap->fd, F_SETSIG, tap->irq) == -1)
    {
        errorf("fcntl(F_SETSIG): %s, dev=%s", strerror(errno), dev->name);
        close(tap->fd);
        return -1;
    }

    // memcmpは「dev->addr」と「ETHER_ADDR_ANY」が「ETHER_ADDR_LEN」分同じであれば0を返す関数
    if (memcmp(dev->addr, ETHER_ADDR_ANY, ETHER_ADDR_LEN) == 0)
    {
        if (ether_tap_addr(dev) == -1)
        {
            errorf("ether_tap_addr() failure, dev=%s", dev->name);
            close(tap->fd);
            return -1;
        }
    }
    return 0;
}

/**
 * @brief Ethernetデバイス（TAP）を閉じる関数。
 *
 * この関数は、指定されたネットワークデバイスに関連付けられたEthernetデバイス（TAP）を閉じます。
 * Ethernetデバイス（TAP）は仮想的なネットワークデバイスで、この関数を通じてそのリソースを解放します。
 *
 * @param dev 閉じたいEthernetデバイス（TAP）に関連付けられたネットワークデバイスを指すポインタ。
 *
 * @return 常に0を返します。
 */
static int ether_tap_close(struct net_device *dev)
{
    close(PRIV(dev)->fd);
    return 0;
}

/**
 * TAPデバイスへのデータ書き込みを行う関数。
 *
 * @param dev   ネットワークデバイス構造体のポインタ。
 * @param frame 書き込むデータのポインタ。
 * @param flen  書き込むデータの長さ。
 * @return      書き込んだバイト数。エラーの場合は-1。
 */
static ssize_t ether_tap_write(struct net_device *dev, const uint8_t *frame, size_t flen)
{
    return write(PRIV(dev)->fd, frame, flen);
}

/**
 * TAPデバイスへのデータ送信を行う関数。
 *
 * @param dev  ネットワークデバイス構造体のポインタ。
 * @param type データのタイプ。
 * @param buf  送信するデータのポインタ。
 * @param len  送信するデータの長さ。
 * @param dst  宛先アドレス。
 * @return     成功時は0、失敗時は-1。
 */
int ether_tap_transmit(struct net_device *dev, uint16_t type, const uint8_t *buf, size_t len, const void *dst)
{
    return ether_transmit_helper(dev, type, buf, len, dst, ether_tap_write);
}

/**
 * TAPデバイスからのデータ読み込みを行う関数。
 *
 * @param dev  ネットワークデバイス構造体のポインタ。
 * @param buf  読み込んだデータを格納するバッファのポインタ。
 * @param size バッファのサイズ。
 * @return     読み込んだバイト数。エラーの場合は-1。
 */
static ssize_t ether_tap_read(struct net_device *dev, uint8_t *buf, size_t size)
{
    ssize_t len;

    len = read(PRIV(dev)->fd, buf, size);
    if (len <= 0)
    {
        if (len == -1 && errno != EINTR)
        {
            errorf("read: %s, dev=%s", strerror(errno), dev->name);
        }
        return -1;
    }
    return len;
}

/**
 * TAPデバイスの割り込み処理
 *
 * @param irq 割り込み要求番号。
 * @param id  デバイスID。
 * @return    常に0を返します。
 */
static int ether_tap_isr(unsigned int irq, void *id)
{
    struct net_device *dev;
    ;
    struct pollfd pfd;
    int ret;

    // pollで何を監視するかの設定
    dev = (struct net_device *)id;
    pfd.fd = PRIV(dev)->fd;
    // 読み取り可能データがあるかを監視
    pfd.events = POLLIN;

    while (1)
    {
        ret = poll(&pfd, 1, 0);
        if (ret == -1)
        {
            if (errno == EINTR)
            {
                continue;
            }
            errorf("poll: %s, dev=%s", strerror(errno), dev->name);
            return -1;
        }
        if (ret == 0)
        {
            break;
        }
        // 読み込み可能な時に呼ぶ
        ether_input_helper(dev, ether_tap_read);
    }
    return 0;
}

/**
 * ether_tap用のネットワークデバイス操作関数群。
 * 
 * この構造体は、ether_tapデバイスの基本的な操作を提供する関数ポインタを定義しています。
 */
static struct net_device_ops ether_tap_ops = {
    .open = ether_tap_open,
    .close = ether_tap_close,
    .transmit = ether_tap_transmit,
};

/**
 * ether_tapデバイスの初期化を行う関数。
 * 
 * @param name  ether_tapデバイスの名前。
 * @param addr  ether_tapデバイスのアドレス。NULLの場合は設定しない。
 * @return      初期化されたnet_device構造体のポインタ。初期化に失敗した場合はNULL。
 */
struct net_device *ether_tap_init(const char *name, const char *addr)
{
    struct net_device *dev;
    struct ether_tap *tap;

    dev = net_device_alloc();
    if (!dev)
    {
        errorf("net_device_alloc() failure");
        return NULL;
    }
    ether_setup_helper(dev);
    if (addr)
    {
        if (ether_addr_pton(addr, dev->addr) == -1)
        {
            errorf("invalid address, addr=%s", addr);
            return NULL;
        }
    }
    dev->ops = &ether_tap_ops;
    tap = memory_alloc(sizeof(*tap));
    if (!tap)
    {
        errorf("memory_alloc() failure");
        return NULL;
    }
    // ドライバ内部で使用するプライベートなデータを生成
    strncpy(tap->name, name, sizeof(tap->name) - 1);
    tap->fd = -1;
    tap->irq = ETHER_TAP_IRQ;
    dev->priv = tap;
    // デバイスをプロトコルスタックに登録
    if (net_device_register(dev) == -1)
    {
        errorf("net_device_register() failure");
        memory_free(tap);
        return NULL;
    }
    // 割り込みハンドラの登録
    intr_request_irq(tap->irq, ether_tap_isr, INTR_IRQ_SHARED, dev->name, dev);
    infof("ethernet device initialized, dev=%s", dev->name);
    return dev;
}
