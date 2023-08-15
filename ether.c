#include <stdio.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>

#include "util.h"
#include "net.h"
#include "ether.h"

// イーサネットヘッダの構造体
struct ether_hdr
{
    uint8_t dst[ETHER_ADDR_LEN];
    uint8_t src[ETHER_ADDR_LEN];
    uint16_t type;
};

const uint8_t ETHER_ADDR_ANY[ETHER_ADDR_LEN] = {"\x00\x00\x00\x00\x00\x00"};
const uint8_t ETHER_ADDR_BROADCAST[ETHER_ADDR_LEN] = {"\xff\xff\xff\xff\xff\xff"};

int ether_addr_pton(const char *p, uint8_t *n)
{
    int index;
    char *ep;
    long val;

    if (!p || !n)
    {
        return -1;
    }
    for (index = 0; index < ETHER_ADDR_LEN; index++)
    {
        val = strtol(p, &ep, 16);
        if (ep == p || val < 0 || val > 0xff || (index < ETHER_ADDR_LEN - 1 && *ep != ':'))
        {
            break;
        }
        n[index] = (uint8_t)val;
        p = ep + 1;
    }
    if (index != ETHER_ADDR_LEN || *ep != '\0')
    {
        return -1;
    }
    return 0;
}

char *
ether_addr_ntop(const uint8_t *n, char *p, size_t size)
{
    if (!n || !p)
    {
        return NULL;
    }
    snprintf(p, size, "%02x:%02x:%02x:%02x:%02x:%02x", n[0], n[1], n[2], n[3], n[4], n[5]);
    return p;
}

/**
 * @brief Ethernetフレームの詳細をダンプする関数
 *
 * この関数は、ソースおよび宛先MACアドレス、Ethernetタイプを表示します。
 * また、HEXDUMPが定義されている場合、フレーム全体の16進ダンプもオプションで表示します。
 *
 * @param frame Ethernetフレームの開始を指すポインタ。
 * @param flen Ethernetフレームのバイト単位の長さ。
 */
static void ether_dump(const uint8_t *frame, size_t flen)
{
    struct ether_hdr *hdr;
    char addr[ETHER_ADDR_STR_LEN];

    hdr = (struct ether_hdr *)frame;
    flockfile(stderr);

    // バイト列のmacアドレスを文字列に変換
    fprintf(stderr, "        src: %s\n", ether_addr_ntop(hdr->src, addr, sizeof(addr)));
    fprintf(stderr, "        dst: %s\n", ether_addr_ntop(hdr->dst, addr, sizeof(addr)));

    fprintf(stderr, "       type: 0x%04x\n", ntoh16(hdr->type));
#ifdef HEXDUMP
    hexdump(stderr, frame, flen);
#endif
    funlockfile(stderr);
}

/**
 * @brief Ethernetフレームの送信を補助する関数。
 *
 * この関数は、指定されたデータとヘッダ情報を使用してEthernetフレームを構築し、
 * そのフレームを指定されたコールバック関数を使用して送信します。
 *
 * @param dev 送信を行うネットワークデバイスのポインタ。
 * @param type Ethernetタイプ（例：IPv4やARPなど）。
 * @param data 送信するデータの先頭ポインタ。
 * @param len 送信するデータ長（バイト単位）。
 * @param dst 宛先MACアドレス。
 * @param callback 実際の送信を行うコールバック関数。
 *
 * @return 送信が成功した場合は0、失敗した場合は-1。
 */
int ether_transmit_helper(struct net_device *dev, uint16_t type, const uint8_t *data, size_t len, const void *dst, ether_transmit_func_t callback)
{
    uint8_t frame[ETHER_FRAME_SIZE_MAX] = {};
    struct ether_hdr *hdr;
    size_t flen, pad = 0;

    hdr = (struct ether_hdr *)frame;
    memcpy(hdr->dst, dst, ETHER_ADDR_LEN);
    memcpy(hdr->src, dev->addr, ETHER_ADDR_LEN);
    hdr->type = hton16(type);
    // イーサネットヘッダの次のポインタにデータをコピー
    memcpy(hdr + 1, data, len);
    // 最小サイズ未満の場合はパディングを追加してサイズ調整
    // ※Ethernetではフレームの最大サイズに加えて最小サイズも規定されており、最小サイズに満たない場合にはパディングを挿入してフレームサイズを調整して送信する。
    // （CSMA/CDにおいて、フレームサイズが小さすぎるとコリジョンを検出した際のジャム信号が届く前に送信を終えてしまい、衝突を検知できなくなてしまうため）

    if (len < ETHER_PAYLOAD_SIZE_MIN)
    {
        pad = ETHER_PAYLOAD_SIZE_MIN - len;
    }
    flen = sizeof(*hdr) + len + pad;
    debugf("dev=%s, type=0x%04x, len=%zu", dev->name, type, flen);
    ether_dump(frame, flen);
    // 引数のcallbackをここで使う
    return callback(dev, frame, flen) == (ssize_t)flen ? 0 : -1;
}

/**
 * @brief Ethernetフレームの受信を補助する関数。
 *
 * この関数は、指定されたコールバック関数を使用してEthernetフレームを受信し、
 * 受信したフレームの内容を解析して適切な処理を行います。
 *
 * @param dev フレームの受信を行うネットワークデバイスを指すポインタ。
 * @param callback 実際の受信を行うコールバック関数。
 * @return フレームの処理が成功した場合は0、失敗した場合は-1。
 */
int ether_input_helper(struct net_device *dev, ether_input_func_t callback)
{
    uint8_t frame[ETHER_FRAME_SIZE_MAX];
    ssize_t flen;
    struct ether_hdr *hdr;
    uint16_t type;

    // 引数のcallbackを使用して、フレームサイズを取得？
    flen = callback(dev, frame, sizeof(frame));
    if (flen < (ssize_t)sizeof(*hdr))
    {
        errorf("too short");
        return -1;
    }
    hdr = (struct ether_hdr *)frame;
    // Ethernetフレームのフィルタリング
    // ・宛先がデバイス自身のMACアドレスまたはブロードキャストMACアドレスであればOK
    // ・それ以外は他のホスト宛とみなして黙って破棄する←本で読む動き
    if (memcmp(dev->addr, hdr->dst, ETHER_ADDR_LEN) != 0)
    {
        if (memcmp(ETHER_ADDR_BROADCAST, hdr->dst, ETHER_ADDR_LEN) != 0)
        {
            /* for other host */
            return -1;
        }
    }
    type = ntoh16(hdr->type);
    debugf("dev=%s, type=0x%04x, len=%zd", dev->name, type, flen);
    ether_dump(frame, flen);
    // net_input_handler() を呼び出してプロトコルスタックにペイロードを渡す
    // ペイロード=ヘッダーやフッター、エラーチェックなどのメタデータや制御情報を除いた、純粋なデータ部分
    // flen(フレーム長)からhdr(ヘッダ長)を除いているのがflen - sizeof(*hdr)の箇所
    return net_input_handler(type, (uint8_t *)(hdr + 1), flen - sizeof(*hdr), dev);
}

/**
 * @brief イーサネットデバイスの初期設定を行う補助関数。
 *
 * この関数は、指定されたネットワークデバイスにイーサネットデバイスとしての共通の設定値を設定します。
 * これには、デバイスタイプ、MTU、フラグ、ヘッダーの長さ、アドレスの長さ、ブロードキャストアドレスなどの情報を含む。
 *
 * @param dev 設定を行いたいネットワークデバイスを指すポインタ。
 */
void ether_setup_helper(struct net_device *dev)
{
    // イーサネットデバイス共通の値を設定
    dev->type = NET_DEVICE_TYPE_ETHERNET;
    dev->mtu = ETHER_PAYLOAD_SIZE_MAX;
    dev->flags = (NET_DEVICE_FLAG_BROADCAST | NET_DEVICE_FLAG_NEED_ARP);
    dev->hlen = ETHER_HDR_SIZE;
    dev->alen = ETHER_ADDR_LEN;
    memcpy(dev->broadcast, ETHER_ADDR_BROADCAST, ETHER_ADDR_LEN);
}
