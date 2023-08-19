#include <stdio.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>

#include "util.h"
#include "ip.h"
#include "udp.h"

// 疑似ヘッダの構造体(チェックサム計算時に使用)
struct pseudo_hdr
{
    uint32_t src;
    uint32_t dst;
    uint8_t zero;
    uint8_t protocol;
    uint16_t len;
};

// UDPヘッダの構造体
struct udp_hdr
{
    uint16_t src;
    uint16_t dst;
    uint16_t len;
    uint16_t sum;
};

/**
 * UDPパケットの内容をダンプします。
 *
 * @param data UDPパケットのデータを指すポインタ。
 * @param len  UDPパケットのデータ長。
 */
static void udp_dump(const uint8_t *data, size_t len)
{
    struct udp_hdr *hdr;

    flockfile(stderr);
    hdr = (struct udp_hdr *)data;
    fprintf(stderr, "        src: %u\n", ntoh16(hdr->src));
    fprintf(stderr, "        dst: %u\n", ntoh16(hdr->dst));
    fprintf(stderr, "        len: %u\n", ntoh16(hdr->len));
    fprintf(stderr, "        sum: 0x%04x\n", ntoh16(hdr->sum));
#ifdef HEXDUMP
    hexdump(stderr, data, len);
#endif
    funlockfile(stderr);
}

/**
 * UDPパケットを処理する関数。
 *
 * @param data   UDPパケットのデータを指すポインタ。
 * @param len    UDPパケットのデータ長。
 * @param src    送信元IPアドレス。
 * @param dst    宛先IPアドレス。
 * @param iface  受信したインターフェースの情報。
 */
static void udp_input(const uint8_t *data, size_t len, ip_addr_t src, ip_addr_t dst, struct ip_iface *iface)
{
    struct pseudo_hdr pseudo;
    uint16_t psum = 0;
    struct udp_hdr *hdr;
    char addr1[IP_ADDR_STR_LEN];
    char addr2[IP_ADDR_STR_LEN];

    // ヘッダサイズ未満はエラー
    if (len < sizeof(*hdr))
    {
        errorf("too short");
        return;
    }
    // 引数のデータをudpヘッダにキャスト
    hdr = (struct udp_hdr *)data;
    // IPから渡されたデータ長（len）とUDPヘッダに含まれるデータグラム長（hdr->len）が一致しない場合はエラー
    if (len != ntoh16(hdr->len))
    { /* just to make sure */
        errorf("length error: len=%zu, hdr->len=%u", len, ntoh16(hdr->len));
        return;
    }
    // チェックサム用疑似ヘッダ準備
    pseudo.src = src;
    pseudo.dst = dst;
    pseudo.zero = 0;
    pseudo.protocol = IP_PROTOCOL_UDP;
    pseudo.len = hton16(len);
    // 疑似ヘッダ部分のチェックサムを計算（計算結果はビット反転されているので戻しておく）
    psum = ~cksum16((uint16_t *)&pseudo, sizeof(pseudo), 0);
    // cksum16() の第三引数に psum を渡すことで続きを計算できる
    if (cksum16((uint16_t *)hdr, len, psum) != 0)
    {
        errorf("checksum error: sum=0x%04x, verify=0x%04x", ntoh16(hdr->sum), ntoh16(cksum16((uint16_t *)hdr, len, -hdr->sum + psum)));
        return;
    }
    debugf("%s:%d => %s:%d, len=%zu (payload=%zu)",
           ip_addr_ntop(src, addr1, sizeof(addr1)), ntoh16(hdr->src),
           ip_addr_ntop(dst, addr2, sizeof(addr2)), ntoh16(hdr->dst),
           len, len - sizeof(*hdr));
    udp_dump(data, len);
}

/**
 * UDPパケットを送信する関数。
 *
 * @param src  送信元のエンドポイント情報（IPアドレスとポート番号）。
 * @param dst  宛先のエンドポイント情報（IPアドレスとポート番号）。
 * @param data 送信するデータを指すポインタ。
 * @param len  送信するデータの長さ。
 * @return     成功時には送信したデータの長さ、失敗時には-1を返す。
 */
ssize_t udp_output(struct ip_endpoint *src, struct ip_endpoint *dst, const uint8_t *data, size_t len)
{
    uint8_t buf[IP_PAYLOAD_SIZE_MAX];
    struct udp_hdr *hdr;
    struct pseudo_hdr pseudo;
    uint16_t total, psum = 0;
    char ep1[IP_ENDPOINT_STR_LEN];
    char ep2[IP_ENDPOINT_STR_LEN];

    if (len > IP_PAYLOAD_SIZE_MAX - sizeof(*hdr))
    {
        errorf("too long");
        return -1;
    }
    hdr = (struct udp_hdr *)buf;

    // exercise18
    hdr->src = src->port;
    hdr->dst = dst->port;
    total = sizeof(*hdr) + len;
    hdr->len = hton16(total);
    hdr->sum = 0;
    // ヘッダの後ろにdata(ペイロード)を格納
    memcpy(hdr + 1, data, len);
    pseudo.src = src->addr;
    pseudo.dst = dst->addr;
    pseudo.zero = 0;
    pseudo.protocol = IP_PROTOCOL_UDP;
    pseudo.len = hton16(total);
    psum = ~cksum16((uint16_t *)&pseudo, sizeof(pseudo), 0);
    hdr->sum = cksum16((uint16_t *)hdr, total, psum);
    debugf("%s => %s, len=%zu (payload=%zu)",
           ip_endpoint_ntop(src, ep1, sizeof(ep1)), ip_endpoint_ntop(dst, ep2, sizeof(ep2)), total, len);
    udp_dump((uint8_t *)hdr, total);

    // exercise18
    if (ip_output(IP_PROTOCOL_UDP, (uint8_t *)hdr, total, src->addr, dst->addr) == -1)
    {
        errorf("ip_output() failure");
        return -1;
    }
    return len;
}

/**
 * UDPプロトコルの初期化関数。
 * IPプロトコルスタックにUDPの受信処理関数を登録する。
 *
 * @return 成功時は0、失敗時は-1を返す。
 */
int udp_init(void)
{
    // exercise18
    if (ip_protocol_register(IP_PROTOCOL_UDP, udp_input) == -1)
    {
        errorf("ip_protocol_register() failure");
        return -1;
    }
    return 0;
}
