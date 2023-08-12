#include <stdio.h>
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>

#include "util.h"
#include "net.h"
#include "ip.h"

// IPヘッダの情報を保持するための構造体
struct ip_hdr
{
    uint8_t vhl;       // IPバージョンとヘッダ長を保持する変数。
    uint8_t tos;       // サービスのタイプを示す変数。
    uint16_t total;    // トータルの長さを示す変数。
    uint16_t id;       // 識別子。
    uint16_t offset;   // フラグメントのオフセット。
    uint8_t ttl;       // Time to Live（生存時間）。
    uint8_t protocol;  // 使用するプロトコルを示す変数。
    uint16_t sum;      // チェックサム。
    ip_addr_t src;     // 送信元のIPアドレス。
    ip_addr_t dst;     // 宛先のIPアドレス。
    uint8_t options[]; // オプション（可変長）。
};

const ip_addr_t IP_ADDR_ANY = 0x00000000;       /* 0.0.0.0 */
const ip_addr_t IP_ADDR_BROADCAST = 0xffffffff; /* 255.255.255.255 */

// 文字列形式のIPアドレスを数値形式に変換する関数
int ip_addr_pton(const char *p, ip_addr_t *n)
{
    char *sp, *ep;
    int idx;
    long ret;

    sp = (char *)p;               // 文字列の開始位置設定(ポインタによって、この位置から文字列全体を追跡可能)
    for (idx = 0; idx < 4; idx++) // IPアドレスは4つの部分から成るため、4回ループ(例："192.168.1.1")
    {
        // strtolは第一引数の位置から数値を読み取り、数値以外の文字列が来ると処理を終える
        // 終えた場所(数値以外の文字),ここでは.の位置を第二引数に格納
        // 第三引数では想定する基数を設定(ここでは10進数)
        ret = strtol(sp, &ep, 10);
        if (ret < 0 || ret > 255) // IPアドレスの各部分は0〜255の範囲のはず
        {
            return -1;
        }
        if (ep == sp) // 数値が読み取れなかった場合。
        {
            return -1;
        }
        // 最後の部分(0,1,2)でなければ次は'.'
        // 最後の部分(3)なら終端文字'\0'でなければならない
        if ((idx == 3 && *ep != '\0') || (idx != 3 && *ep != '.'))
        {
            return -1;
        }
        // nは32ビット、それを8ビットにキャストすると8ビット×4のリストになる
        // retは10進数だが、8ビットに格納すると自動で2進数の8ビットに変換される。
        ((uint8_t *)n)[idx] = ret;
        sp = ep + 1; // 次の部分の開始位置を設定。
    }
    return 0;
}

// 数値形式のIPアドレスを.区切りの文字列に変換する関数。
char *
ip_addr_ntop(ip_addr_t n, char *p, size_t size)
{
    uint8_t *u8;

    u8 = (uint8_t *)&n;
    // snprintf関数は、指定されたフォーマットに従って文字列を生成し、pという文字列バッファに保存
    snprintf(p, size, "%d.%d.%d.%d", u8[0], u8[1], u8[2], u8[3]);

    return p;
}

// IPデータをダンプ（表示）するための関数
static void
ip_dump(const uint8_t *data, size_t len)
{
    struct ip_hdr *hdr;
    uint8_t v, hl, hlen;
    uint16_t total, offset;
    char addr[IP_ADDR_STR_LEN];

    flockfile(stderr);
    hdr = (struct ip_hdr *)data;
    // vhl→上位4ビットはバージョン情報、下位4ビットはipヘッダ長
    // 16進数0xf0は二進数で11110000,これとand演算して上位四桁を取り出す
    // >>4で右シフトして、上位4ビットを下位4ビットにする
    v = (hdr->vhl & 0xf0) >> 4;
    // 0x0fは2進数で00001111
    hl = hdr->vhl & 0x0f;
    // hlには32bit単位の長さが格納されている。そのため、実際のバイト数を得るためには、hlの値を4倍する
    // hl=1ということは、32ビットを表す、これをバイトにすると32÷8=4バイトなので,4倍
    hlen = hl << 2;
    fprintf(stderr, "        vhl: 0x%02x [v: %u, hl: %u (%u)]\n", hdr->vhl, v, hl, hlen);
    fprintf(stderr, "        tos: 0x%02x\n", hdr->tos);
    total = ntoh16(hdr->total);
    fprintf(stderr, "      total: %u (payload: %u)\n", total, total - hlen);
    fprintf(stderr, "         id: %u\n", ntoh16(hdr->id));
    offset = ntoh16(hdr->offset);
    // offset … 上位 3bit = フラグ, 下位 13bit = フラグメントオフセット
    fprintf(stderr, "     offset: 0x%04x [flags=%x, offset=%u]\n", offset, (offset & 0xe000) >> 13, offset & 0x1fff);
    fprintf(stderr, "        ttl: %u\n", hdr->ttl);
    fprintf(stderr, "   protocol: %u\n", hdr->protocol);
    fprintf(stderr, "        sum: 0x%04x\n", ntoh16(hdr->sum));
    fprintf(stderr, "        src: %s\n", ip_addr_ntop(hdr->src, addr, sizeof(addr)));
    fprintf(stderr, "        dst: %s\n", ip_addr_ntop(hdr->dst, addr, sizeof(addr)));
#ifdef HEXDUMP
    hexdump(stderr, data, len);
#endif
    funlockfile(stderr);
}

// IPデータを処理するための関数
static void
ip_input(const uint8_t *data, size_t len, struct net_device *dev)
{
    struct ip_hdr *hdr;
    uint8_t v;
    uint16_t hlen, total, offset;

    if (len < IP_HDR_SIZE_MIN)
    {
        errorf("too short");
        return;
    }
    hdr = (struct ip_hdr *)data;

    // exercise6
    hdr = (struct ip_hdr *)data;
    // versionチェック
    v = hdr->vhl >> 4; // version取得
    if (v != IP_VERSION_IPV4)
    {
        errorf("ip version error: v=%u", v);
        return;
    }

    // 入力データ長チェック
    hlen = (hdr->vhl & 0x0f) << 2;
    // ヘッダ長とチェック
    if (len < hlen)
    {
        errorf("header length error: len=%zu < hlen=%u", len, hlen);
        return;
    }
    // トータル長とチェック
    // lenは実際に受信したデータ(ヘッダとペイロード)、totalはヘッダとペイロードの長さなので短いのはおかしい
    total = ntoh16(hdr->total);
    if (len < total)
    {
        errorf("total length error: len=%zu < total=%u", len, total);
        return;
    }

    // チェックサム
    if (cksum16((uint16_t *)hdr, hlen, 0) != 0)
    {
        errorf("checksum error: sum=0x%04x, verify=0x%04x", ntoh16(hdr->sum), ntoh16(cksum16((uint16_t *)hdr, hlen, -hdr->sum)));
        return;
    }

    offset = ntoh16(hdr->offset);
    if (offset & 0x2000 || offset & 0x1fff)
    {
        errorf("fragments does not support");
        return;
    }
    debugf("dev=%s, protocol=%u, total=%u", dev->name, hdr->protocol, total);
    ip_dump(data, total);
}

// IP関連の初期化を行う関数
int ip_init(void)
{
    if (net_protocol_register(NET_PROTOCOL_TYPE_IP, ip_input) == -1)
    {
        errorf("net_protocol_register() failure");
        return -1;
    }
    return 0;
}