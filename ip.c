#include <stdio.h>
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <sys/types.h>
#include <string.h>

#include "platform.h"
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
/* NOTE: if you want to add/delete the entries after net_run(), you need to protect these lists with a mutex. */
static struct ip_iface *ifaces;

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

// IPインターフェースを作成する関数
struct ip_iface *
ip_iface_alloc(const char *unicast, const char *netmask)
{
    struct ip_iface *iface;

    iface = memory_alloc(sizeof(*iface));
    if (!iface)
    {
        errorf("memory_alloc() failure");
        return NULL;
    }
    NET_IFACE(iface)->family = NET_IFACE_FAMILY_IP;
    // exercise7-3
    // unicastを数値形式に変換して、インターフェースのunicastフィールドに保存
    if (ip_addr_pton(unicast, &iface->unicast) == -1)
    {
        errorf("ip_addr_pton() failure, address=%s", unicast);
        memory_free(iface);
        return NULL;
    }
    // netmaskを数値形式に変換して、インターフェースのnetmaskフィールドに保存
    if (ip_addr_pton(netmask, &iface->netmask) == -1)
    {
        errorf("ip_addr_pton() failure, address=%s", netmask);
        memory_free(iface);
        return NULL;
    }
    // ブロードキャストアドレスを計算して、インターフェースのbroadcastフィールドに保存
    iface->broadcast = (iface->unicast & iface->netmask) | ~iface->netmask;
    return iface;
}

// IPインターフェイスを登録する関数
int ip_iface_register(struct net_device *dev, struct ip_iface *iface)
{
    char addr1[IP_ADDR_STR_LEN];
    char addr2[IP_ADDR_STR_LEN];
    char addr3[IP_ADDR_STR_LEN];
    // Exercise 7-4
    if (net_device_add_iface(dev, NET_IFACE(iface)) == -1)
    {
        errorf("net_device_add_iface() failure");
        return -1;
    }
    iface->next = ifaces;
    ifaces = iface;

    infof("registered: dev=%s, unicast=%s, netmask=%s, broadcast=%s", dev->name,
          ip_addr_ntop(iface->unicast, addr1, sizeof(addr1)),
          ip_addr_ntop(iface->netmask, addr2, sizeof(addr2)),
          ip_addr_ntop(iface->broadcast, addr3, sizeof(addr3)));
    return 0;
}

// 引数addrとunicastが一致するインターフェイスを返却する関数
struct ip_iface *
ip_iface_select(ip_addr_t addr)
{
    struct ip_iface *entry;

    // ifacesをループする
    for (entry = ifaces; entry; entry = entry->next)
    {
        if (entry->unicast == addr)
        {
            break;
        }
    }
    return entry;
}

// IPデータを処理するための関数
static void
ip_input(const uint8_t *data, size_t len, struct net_device *dev)
{
    struct ip_hdr *hdr;
    uint8_t v;
    uint16_t hlen, total, offset;
    struct ip_iface *iface;
    char addr[IP_ADDR_STR_LEN];

    // 受信したデータが最小のIPヘッダサイズよりも小さい場合はエラー
    if (len < IP_HDR_SIZE_MIN)
    {
        errorf("too short");
        return;
    }

    // 受信したデータをIPヘッダ構造体にキャスト
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

    // 取得したインターフェイスをIPインターフェイスにキャスト
    iface = (struct ip_iface *)net_device_get_iface(dev, NET_IFACE_FAMILY_IP);
    if (!iface)
    {
        return;
    }
    // 宛先アドレスがインターフェースのユニキャストと一致しない場合の処理
    if (hdr->dst != iface->unicast)
    {
        // 宛先がブロードキャストアドレスでない場合は終了
        if (hdr->dst != iface->broadcast && hdr->dst != IP_ADDR_BROADCAST)
        {
            return;
        }
    }

    debugf("dev=%s, iface=%s, protocol=%u, total=%u",
           dev->name, ip_addr_ntop(iface->unicast, addr, sizeof(addr)), hdr->protocol, total);
    ip_dump(data, total);
}

// IPデータをデバイスに送信する関数
static int
ip_output_device(struct ip_iface *iface, const uint8_t *data, size_t len, ip_addr_t dst)
{
    uint8_t hwaddr[NET_DEVICE_ADDR_LEN] = {};

    // ネットワークデバイスのフラグがARPのフラグか判定
    if (NET_IFACE(iface)->dev->flags & NET_DEVICE_FLAG_NEED_ARP)
    {
        // 送信先がブロードキャストアドレス
        if (dst == iface->broadcast || dst == IP_ADDR_BROADCAST)
        {
            // ハードウェアアドレスをブロードキャストアドレスにする
            memcpy(hwaddr, NET_IFACE(iface)->dev->broadcast, NET_IFACE(iface)->dev->alen);
        }
        else
        {
            errorf("arp does not implement");
            return -1;
        }
    }
    // exercise8
    return net_device_output(NET_IFACE(iface)->dev, NET_PROTOCOL_TYPE_IP, data, len, hwaddr);
}

// データをIPパケットに格納する？
static ssize_t
ip_output_core(struct ip_iface *iface, uint8_t protocol, const uint8_t *data, size_t len, ip_addr_t src, ip_addr_t dst, uint16_t id, uint16_t offset)
{
    uint8_t buf[IP_TOTAL_SIZE_MAX];
    struct ip_hdr *hdr;
    uint16_t hlen, total;
    char addr[IP_ADDR_STR_LEN];

    // bufの先頭アドレスをipヘッダのポインタにキャスト
    hdr = (struct ip_hdr *)buf;

    // exercise8
    hlen = IP_HDR_SIZE_MIN; // ヘッダの最小サイズ
    // 上位４桁はversion,下位
    hdr->vhl = (IP_VERSION_IPV4 << 4) | (hlen >> 2);
    hdr->tos = 0;
    total = hlen + len;
    hdr->total = hton16(total);
    hdr->id = hton16(id);
    hdr->offset = hton16(offset);
    hdr->ttl = 0xff;
    hdr->protocol = protocol;
    hdr->sum = 0;
    hdr->src = src;
    hdr->dst = dst;
    hdr->sum = cksum16((uint16_t *)hdr, hlen, 0); /* don't convert byteoder */
    memcpy(hdr + 1, data, len);

    debugf("dev=%s, dst=%s, protocol=%u, len=%u",
           NET_IFACE(iface)->dev->name, ip_addr_ntop(dst, addr, sizeof(addr)), protocol, total);
    ip_dump(buf, total);
    return ip_output_device(iface, buf, total, dst);
}

static uint16_t
ip_generate_id(void)
{
    static mutex_t mutex = MUTEX_INITIALIZER;
    static uint16_t id = 128;
    uint16_t ret;

    mutex_lock(&mutex);
    ret = id++;
    mutex_unlock(&mutex);
    return ret;
}

// IPデータ送信関数
ssize_t
ip_output(uint8_t protocol, const uint8_t *data, size_t len, ip_addr_t src, ip_addr_t dst)
{
    struct ip_iface *iface;
    char addr[IP_ADDR_STR_LEN];
    uint16_t id;

    if (src == IP_ADDR_ANY)
    {
        errorf("ip routing does not implement");
        return -1;
    }
    else
    { /* NOTE: I'll rewrite this block later. */
        // exercise8
        iface = ip_iface_select(src);
        if (!iface)
        {
            errorf("interface not found, src=%s", ip_addr_ntop(src, addr, sizeof(addr)));
            return -1;
        }
        // 送信先IPアドレスとネットマスクでand演算をして、ネットワーク部のみを取り出す
        // この端末のネットワークインターフェースのユニキャストアドレスのネットワーク部を取り出す
        // 両者を比較して同じネットワークに属するか確認
        // ただし、送信先ipアドレスがブロードキャストアドレスなら必ずスキップ
        if ((dst & iface->netmask) != (iface->unicast & iface->netmask) && dst != IP_ADDR_BROADCAST)
        {
            errorf("not reached, dst=%s", ip_addr_ntop(src, addr, sizeof(addr)));
            return -1;
        }
    }
    // フラグメンテーション=当該データがこのインターフェースの最大転送サイズを超えた場合にパケットに分割して送信すること。
    // ただし、今回はフラグメンテーションを考慮しないので、超えたらエラー
    if (NET_IFACE(iface)->dev->mtu < IP_HDR_SIZE_MIN + len)
    {
        errorf("too long, dev=%s, mtu=%u < %zu",
               NET_IFACE(iface)->dev->name, NET_IFACE(iface)->dev->mtu, IP_HDR_SIZE_MIN + len);
        return -1;
    }
    // ipのid作成
    id = ip_generate_id();
    if (ip_output_core(iface, protocol, data, len, iface->unicast, dst, id, 0) == -1)
    {
        errorf("ip_output_core() failure");
        return -1;
    }
    return len;
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