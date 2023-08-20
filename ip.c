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
#include "arp.h"

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

// IPプロトコルの構造体
struct ip_protocol
{
    struct ip_protocol *next;
    uint8_t type;
    // 同じ引数を持つ関数なら設定できる
    void (*handler)(const uint8_t *data, size_t len, ip_addr_t src, ip_addr_t dst, struct ip_iface *iface);
};

// 経路情報の構造体
struct ip_route
{
    struct ip_route *next; // 次の経路へのポインタ
    ip_addr_t network;
    ip_addr_t netmask;
    ip_addr_t nexthop;      // 次の中継先のアドレス(なければIP_ADDR_ANY)
    struct ip_iface *iface; // この経路への送信に使うインターフェース
};

// 受信側の発想(0.0.0.0)
// サーバがこのアドレスにバインドすると、サーバはすべてのネットワークインターフェースを通じて来る接続要求を受け入れる
// つまり、どのIPアドレスを使用してサーバにアクセスしても、サーバはその接続要求を受け入れる
const ip_addr_t IP_ADDR_ANY = 0x00000000;
// 送信側の発想(255.255.255.255)
// このアドレスにパケットを送信すると、そのパケットはネットワーク上のすべてのデバイスに配信される
const ip_addr_t IP_ADDR_BROADCAST = 0xffffffff;
// 登録されているインターフェースのリスト
static struct ip_iface *ifaces;
// 登録されているプロトコルのリスト
static struct ip_protocol *protocols;
// 登録されている経路情報のリスト
static struct ip_route *routes;

/**
 * 文字列形式のIPv4アドレスをバイナリ形式に変換します。
 *
 * この関数は、ドットで区切られたIPv4アドレスの文字列を、32ビットの整数形式に変換します。
 * 例: "192.168.1.1" -> 0xC0A80101
 *
 * @param p 変換するIPv4アドレスの文字列
 * @param n 変換したバイナリ形式のIPv4アドレスを格納するポインタ
 * @return 成功時は0、失敗時は-1。
 */
int ip_addr_pton(const char *srcStr, ip_addr_t *dstBin)
{
    char *sp, *ep;
    int idx;
    long ret;

    sp = (char *)srcStr;          // 文字列の開始位置設定(ポインタによって、この位置から文字列全体を追跡可能)
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
        ((uint8_t *)dstBin)[idx] = ret;
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

int ip_endpoint_pton(const char *p, struct ip_endpoint *n)
{
    char *sep;
    char addr[IP_ADDR_STR_LEN] = {};
    long int port;

    sep = strrchr(p, ':');
    if (!sep)
    {
        return -1;
    }
    memcpy(addr, p, sep - p);
    if (ip_addr_pton(addr, &n->addr) == -1)
    {
        return -1;
    }
    port = strtol(sep + 1, NULL, 10);
    if (port <= 0 || port > UINT16_MAX)
    {
        return -1;
    }
    n->port = hton16(port);
    return 0;
}

char *
ip_endpoint_ntop(const struct ip_endpoint *n, char *p, size_t size)
{
    size_t offset;

    ip_addr_ntop(n->addr, p, size);
    offset = strlen(p);
    snprintf(p + offset, size - offset, ":%d", ntoh16(n->port));
    return p;
}

// IPデータをダンプ（表示）するための関数
static void ip_dump(const uint8_t *data, size_t len)
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

/**
 * IPルーティングテーブルに新しいルートを追加する関数。
 *
 * この関数は、指定されたネットワークアドレス、ネットマスク、ネクストホップ、インターフェース情報を
 * 使用して、新しいルーティングエントリを作成し、ルーティングテーブルに追加します。
 *
 * @param network  ルートのネットワークアドレス。
 * @param netmask  ルートのネットマスク。
 * @param nexthop  ルートのネクストホップアドレス。
 * @param iface    ルートのインターフェース情報。
 * @return         成功した場合、新しく作成されたルーティングエントリへのポインタ。失敗した場合はNULL。
 */
static struct ip_route *ip_route_add(ip_addr_t network, ip_addr_t netmask, ip_addr_t nexthop, struct ip_iface *iface)
{
    struct ip_route *route;
    char addr1[IP_ADDR_STR_LEN];
    char addr2[IP_ADDR_STR_LEN];
    char addr3[IP_ADDR_STR_LEN];
    char addr4[IP_ADDR_STR_LEN];

    // exercise17
    route = memory_alloc(sizeof(*route));
    if (!route)
    {
        errorf("memory_alloc() failure");
        return NULL;
    }
    route->network = network;
    route->netmask = netmask;
    route->nexthop = nexthop;
    route->iface = iface;
    route->next = routes;
    routes = route;

    infof("route added: network=%s, netmask=%s, nexthop=%s, iface=%s dev=%s",
          ip_addr_ntop(route->network, addr1, sizeof(addr1)),
          ip_addr_ntop(route->netmask, addr2, sizeof(addr2)),
          ip_addr_ntop(route->nexthop, addr3, sizeof(addr3)),
          ip_addr_ntop(route->iface->unicast, addr4, sizeof(addr4)),
          NET_IFACE(iface)->dev->name);
    return route;
}

/**
 * 指定された宛先IPアドレスに対応するルーティングエントリをルーティングテーブル(routes)から検索します。
 * もし複数のルートがマッチする場合、最長のネットマスクを持つルートが選択されます。
 *
 * @param dst 検索する宛先IPアドレス
 * @return 対応するルーティングエントリ。見つからない場合はNULL。
 */
static struct ip_route *ip_route_lookup(ip_addr_t dst)
{
    struct ip_route *route, *candidate = NULL;

    for (route = routes; route; route = route->next)
    {
        // 宛先アドレス（dst）とrouteのネットマスクを使って、宛先がこのルートのネットワークに属しているかを確認
        if ((dst & route->netmask) == route->network)
        {
            // 最も具体的なルーティングエントリ（最長のネットマスクを持つもの）を見つける
            // candidateがNULL、または、このループでのrouteのネットマスクがこれまでの候補よりも具体的(より多いビットで一致)な場合
            // 例)
            // dst=192.0.2.1
            // route1 network=192.0.0.0, netmask=255.0.0.0 (/8) … 8bit一致
            // route2 network=192.0.0.0, netmask=255.255.0.0 (/16) … 16bit一致
            // route3 network=192.0.2.0, netmask=255.255.255.0 (/24) … 24bit一致
            if (!candidate || ntoh32(candidate->netmask) < ntoh32(route->netmask))
            {
                // candidateを現在のルートに更新
                candidate = route;
            }
        }
    }
    return candidate;
}

/**
 * デフォルトゲートウェイを設定します。
 * 指定されたインターフェースとゲートウェイアドレスを使用して、デフォルトのルーティングエントリを追加します。
 *
 * @param iface デフォルトゲートウェイを設定するインターフェース
 * @param gateway デフォルトゲートウェイのIPアドレス（文字列形式）
 * @return 成功時は0、失敗時は-1。
 */
int ip_route_set_default_gateway(struct ip_iface *iface, const char *gateway)
{
    ip_addr_t gw;

    if (ip_addr_pton(gateway, &gw) == -1)
    {
        errorf("ip_addr_pton() failure, addr=%s", gateway);
        return -1;
    }
    // 0.0.0.0/0 のサブネットワークへの経路情報として登録する
    if (!ip_route_add(IP_ADDR_ANY, IP_ADDR_ANY, gw, iface))
    {
        errorf("ip_route_add() failure");
        return -1;
    }
    return 0;
}

/**
 * 指定された宛先IPアドレスに対応するインターフェースを取得します。
 * ルーティングテーブルを使用して、適切なインターフェースを検索します。
 *
 * @param dst 検索する宛先IPアドレス
 * @return 対応するIPインターフェース。見つからない場合はNULL。
 */
struct ip_iface *ip_route_get_iface(ip_addr_t dst)
{
    struct ip_route *route;

    route = ip_route_lookup(dst);
    if (!route)
    {
        return NULL;
    }
    return route->iface;
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

/**
 * IPインターフェースをネットワークデバイスに登録する関数。
 *
 * この関数は、指定されたネットワークデバイスにIPインターフェースを登録します。
 * また、該当のIPインターフェースのユニキャストアドレスとネットマスクを使用して、
 * ルーティングテーブルにデフォルトのルートを追加します。
 *
 * @param dev   IPインターフェースを登録するネットワークデバイス。
 * @param iface 登録するIPインターフェースの情報。
 * @return      成功した場合は0、失敗した場合は-1。
 */
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
    // exercise17
    // iface->unicast & iface->netmask→ユニキャストアドレスのネットワーク部を取得
    if (!ip_route_add(iface->unicast & iface->netmask, iface->netmask, IP_ADDR_ANY, iface))
    {
        errorf("ip_route_add() failure");
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

/**
 * IPプロトコルスタックに新しいプロトコルの受信処理関数を登録する関数。
 *
 * @param type     登録するプロトコルのタイプ（例：TCP, UDPなどの識別子）
 * @param handler  登録するプロトコルの受信処理関数のポインタ
 * @return 成功時は0、失敗時（既に同じタイプのプロトコルが登録されている場合やメモリ確保失敗時）は-1を返す。
 */
int ip_protocol_register(uint8_t type, void (*handler)(const uint8_t *data, size_t len, ip_addr_t src, ip_addr_t dst, struct ip_iface *iface))
{
    // 新規登録用のデータ構造体を作成
    struct ip_protocol *entry;

    // exercixe9
    // プロトコルリストの先頭のポインタを初期値に、処理が終わると次のプロトコルのポインタを格納して次のループ
    for (entry = protocols; entry; entry = entry->next)
    {
        if (entry->type == type)
        // もう登録済みならエラー返却
        {
            errorf("already exists, type=%u", type);
            return -1;
        }
    }
    entry = memory_alloc(sizeof(*entry));
    if (!entry)
    {
        errorf("memory_alloc() failure");
        return -1;
    }
    entry->type = type;
    // 引数handlerの関数をhandlerに設定
    entry->handler = handler;
    entry->next = protocols;
    protocols = entry;
    infof("registered, type=%u", entry->type);
    return 0;
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
    // forループ用の変数を宣言(C言語は変数宣言を文頭でしなければならない)
    struct ip_protocol *proto;

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

    for (proto = protocols; proto; proto = proto->next)
    {
        // IPヘッダのプロトコル番号と一致するか判定
        if (proto->type == hdr->protocol)
        {
            proto->handler((uint8_t *)hdr + hlen, total - hlen, hdr->src, hdr->dst, iface);
            return;
        }
    }
}

/**
 * IPデータを指定したインターフェースを通じて送信します。
 *
 * @param iface 送信するIPインターフェース
 * @param data 送信するデータのポインタ
 * @param len 送信するデータの長さ
 * @param dst 送信先のIPアドレス
 * @return 成功時は0以上、失敗時は-1
 */
static int ip_output_device(struct ip_iface *iface, const uint8_t *data, size_t len, ip_addr_t dst)
{
    // ハードウェアアドレス
    uint8_t hwaddr[NET_DEVICE_ADDR_LEN] = {};
    int res;

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
            // exercise14
            res = arp_resolve(NET_IFACE(iface), dst, hwaddr);
            if (res != ARP_RESOLVE_FOUND)
            {
                return res;
            }
        }
    }
    // exercise8
    return net_device_output(NET_IFACE(iface)->dev, NET_PROTOCOL_TYPE_IP, data, len, hwaddr);
}

/**
 * IPデータのコア出力処理。
 *
 * @param iface 送信するネットワークインターフェース
 * @param protocol 送信するデータのプロトコルタイプ（例：ICMP, TCP, UDPなど）
 * @param data 送信するデータのポインタ
 * @param len 送信するデータの長さ
 * @param src 送信元IPアドレス
 * @param dst 宛先IPアドレス
 * @param id IPヘッダのIDフィールド
 * @param offset フラグメントのオフセット
 * @return 成功時は送信したデータの長さ、エラー時は-1
 */
static ssize_t ip_output_core(struct ip_iface *iface, uint8_t protocol, const uint8_t *data, size_t len, ip_addr_t src, ip_addr_t dst, ip_addr_t nexthop, uint16_t id, uint16_t offset)
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
    hdr->sum = cksum16((uint16_t *)hdr, hlen, 0);
    memcpy(hdr + 1, data, len);

    debugf("dev=%s, dst=%s, protocol=%u, len=%u",
           NET_IFACE(iface)->dev->name, ip_addr_ntop(dst, addr, sizeof(addr)), protocol, total);
    ip_dump(buf, total);
    return ip_output_device(iface, buf, total, nexthop);
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

/**
 * IPデータを送信する。
 *
 * @param protocol 送信するデータのプロトコルタイプ（例：ICMP, TCP, UDPなど）
 * @param data 送信するデータのポインタ
 * @param len 送信するデータの長さ
 * @param src 送信元IPアドレス
 * @param dst 宛先IPアドレス
 * @return 成功時は送信したデータの長さ、エラー時は-1
 */
ssize_t ip_output(uint8_t protocol, const uint8_t *data, size_t len, ip_addr_t src, ip_addr_t dst)
{
    struct ip_route *route;
    struct ip_iface *iface;
    char addr[IP_ADDR_STR_LEN];
    ip_addr_t nexthop;
    uint16_t id;

    // 送信先インターフェースアドレスが0.0.0.0、送信先アドレスが255.255.255.255の時エラー
    if (src == IP_ADDR_ANY && dst == IP_ADDR_BROADCAST)
    {
        errorf("source address is required for broadcast addresses");
        return -1;
    }

    // 宛先IPアドレスのネットワーク部が一致するルーティング情報取得
    route = ip_route_lookup(dst);
    if (!route)
    {
        errorf("no route to host, addr=%s", ip_addr_ntop(dst, addr, sizeof(addr)));
        return -1;
    }
    iface = route->iface; // 宛先のインターフェース取得
    // ネットワーク部が一致しても、宛先インターフェースのアドレスが異なっていればエラーとする。
    if (src != IP_ADDR_ANY && src != iface->unicast)
    {
        errorf("unable to output with specified source address, addr=%s", ip_addr_ntop(src, addr, sizeof(addr)));
        return -1;
    }
    // nexthop … IPパケットの次の送り先（IPヘッダの宛先とは異なる）引数srcとdstの使い分けがわからん。
    nexthop = (route->nexthop != IP_ADDR_ANY) ? route->nexthop : dst;

    debugf("★わからないのでデバッグ★src=%s, dst=%s",
           ip_addr_ntop(src, addr, sizeof(addr)), ip_addr_ntop(dst, addr, sizeof(addr)));

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
    if (ip_output_core(iface, protocol, data, len, iface->unicast, dst, nexthop, id, 0) == -1)
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