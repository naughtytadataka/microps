#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <sys/time.h>

#include "platform.h"
#include "util.h"
#include "net.h"
#include "ether.h"
#include "arp.h"
#include "ip.h"

/* see https://www.iana.org/assignments/arp-parameters/arp-parameters.txt */
#define ARP_HRD_ETHER 0x0001
/* NOTE: use same value as the Ethernet types */
#define ARP_PRO_IP ETHER_TYPE_IP

#define ARP_OP_REQUEST 1
#define ARP_OP_REPLY 2

#define ARP_CACHE_SIZE 32

#define ARP_CACHE_STATE_FREE 0
#define ARP_CACHE_STATE_INCOMPLETE 1
#define ARP_CACHE_STATE_RESOLVED 2
#define ARP_CACHE_STATE_STATIC 3

// arpヘッダの構造体
struct arp_hdr
{
    uint16_t hrd;
    uint16_t pro;
    uint8_t hln;
    uint8_t pln;
    uint16_t op;
};

// ethernet/IPペア用のARPメッセージ構造体
struct arp_ether_ip
{
    struct arp_hdr hdr;
    uint8_t sha[ETHER_ADDR_LEN]; // 送信元ハードウェアアドレス（Source Hardware Address）MACアドレス
    uint8_t spa[IP_ADDR_LEN];    // 送信元プロトコルアドレス（Source Protocol Address）IPアドレス
    uint8_t tha[ETHER_ADDR_LEN]; // 宛先ハードウェアアドレス（Target Hardware Address）
    uint8_t tpa[IP_ADDR_LEN];    // 宛先プロトコルアドレス（Target Protocol Address）※このアドレスのMACアドレスを知りたいはず。
};

// ARPキャッシュ用の構造体
struct arp_cache
{
    unsigned char state;        // キャッシュの状態
    ip_addr_t pa;               // Protocol Address
    uint8_t ha[ETHER_ADDR_LEN]; // Hardware Address
    struct timeval timestamp;   // 最終更新時刻
};

static mutex_t mutex = MUTEX_INITIALIZER;
static struct arp_cache caches[ARP_CACHE_SIZE]; // ARPキャッシュの配列（ARPテーブル）

static char *
arp_opcode_ntoa(uint16_t opcode)
{
    switch (ntoh16(opcode))
    {
    case ARP_OP_REQUEST:
        return "Request";
    case ARP_OP_REPLY:
        return "Reply";
    }
    return "Unknown";
}

/**
 * ARPメッセージを標準エラー出力にダンプする関数。
 *
 * @param data ダンプするARPメッセージのデータへのポインタ。
 * @param len  ダンプするデータの長さ（バイト単位）。
 */
static void arp_dump(const uint8_t *data, size_t len)
{
    struct arp_ether_ip *message;
    ip_addr_t spa, tpa;
    char addr[128];

    // ethernet/IPペアにキャスト
    message = (struct arp_ether_ip *)data;
    flockfile(stderr);
    fprintf(stderr, "        hrd: 0x%04x\n", ntoh16(message->hdr.hrd));
    fprintf(stderr, "        pro: 0x%04x\n", ntoh16(message->hdr.pro));
    fprintf(stderr, "        hln: %u\n", message->hdr.hln);
    fprintf(stderr, "        pln: %u\n", message->hdr.pln);
    fprintf(stderr, "         op: %u (%s)\n", ntoh16(message->hdr.op), arp_opcode_ntoa(message->hdr.op));
    fprintf(stderr, "        sha: %s\n", ether_addr_ntop(message->sha, addr, sizeof(addr)));
    memcpy(&spa, message->spa, sizeof(spa)); // spa が uint8_t [4] なので、一旦 memcpy() で ip_addr_t の変数へ取り出す
    fprintf(stderr, "        spa: %s\n", ip_addr_ntop(spa, addr, sizeof(addr)));
    fprintf(stderr, "        tha: %s\n", ether_addr_ntop(message->tha, addr, sizeof(addr)));
    memcpy(&tpa, message->tpa, sizeof(tpa)); // tpa も同様に memcpy() で ip_addr_t の変数へ取り出す
    fprintf(stderr, "        tpa: %s\n", ip_addr_ntop(tpa, addr, sizeof(addr)));
#ifdef HEXDUMP
    hexdump(stderr, data, len);
#endif
    funlockfile(stderr);
}

/**
 * ARPキャッシュエントリを削除します。
 *
 * @param cache 削除するARPキャッシュエントリへのポインタ。
 */
static void arp_cache_delete(struct arp_cache *cache)
{
    char addr1[IP_ADDR_STR_LEN];
    char addr2[ETHER_ADDR_STR_LEN];

    debugf("[ARP]DELETE: pa=%s, ha=%s", ip_addr_ntop(cache->pa, addr1, sizeof(addr1)), ether_addr_ntop(cache->ha, addr2, sizeof(addr2)));

    // exercise14
    cache->state = ARP_CACHE_STATE_FREE;
    cache->pa = 0;
    memset(cache->ha, 0, ETHER_ADDR_LEN);
    timerclear(&cache->timestamp);
}

/**
 * ARPキャッシュエントリを返却
 *
 * @return 割り当てられたARPキャッシュエントリへのポインタ。使用されていないエントリがあればそれを、なければ最も古いエントリ
 */
static struct arp_cache *arp_cache_alloc(void)
{
    struct arp_cache *entry, *oldest = NULL;

    // ARPテーブル巡回
    for (entry = caches; entry < tailof(caches); entry++)
    {
        // 使用されていない=stateがfreeのentryを返却
        if (entry->state == ARP_CACHE_STATE_FREE)
        {
            return entry;
        }
        // freeが無かった場合は最終更新時刻が一番古いentryを取得
        if (!oldest || timercmp(&oldest->timestamp, &entry->timestamp, >))
        {
            oldest = entry;
        }
    }
    // 上記の２つのif分に入らない時はoldestはNULLのまま

    // 一番古いentryを削除
    arp_cache_delete(oldest);
    return oldest;
}

/**
 * 指定されたIPアドレスに対応するARPキャッシュエントリを返却
 *
 * @param pa 検索するIPアドレス。
 * @return 対応するARPキャッシュエントリへのポインタ。見つからない場合はNULLを返します。
 */
static struct arp_cache *arp_cache_select(ip_addr_t pa)
{
    // exercise14
    struct arp_cache *entry;

    for (entry = caches; entry < tailof(caches); entry++)
    {
        if (entry->state != ARP_CACHE_STATE_FREE && entry->pa == pa)
        {
            return entry;
        }
    }
    return NULL;
}

/**
 * ARPキャッシュを更新する関数。
 *
 * @param pa IPアドレス。
 * @param ha ハードウェアアドレス。
 * @return 更新されたARPキャッシュエントリ。エントリが見つからない場合はNULL。
 */
static struct arp_cache *arp_cache_update(ip_addr_t pa, const uint8_t *ha)
{
    struct arp_cache *cache;
    char addr1[IP_ADDR_STR_LEN];
    char addr2[ETHER_ADDR_STR_LEN];

    // exercise14
    cache = arp_cache_select(pa);
    if (!cache)
    {
        return NULL;
    }
    // 状態を解決済みに更新
    cache->state = ARP_CACHE_STATE_RESOLVED;
    // Hardware Addressを更新
    memcpy(cache->ha, ha, ETHER_ADDR_LEN);
    // 最終更新時刻を更新
    gettimeofday(&cache->timestamp, NULL);

    debugf("[ARP]UPDATE: pa=%s, ha=%s", ip_addr_ntop(pa, addr1, sizeof(addr1)), ether_addr_ntop(ha, addr2, sizeof(addr2)));
    return cache;
}

/**
 * ARPキャッシュテーブルに新しいエントリを挿入します。
 *
 * @param pa プロトコルアドレス (通常はIPアドレス)
 * @param ha ハードウェアアドレス (通常はMACアドレス)
 * @return 挿入されたARPキャッシュエントリ。エントリが挿入できない場合はNULL。
 */
static struct arp_cache *arp_cache_insert(ip_addr_t pa, const uint8_t *ha)
{
    struct arp_cache *cache;
    char addr1[IP_ADDR_STR_LEN];
    char addr2[ETHER_ADDR_STR_LEN];

    // exercise14
    // 使用可能なARPテーブルのentryを取得
    cache = arp_cache_alloc();
    if (!cache)
    {
        // NULLが返却されたらエラー
        errorf("arp_cache_alloc() failure");
        return NULL;
    }
    cache->state = ARP_CACHE_STATE_RESOLVED;
    // Protocol Address(IPアドレス)を更新※updateとの違い
    cache->pa = pa;
    memcpy(cache->ha, ha, ETHER_ADDR_LEN);
    gettimeofday(&cache->timestamp, NULL);

    debugf("[ARP]INSERT: pa=%s, ha=%s", ip_addr_ntop(pa, addr1, sizeof(addr1)), ether_addr_ntop(ha, addr2, sizeof(addr2)));
    return cache;
}

/**
 * ARPリクエストを送信する。
 *
 * @param iface 送信するネットワークインターフェース
 * @param tpa ターゲットとなるプロトコルアドレス（IPアドレス）
 * @return 成功時は0以上、エラー時は-1
 */
static int arp_request(struct net_iface *iface, ip_addr_t tpa)
{
    struct arp_ether_ip request;

    // exercise15
    // ARPのメッセージ構造体を設定
    request.hdr.hrd = hton16(ARP_HRD_ETHER);
    request.hdr.pro = hton16(ARP_PRO_IP);
    request.hdr.hln = ETHER_ADDR_LEN;
    request.hdr.pln = IP_ADDR_LEN;
    request.hdr.op = hton16(ARP_OP_REQUEST);
    memcpy(request.sha, iface->dev->addr, ETHER_ADDR_LEN);
    memcpy(request.spa, &((struct ip_iface *)iface)->unicast, IP_ADDR_LEN);
    memset(request.tha, 0, ETHER_ADDR_LEN);
    memcpy(request.tpa, &tpa, IP_ADDR_LEN);

    debugf("ARP要求を送信します。 dev=%s, len=%zu", iface->dev->name, sizeof(request));
    arp_dump((uint8_t *)&request, sizeof(request));
    // exercise15
    return net_device_output(iface->dev, ETHER_TYPE_ARP, (uint8_t *)&request, sizeof(request), iface->dev->broadcast);
}

/**
 * ARPリプライメッセージを生成し、送信する関数。
 *
 * @param iface 対象のネットワークインターフェース。
 * @param tha   ターゲットハードウェアアドレス。
 * @param tpa   ターゲットプロトコルアドレス。
 * @param dst   宛先のハードウェアアドレス。
 *
 * @return 送信成功時は0、失敗時は-1。
 */
static int arp_reply(struct net_iface *iface, const uint8_t *tha, ip_addr_t tpa, const uint8_t *dst)
{
    struct arp_ether_ip reply;
    // exercise13
    // ARPメッセージの各フィールドを設定
    reply.hdr.hrd = hton16(ARP_HRD_ETHER);
    reply.hdr.pro = hton16(ARP_PRO_IP);
    reply.hdr.hln = ETHER_ADDR_LEN;
    reply.hdr.pln = IP_ADDR_LEN;
    reply.hdr.op = hton16(ARP_OP_REPLY);
    // 複数のバイトからなるデータはmemcpyを使う？
    memcpy(reply.sha, iface->dev->addr, ETHER_ADDR_LEN);
    memcpy(reply.spa, &((struct ip_iface *)iface)->unicast, IP_ADDR_LEN);
    memcpy(reply.tha, tha, ETHER_ADDR_LEN);
    memcpy(reply.tpa, &tpa, IP_ADDR_LEN);

    debugf("ARPリプライメッセージ作成 : dev=%s, len=%zu", iface->dev->name, sizeof(reply));
    arp_dump((uint8_t *)&reply, sizeof(reply));
    // arpメッセージ送信
    return net_device_output(iface->dev, ETHER_TYPE_ARP, (uint8_t *)&reply, sizeof(reply), dst);
}

/**
 * ARPメッセージを処理する関数。
 *
 * ARPメッセージを解析し、必要に応じてARPリプライを送信する。
 * この関数は、ARPリクエストのターゲットIPアドレスが自身のものである場合にのみ、
 * ARPリプライを生成・送信する。
 * @param data ARPメッセージのデータ部を指すポインタ。
 * @param len  ARPメッセージの長さ。
 * @param dev  ARPメッセージを受信したネットワークデバイス。
 */
static void arp_input(const uint8_t *data, size_t len, struct net_device *dev)
{
    struct arp_ether_ip *msg;
    ip_addr_t spa, tpa;
    struct net_iface *iface;
    int marge = 0; // 更新の可否を示すフラグ

    if (len < sizeof(*msg))
    {
        errorf("too short");
        return;
    }
    msg = (struct arp_ether_ip *)data;

    // exercise13
    if (ntoh16(msg->hdr.hrd) != ARP_HRD_ETHER || msg->hdr.hln != ETHER_ADDR_LEN)
    {
        errorf("unsupported hardware address");
        return;
    }
    if (ntoh16(msg->hdr.pro) != ARP_PRO_IP || msg->hdr.pln != IP_ADDR_LEN)
    {
        errorf("unsupported protocol address");
        return;
    }

    debugf("dev=%s, len=%zu", dev->name, len);
    arp_dump(data, len);
    // spa/tpa を memcpy() で ip_addr_t の変数へ取り出す
    memcpy(&spa, msg->spa, sizeof(spa));
    memcpy(&tpa, msg->tpa, sizeof(tpa));

    mutex_lock(&mutex); // キャッシュへのアクセスをミューテックスで保護
    // まずは送信元アドレスのキャッシュ情報の更新を試みる
    if (arp_cache_update(spa, msg->sha))
    {
        marge = 1; // 更新出来たら1にする
    }
    mutex_unlock(&mutex); // アンロックする

    // デバイスに紐づくIPインタフェースを取得する
    iface = net_device_get_iface(dev, NET_IFACE_FAMILY_IP);
    // ARP要求のターゲットプロトコルアドレスと一致するか確認
    if (iface && ((struct ip_iface *)iface)->unicast == tpa)
    {
        // 更新されていない=未登録の時
        if (!marge)
        {
            mutex_lock(&mutex);
            arp_cache_insert(spa, msg->sha); // ARPテーブルに新規登録する
            mutex_unlock(&mutex);
        }

        // exercise13
        if (ntoh16(msg->hdr.op) == ARP_OP_REQUEST)
        {
            arp_reply(iface, msg->sha, spa, msg->sha);
        }
    }
}

/**
 * ARPキャッシュから指定されたIPアドレスに対応するハードウェアアドレスを取得して引数haに反映する。
 *
 * @param iface ネットワークインターフェース情報
 * @param pa 検索するプロトコルアドレス (IPアドレス)
 * @param ha 取得したハードウェアアドレスを格納するアドレス
 * @return ARP_RESOLVE_FOUND or ARP_RESOLVE_ERROR
 */
int arp_resolve(struct net_iface *iface, ip_addr_t pa, uint8_t *ha)
{
    struct arp_cache *cache;
    char addr1[IP_ADDR_STR_LEN];
    char addr2[ETHER_ADDR_STR_LEN];

    // インターフェースがイーサネットタイプでない場合はエラー
    if (iface->dev->type != NET_DEVICE_TYPE_ETHERNET)
    {
        debugf("unsupported hardware address type");
        return ARP_RESOLVE_ERROR;
    }
    // インターフェースがIPファミリでない場合はエラー
    if (iface->family != NET_IFACE_FAMILY_IP)
    {
        debugf("unsupported protocol address type");
        return ARP_RESOLVE_ERROR;
    }
    mutex_lock(&mutex);
    // ARPキャッシュエントリを検索
    cache = arp_cache_select(pa);
    if (!cache)
    {
        // IPに一致するエントリがARPテーブルに無い

        debugf("IPアドレスに一致するキャッシュがありません。, pa=%s", ip_addr_ntop(pa, addr1, sizeof(addr1)));
        // exercise15
        // 割当て可能なentryを取得
        cache = arp_cache_alloc();
        if (!cache)
        {
            mutex_unlock(&mutex);
            errorf("arp_cache_alloc() failure");
            return ARP_RESOLVE_ERROR;
        }
        cache->state = ARP_CACHE_STATE_INCOMPLETE; // 状態は解決途中にする
        cache->pa = pa;
        gettimeofday(&cache->timestamp, NULL); // 更新時刻を未解決なのでNULLにする
        mutex_unlock(&mutex);
        arp_request(iface, pa); // ARPリクエストを送信
        return ARP_RESOLVE_INCOMPLETE;
    }
    // パケットロスの可能性を考慮して、再度ARPリクエストを送信
    if (cache->state == ARP_CACHE_STATE_INCOMPLETE)
    {
        mutex_unlock(&mutex);
        arp_request(iface, pa); /* just in case packet loss */
        return ARP_RESOLVE_INCOMPLETE;
    }

    // 検索結果のキャッシュのハードウェアアドレスを引数haにコピーする
    // ※呼び出し元にもコピーが反映される
    memcpy(ha, cache->ha, ETHER_ADDR_LEN);
    mutex_unlock(&mutex);
    debugf("[ARP]resolved, [IPアドレス]pa=%s, [MACアドレス]ha=%s",
           ip_addr_ntop(pa, addr1, sizeof(addr1)), ether_addr_ntop(ha, addr2, sizeof(addr2)));
    return ARP_RESOLVE_FOUND;
}

/**
 * プロトコルスタックにARPを登録する関数
 */
int arp_init(void)
{
    // exercise13
    if (net_protocol_register(NET_PROTOCOL_TYPE_ARP, arp_input) == -1)
    {
        errorf("net_protocol_register() failure");
        return -1;
    }
    return 0;
}
