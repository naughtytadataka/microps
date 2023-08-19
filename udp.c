#include <stdio.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>

#include "platform.h"
#include "util.h"
#include "ip.h"
#include "udp.h"

#define UDP_PCB_SIZE 16

// コントロールブロックの状態を示す定数
#define UDP_PCB_STATE_FREE 0
#define UDP_PCB_STATE_OPEN 1
#define UDP_PCB_STATE_CLOSING 2

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

// コントロールブロックの構造体
struct udp_pcb
{
    int state;
    struct ip_endpoint local; // 自分のアドレス＆ポート番号
    struct queue_head queue;  /* receive queue */
};

// 受信キューのエントリの構造体
struct udp_queue_entry
{
    struct ip_endpoint foreign; // 送信元のアドレス&ポート番号
    uint16_t len;
    uint8_t data[];
};

static mutex_t mutex = MUTEX_INITIALIZER;
static struct udp_pcb pcbs[UDP_PCB_SIZE]; // コントロールブロックの配列

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

/*
 * UDP Protocol Control Block (PCB)
 *
 * NOTE: UDP PCB functions must be called after mutex locked
 */

/**
 * UDPプロトコルコントロールブロック(PCB)を確保する関数。
 * 利用可能なPCBを探して、その状態をOPENに変更して返します。
 * 利用可能なPCBがない場合はNULLを返します。
 *
 * @return struct udp_pcb* 利用可能なPCBのポインタ、またはNULL。
 */
static struct udp_pcb *udp_pcb_alloc(void)
{
    struct udp_pcb *pcb;

    for (pcb = pcbs; pcb < tailof(pcbs); pcb++)
    {
        if (pcb->state == UDP_PCB_STATE_FREE)
        {
            pcb->state = UDP_PCB_STATE_OPEN;
            return pcb;
        }
    }
    return NULL;
}

/**
 * UDPプロトコルコントロールブロック(PCB)を解放する関数。
 * 指定されたPCBの状態をFREEに変更し、関連するキュー内のエントリも解放します。
 *
 * @param pcb struct udp_pcb* 解放するPCBのポインタ。
 */
static void udp_pcb_release(struct udp_pcb *pcb)
{
    struct queue_entry *entry;

    pcb->state = UDP_PCB_STATE_FREE;
    pcb->local.addr = IP_ADDR_ANY;
    pcb->local.port = 0;
    while (1)
    {
        entry = queue_pop(&pcb->queue);
        if (!entry)
        {
            break;
        }
        memory_free(entry);
    }
}

/**
 * 指定されたアドレスとポート番号に一致する開いているUDP PCBを選択します。
 *
 * @param addr ip_addr_t 検索するIPアドレス。
 * @param port uint16_t 検索するポート番号。
 * @return struct udp_pcb* 一致するUDP PCBのポインタ。見つからない場合はNULL。
 */
static struct udp_pcb *udp_pcb_select(ip_addr_t addr, uint16_t port)
{
    struct udp_pcb *pcb;

    for (pcb = pcbs; pcb < tailof(pcbs); pcb++)
    {
        if (pcb->state == UDP_PCB_STATE_OPEN) // OPEN状態のPCBのみが対象
        {
            // pcbのローカルアドレスか指定のアドレスがワイルドカード、もしくは、pcbのローカルアドレスが指定のアドレスと一致
            // かつ、portが一致する、pcbを返却
            if ((pcb->local.addr == IP_ADDR_ANY || addr == IP_ADDR_ANY || pcb->local.addr == addr) && pcb->local.port == port)
            {
                return pcb;
            }
        }
    }
    return NULL;
}

/**
 * 指定されたIDに対応するUDP PCBを取得します。
 *
 * @param id int 取得するUDP PCBのID。
 * @return struct udp_pcb* 対応するUDP PCBのポインタ。見つからない場合や状態がOPENでない場合はNULL。
 */
static struct udp_pcb *udp_pcb_get(int id)
{
    struct udp_pcb *pcb;

    if (id < 0 || id >= (int)countof(pcbs))
    {
        return NULL;
    }
    pcb = &pcbs[id];
    if (pcb->state != UDP_PCB_STATE_OPEN) // openのみ返却
    {
        return NULL;
    }
    return pcb;
}

/**
 * 指定されたUDP PCBのIDを取得します。
 *
 * @param pcb struct udp_pcb* IDを取得するUDP PCBのポインタ。
 * @return int UDP PCBのID。見つからない場合は-1。
 */
static int udp_pcb_id(struct udp_pcb *pcb)
{
    return indexof(pcbs, pcb);
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
    struct udp_pcb *pcb;
    struct udp_queue_entry *entry;

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
    mutex_lock(&mutex);
    pcb = udp_pcb_select(dst, hdr->dst);
    if (!pcb)
    {
        mutex_unlock(&mutex);
        return;
    }
    // exercise19
    entry = memory_alloc(sizeof(*entry) + (len - sizeof(*hdr))); // ヘッダ分引く
    if (!entry)
    {
        mutex_unlock(&mutex);
        errorf("memory_alloc() failure");
        return;
    }
    entry->foreign.addr = src;
    entry->foreign.port = hdr->src;
    entry->len = len - sizeof(*hdr);
    memcpy(entry->data, hdr + 1, entry->len);
    if (!queue_push(&pcb->queue, entry))
    {
        mutex_unlock(&mutex);
        errorf("queue_push() failure");
        return;
    }

    debugf("queue pushed: id=%d, num=%d", udp_pcb_id(pcb), pcb->queue.num);
    mutex_unlock(&mutex);
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

/*
 * UDP User Commands
 */

/**
 * UDP通信のための新しいPCB（プロトコル制御ブロック）を確保し、そのIDを返します。
 * 
 * @return 確保されたPCBのID。失敗した場合は-1。
 */
int udp_open(void)
{
    // exercise19
    struct udp_pcb *pcb;
    int id;

    mutex_lock(&mutex);
    pcb = udp_pcb_alloc();
    if (!pcb)
    {
        errorf("udp_pcb_alloc() failure");
        mutex_unlock(&mutex);
        return -1;
    }
    id = udp_pcb_id(pcb);
    mutex_unlock(&mutex);
    return id;
}

/**
 * 指定されたIDのUDP PCBを解放します。
 * 
 * @param id 解放するPCBのID。
 * @return 成功時は0、失敗時は-1。
 */
int udp_close(int id)
{
    // exercise19
    struct udp_pcb *pcb;

    mutex_lock(&mutex);
    pcb = udp_pcb_get(id);
    if (!pcb)
    {
        errorf("pcb not found, id=%d", id);
        mutex_unlock(&mutex);
        return -1;
    }
    udp_pcb_release(pcb);
    mutex_unlock(&mutex);
    return 0;
}

/**
 * 指定されたIDのUDP PCBを特定のローカルエンドポイントにバインドします。
 * 
 * @param id バインドするPCBのID。
 * @param local バインドするローカルエンドポイント。
 * @return 成功時は0、失敗時（既に使用中のエンドポイントなど）は-1。
 */
int udp_bind(int id, struct ip_endpoint *local)
{
    struct udp_pcb *pcb, *exist;
    char ep1[IP_ENDPOINT_STR_LEN];
    char ep2[IP_ENDPOINT_STR_LEN];

    mutex_lock(&mutex);
    // exercise19
    pcb = udp_pcb_get(id);
    if (!pcb)
    {
        errorf("pcb not found, id=%d", id);
        mutex_unlock(&mutex);
        return -1;
    }
    exist = udp_pcb_select(local->addr, local->port);
    if (exist)
    {
        errorf("already in use, id=%d, want=%s, exist=%s",
               id, ip_endpoint_ntop(local, ep1, sizeof(ep1)), ip_endpoint_ntop(&exist->local, ep2, sizeof(ep2)));
        mutex_unlock(&mutex);
        return -1;
    }
    pcb->local = *local;
    debugf("bound, id=%d, local=%s", id, ip_endpoint_ntop(&pcb->local, ep1, sizeof(ep1)));
    mutex_unlock(&mutex);
    return 0;
}
