#include <stdio.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <errno.h>

#include "platform.h"
#include "util.h"
#include "ip.h"
#include "udp.h"

#define UDP_PCB_SIZE 16

// コントロールブロックの状態を示す定数
#define UDP_PCB_STATE_FREE 0
#define UDP_PCB_STATE_OPEN 1
#define UDP_PCB_STATE_CLOSING 2

// 送信元ポート番号の範囲
#define UDP_SOURCE_PORT_MIN 49152
#define UDP_SOURCE_PORT_MAX 65535

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
    struct queue_head queue;
    struct sched_ctx ctx; // スケジューラの構造体
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
            sched_ctx_init(&pcb->ctx); // 構造体の初期化
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
    pcb->state = UDP_PCB_STATE_CLOSING;
    if (sched_ctx_destroy(&pcb->ctx) == -1)
    {
        sched_wakeup(&pcb->ctx);
        return;
    }

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
 * イベントハンドラ関数。
 * 状態が「OPEN」のすべてのUDP PCB（プロトコル制御ブロック）に対して、スケジュールの割り込みを行います。
 * 
 * @param arg
 */
static void event_handler(void *arg)
{
    struct udp_pcb *pcb;

    (void)arg;
    mutex_lock(&mutex);
    for (pcb = pcbs; pcb < tailof(pcbs); pcb++)
    {
        if (pcb->state == UDP_PCB_STATE_OPEN)
        {
            sched_interrupt(&pcb->ctx);
        }
    }
    mutex_unlock(&mutex);
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
    // ハンドラの登録・設定
    if (net_event_subscribe(event_handler, NULL) == -1)
    {
        errorf("net_event_subscribe() failure");
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

/**
 * UDPでデータを指定されたエンドポイントに送信します。
 *
 * @param id       送信に使用するUDP PCB (Protocol Control Block) のID。
 * @param data     送信するデータのポインタ。
 * @param len      送信するデータの長さ。
 * @param foreign  送信先のIPエンドポイント情報。
 *
 * @return 送信したデータの長さ。エラー時は-1。
 */
ssize_t udp_sendto(int id, uint8_t *data, size_t len, struct ip_endpoint *foreign)
{
    struct udp_pcb *pcb;
    struct ip_endpoint local;
    struct ip_iface *iface;
    char addr[IP_ADDR_STR_LEN];
    uint32_t p;

    mutex_lock(&mutex);
    pcb = udp_pcb_get(id); // idからpcb取得
    if (!pcb)
    {
        errorf("pcb not found, id=%d", id);
        mutex_unlock(&mutex);
        return -1;
    }
    local.addr = pcb->local.addr;
    if (local.addr == IP_ADDR_ANY)
    {
        iface = ip_route_get_iface(foreign->addr); // IPの経路情報からあて先に到達可能なインタフェースを取得
        if (!iface)
        {
            errorf("iface not found that can reach foreign address, addr=%s",
                   ip_addr_ntop(foreign->addr, addr, sizeof(addr)));
            mutex_unlock(&mutex);
            return -1;
        }
        local.addr = iface->unicast; // 取得したインタフェースのアドレスを使う
        debugf("select local address, addr=%s", ip_addr_ntop(local.addr, addr, sizeof(addr)));
    }
    // 自分の使うポート番号が設定されていなかったら送信元ポートを自動的に選択する
    if (!pcb->local.port)
    {
        // 送信元ポート番号の範囲(49152~65535)を巡回
        for (p = UDP_SOURCE_PORT_MIN; p <= UDP_SOURCE_PORT_MAX; p++)
        {
            if (!udp_pcb_select(local.addr, hton16(p)))
            {
                // 一致するポート番号のPCBがないポーを使用する
                pcb->local.port = hton16(p);
                debugf("dinamic assign local port, port=%d", p);
                break;
            }
        }
        // 一つも無ければエラー
        if (!pcb->local.port)
        {
            debugf("failed to dinamic assign local port, addr=%s", ip_addr_ntop(local.addr, addr, sizeof(addr)));
            mutex_unlock(&mutex);
            return -1;
        }
    }
    local.port = pcb->local.port;
    mutex_unlock(&mutex);
    return udp_output(&local, foreign, data, len);
}

/**
 * UDPでデータを受信し、送信元のエンドポイント情報を取得します。
 *
 * @param id       受信に使用するUDP PCB (Protocol Control Block) のID。
 * @param buf      受信データを格納するバッファのポインタ。
 * @param size     バッファのサイズ。
 * @param foreign  送信元のIPエンドポイント情報を格納するためのポインタ。
 *
 * @return 受信したデータの長さ。エラー時は-1。
 */
ssize_t udp_recvfrom(int id, uint8_t *buf, size_t size, struct ip_endpoint *foreign)
{
    struct udp_pcb *pcb;
    struct udp_queue_entry *entry;
    ssize_t len;
    int err;

    mutex_lock(&mutex);
    pcb = udp_pcb_get(id);
    if (!pcb)
    {
        errorf("pcb not found, id=%d", id);
        mutex_unlock(&mutex);
        return -1;
    }
    // 受信キューにエントリが追加されるのを待つ
    // ただし、pcb自体がclosing状態になっていれば、エラーを返す。
    while (1)
    {
        entry = queue_pop(&pcb->queue);
        if (entry)
        {
            break;
        }

        err = sched_sleep(&pcb->ctx, &mutex, NULL); // sched_wakeup() もしくは sched_interrupt() が呼ばれるまでタスクを休止
        if (err)
        {
            // エラーだった場合は sched_interrup() による起床なので errno に EINTR を設定してエラーを返す
            debugf("interrupted");
            mutex_unlock(&mutex);
            errno = EINTR;
            return -1;
        }

        if (pcb->state == UDP_PCB_STATE_CLOSING)
        {
            debugf("closed");
            udp_pcb_release(pcb);
            mutex_unlock(&mutex);
            return -1;
        }
    }
    mutex_unlock(&mutex);
    if (foreign)
    {
        *foreign = entry->foreign; // 送信元のアドレス＆ポートをコピー
    }
    len = MIN(size, entry->len); // 引数のバッファのサイズとentryのサイズを比べて小さい方を返却する。
    memcpy(buf, entry->data, len);
    memory_free(entry);
    return len;
}