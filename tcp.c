#include <stdio.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>

#include "platform.h"
#include "util.h"
#include "ip.h"
#include "tcp.h"

// TCPヘッダのフラグフィールドの値
#define TCP_FLG_FIN 0x01  // FINフラグ: 接続の終了を示す
#define TCP_FLG_SYN 0x02  // SYNフラグ: 接続の開始を示す
#define TCP_FLG_RST 0x04  // RSTフラグ: 接続のリセットを示す
#define TCP_FLG_PSH 0x08  // PSHフラグ: 受信側にデータの即時処理を要求する
#define TCP_FLG_ACK 0x10  // ACKフラグ: 前回の通信を確認する
#define TCP_FLG_URG 0x20  // URGフラグ: 緊急データの存在を示す

// TCPフラグが指定された値と完全に一致するかどうかを確認します。x 検査するTCPフラグ。y 一致を確認する値。フラグが指定された値と完全に一致する場合は1、それ以外の場合は0。
#define TCP_FLG_IS(x, y) ((x & 0x3f) == (y))

// TCPフラグが指定されたビットを持っているかどうかを確認します。x 検査するTCPフラグ。y 確認するビットの値。フラグが指定されたビットを持っている場合は1、それ以外の場合は0。
#define TCP_FLG_ISSET(x, y) ((x & 0x3f) & (y) ? 1 : 0)

#define TCP_PCB_SIZE 16

#define TCP_PCB_STATE_FREE 0
#define TCP_PCB_STATE_CLOSED 1
#define TCP_PCB_STATE_LISTEN 2
#define TCP_PCB_STATE_SYN_SENT 3
#define TCP_PCB_STATE_SYN_RECEIVED 4
#define TCP_PCB_STATE_ESTABLISHED 5
#define TCP_PCB_STATE_FIN_WAIT1 6
#define TCP_PCB_STATE_FIN_WAIT2 7
#define TCP_PCB_STATE_CLOSING 8
#define TCP_PCB_STATE_TIME_WAIT 9
#define TCP_PCB_STATE_CLOSE_WAIT 10
#define TCP_PCB_STATE_LAST_ACK 11

// TCPの疑似ヘッダの構造体(チェックサム用)
struct pseudo_hdr
{
    uint32_t src;
    uint32_t dst;
    uint8_t zero;
    uint8_t protocol;
    uint16_t len;
};

// TCPヘッダの構造体
struct tcp_hdr
{
    uint16_t src;
    uint16_t dst;
    uint32_t seq;
    uint32_t ack;
    uint8_t off;
    uint8_t flg;
    uint16_t wnd;
    uint16_t sum;
    uint16_t up;
};

struct tcp_segment_info
{
    uint32_t seq;
    uint32_t ack;
    uint16_t len;
    uint16_t wnd;
    uint16_t up;
};

// コントロールブロックの構造体
struct tcp_pcb
{
    int state;                  // TCPの現在の状態（例：接続中、待機中など）
    struct ip_endpoint local;   // この接続のローカルエンドポイント（自分のIPアドレスとポート番号）
    struct ip_endpoint foreign; // この接続の外部エンドポイント（相手のIPアドレスとポート番号）

    // 送信時に必要となる情報
    struct
    {
        uint32_t nxt; // 次に送信するシーケンス番号
        uint32_t una; // まだ確認されていない最初のシーケンス番号
        uint16_t wnd; // 送信ウィンドウサイズ
        uint16_t up;  // 送信の緊急ポインタ
        uint32_t wl1; // ウィンドウ更新のための最後のシーケンス番号
        uint32_t wl2; // ウィンドウ更新のための最後の確認応答番号
    } snd;
    uint32_t iss; // 初期送信シーケンス番号

    // 受信時に必要となる情報
    struct
    {
        uint32_t nxt; // 次に受信する予定のシーケンス番号
        uint16_t wnd; // 受信ウィンドウサイズ
        uint16_t up;  // 受信の緊急ポインタ
    } rcv;

    uint32_t irs;         // 初期受信シーケンス番号
    uint16_t mtu;         // 最大転送ユニット（この接続で送受信できる最大のデータサイズ）
    uint16_t mss;         // 最大セグメントサイズ（TCPセグメントの最大サイズ）
    uint8_t buf[65535];   // 受信データを一時的に保存するバッファ
    struct sched_ctx ctx; // スケジューリングに関する情報（スレッドの同期や待機に使用）
};

static mutex_t mutex = MUTEX_INITIALIZER;
static struct tcp_pcb pcbs[TCP_PCB_SIZE];

/**
 * TCPフラグを文字列として表現する関数。
 *
 * @param flg TCPフラグを表す8ビットの整数。
 * @return フラグを表す文字列。例: "--UAPRSF" など。
 *         URG, ACK, PSH, RST, SYN, FINの各フラグがセットされている場合は対応する文字が、
 *         セットされていない場合は'-'が表示される。
 *
 */
static char *tcp_flg_ntoa(uint8_t flg)
{
    static char str[9];

    snprintf(str, sizeof(str), "--%c%c%c%c%c%c",
             TCP_FLG_ISSET(flg, TCP_FLG_URG) ? 'U' : '-',
             TCP_FLG_ISSET(flg, TCP_FLG_ACK) ? 'A' : '-',
             TCP_FLG_ISSET(flg, TCP_FLG_PSH) ? 'P' : '-',
             TCP_FLG_ISSET(flg, TCP_FLG_RST) ? 'R' : '-',
             TCP_FLG_ISSET(flg, TCP_FLG_SYN) ? 'S' : '-',
             TCP_FLG_ISSET(flg, TCP_FLG_FIN) ? 'F' : '-');
    return str;
}

/**
 * TCPヘッダの内容を標準エラー出力にダンプ（表示）します。
 *
 * @param data TCPヘッダの先頭を指すポインタ。
 * @param len  ダンプするデータの長さ（バイト単位）。
 */
static void tcp_dump(const uint8_t *data, size_t len)
{
    struct tcp_hdr *hdr;

    flockfile(stderr);
    hdr = (struct tcp_hdr *)data;
    fprintf(stderr, "        src: %u\n", ntoh16(hdr->src));
    fprintf(stderr, "        dst: %u\n", ntoh16(hdr->dst));
    fprintf(stderr, "        seq: %u\n", ntoh32(hdr->seq));
    fprintf(stderr, "        ack: %u\n", ntoh32(hdr->ack));
    fprintf(stderr, "        off: 0x%02x (%d)\n", hdr->off, (hdr->off >> 4) << 2);
    fprintf(stderr, "        flg: 0x%02x (%s)\n", hdr->flg, tcp_flg_ntoa(hdr->flg));
    fprintf(stderr, "        wnd: %u\n", ntoh16(hdr->wnd));
    fprintf(stderr, "        sum: 0x%04x\n", ntoh16(hdr->sum));
    fprintf(stderr, "         up: %u\n", ntoh16(hdr->up));
#ifdef HEXDUMP
    hexdump(stderr, data, len);
#endif
    funlockfile(stderr);
}

/*
 * TCP Protocol Control Block (PCB)
 *
 * NOTE: TCP PCB functions must be called after mutex locked
 */

/**
 * @brief 空きのTCP制御ブロックを割り当てる関数。
 *
 * この関数は、利用可能なTCP制御ブロックを検索し、その制御ブロックを初期化して返します。
 *
 * @return 利用可能なTCP制御ブロックへのポインタ。利用可能なものがない場合はNULLを返します。
 */
static struct tcp_pcb *tcp_pcb_alloc(void)
{
    struct tcp_pcb *pcb;

    for (pcb = pcbs; pcb < tailof(pcbs); pcb++)
    {
        if (pcb->state == TCP_PCB_STATE_FREE)
        {
            pcb->state = TCP_PCB_STATE_CLOSED;
            sched_ctx_init(&pcb->ctx);
            return pcb;
        }
    }
    return NULL;
}

/**
 * @brief TCP制御ブロックを解放する関数。
 *
 * この関数は、指定されたTCP制御ブロックのリソースを解放し、そのメモリをクリアします。
 *
 * @param pcb 解放するTCP制御ブロックへのポインタ。
 */
static void tcp_pcb_release(struct tcp_pcb *pcb)
{
    char ep1[IP_ENDPOINT_STR_LEN];
    char ep2[IP_ENDPOINT_STR_LEN];

    if (sched_ctx_destroy(&pcb->ctx) == -1)
    {
        // pcbのスケジューリングの破棄に失敗したら、条件変数で待機しているスレッドをすべて起こす。
        sched_wakeup(&pcb->ctx);
        return;
    }
    debugf("released, local=%s, foreign=%s",
           ip_endpoint_ntop(&pcb->local, ep1, sizeof(ep1)),
           ip_endpoint_ntop(&pcb->foreign, ep2, sizeof(ep2)));
    memset(pcb, 0, sizeof(*pcb));
}

/**
 * 指定されたローカルおよび外部エンドポイントに一致するTCPプロトコル制御ブロック(PCB)を選択します。
 *
 * @param local    検索するローカルエンドポイント。ローカルアドレスとポート番号を指定します。
 * @param foreign  検索する外部エンドポイント。外部アドレスとポート番号を指定します。
 *                 この引数がNULLの場合、ローカルエンドポイントのみでPCBを検索します。
 *
 * @return 一致するTCP PCBを返します。一致するものがない場合、LISTEN状態のワイルドカードの外部アドレス/ポートを持つPCBを返します。
 *         それも見つからない場合はNULLを返します。
 */
static struct tcp_pcb *tcp_pcb_select(struct ip_endpoint *local, struct ip_endpoint *foreign)
{
    struct tcp_pcb *pcb, *listen_pcb = NULL;

    for (pcb = pcbs; pcb < tailof(pcbs); pcb++)
    {
        // 引数のローカル接続情報と一致するか確認
        if ((pcb->local.addr == IP_ADDR_ANY || pcb->local.addr == local->addr) && pcb->local.port == local->port)
        {
            if (!foreign)
            {
                // 外部アドレスが指定されていなければ、ローカル接続情報に一致するPCBを返却
                return pcb;
            }
            if (pcb->foreign.addr == foreign->addr && pcb->foreign.port == foreign->port)
            {
                // 外部接続情報と一致していれば、返却
                return pcb;
            }
            if (pcb->state == TCP_PCB_STATE_LISTEN)
            {
                if (pcb->foreign.addr == IP_ADDR_ANY && pcb->foreign.port == 0)
                {
                    // PCBがリッスン状態で、外部アドレスとポートが特定されていない（すべてのアドレス・ポートからの接続を受け入れる設定）
                    listen_pcb = pcb;
                }
            }
        }
    }
    return listen_pcb;
}

/**
 * 指定されたIDに関連付けられたTCP PCB（プロトコル制御ブロック）を取得します。
 *
 * @param id 取得したいTCP PCBのID。
 * @return 指定されたIDに関連するTCP PCB。存在しない場合やFREE状態の場合はNULLを返します。
 */
static struct tcp_pcb *tcp_pcb_get(int id)
{
    struct tcp_pcb *pcb;

    if (id < 0 || id >= (int)countof(pcbs))
    {
        return NULL;
    }
    pcb = &pcbs[id];
    if (pcb->state == TCP_PCB_STATE_FREE)
    {
        return NULL;
    }
    return pcb;
}

/**
 * 指定されたTCP PCB（プロトコル制御ブロック）のIDを取得します。
 *
 * @param pcb IDを取得したいTCP PCB。
 * @return 指定されたTCP PCBのID。
 */
static int tcp_pcb_id(struct tcp_pcb *pcb)
{
    return indexof(pcbs, pcb);
}

/**
 * TCPセグメントを出力します。指定された情報を使用してTCPヘッダを作成し、
 * その後、IPレイヤにセグメントを送信します。
 *
 * @param seq 送信するTCPセグメントのシーケンス番号。
 * @param ack 送信するTCPセグメントの確認応答番号。
 * @param flg TCPフラグ。
 * @param wnd 送信するTCPセグメントのウィンドウサイズ。
 * @param data 送信するデータのポインタ。
 * @param len 送信するデータの長さ。
 * @param local 送信元のIPエンドポイント。
 * @param foreign 宛先のIPエンドポイント。
 * @return 送信したデータの長さ。エラーが発生した場合は-1。
 */
static ssize_t tcp_output_segment(uint32_t seq, uint32_t ack, uint8_t flg, uint16_t wnd, uint8_t *data, size_t len, struct ip_endpoint *local, struct ip_endpoint *foreign)
{
    uint8_t buf[IP_PAYLOAD_SIZE_MAX] = {};
    struct tcp_hdr *hdr;
    struct pseudo_hdr pseudo;
    uint16_t psum;
    uint16_t total;
    char ep1[IP_ENDPOINT_STR_LEN];
    char ep2[IP_ENDPOINT_STR_LEN];

    hdr = (struct tcp_hdr *)buf;

    // exercise23
    hdr->src = local->port;
    hdr->dst = foreign->port;
    hdr->seq = hton32(seq);
    hdr->ack = hton32(ack);
    hdr->off = (sizeof(*hdr) >> 2) << 4;
    hdr->flg = flg;
    hdr->wnd = hton16(wnd);
    hdr->sum = 0;
    hdr->up = 0;
    memcpy(hdr + 1, data, len);
    pseudo.src = local->addr;
    pseudo.dst = foreign->addr;
    pseudo.zero = 0;
    pseudo.protocol = IP_PROTOCOL_TCP;
    total = sizeof(*hdr) + len;
    pseudo.len = hton16(total);
    psum = ~cksum16((uint16_t *)&pseudo, sizeof(pseudo), 0);
    hdr->sum = cksum16((uint16_t *)hdr, total, psum);
    debugf("%s => %s, len=%zu (payload=%zu)",
           ip_endpoint_ntop(local, ep1, sizeof(ep1)),
           ip_endpoint_ntop(foreign, ep2, sizeof(ep2)),
           total, len);
    tcp_dump((uint8_t *)hdr, total);
    // exercise23
    if (ip_output(IP_PROTOCOL_TCP, (uint8_t *)hdr, total, local->addr, foreign->addr) == -1)
    {
        return -1;
    }
    return len;
}

/**
 * 指定されたTCP制御ブロックを使用してTCPセグメントを出力します。
 * シーケンス番号や確認応答番号など、必要な情報はTCP制御ブロックから取得出来る。
 *
 * @param pcb 使用するTCP制御ブロックのポインタ。
 * @param flg TCPフラグ。
 * @param data 送信するデータのポインタ。
 * @param len 送信するデータの長さ。
 * @return 送信したデータの長さ。エラーが発生した場合は-1。
 */
static ssize_t tcp_output(struct tcp_pcb *pcb, uint8_t flg, uint8_t *data, size_t len)
{
    uint32_t seq;

    seq = pcb->snd.nxt;
    if (TCP_FLG_ISSET(flg, TCP_FLG_SYN))
    {
        seq = pcb->iss; // SYNフラグが指定されるのは初回送信時なので iss（初期送信シーケンス番号）を使う
    }
    if (TCP_FLG_ISSET(flg, TCP_FLG_SYN | TCP_FLG_FIN) || len)
    {
    }
    // PCBの情報を使ってTCPセグメントを送信
    return tcp_output_segment(seq, pcb->rcv.nxt, flg, pcb->rcv.wnd, data, len, &pcb->local, &pcb->foreign);
}

/* rfc793 - section 3.9 [Event Processing > SEGMENT ARRIVES] */

/**
 * TCPセグメントが到着したときの処理を行います。
 * 
 * 既存の接続(PCB: Protocol Control Block)を検索し、該当する接続が存在しない、または接続が閉じられている場合、
 * 必要に応じてRST(リセット)フラグを持つTCPセグメントを送信します。
 *
 * @param seg TCPセグメントの情報を持つ構造体。
 * @param flags TCPヘッダのフラグ。
 * @param data TCPセグメントのペイロードデータ。
 * @param len ペイロードデータの長さ。
 * @param local ローカルエンドポイントの情報。
 * @param foreign 外部エンドポイントの情報。
 */
static void tcp_segment_arrives(struct tcp_segment_info *seg, uint8_t flags, uint8_t *data, size_t len, struct ip_endpoint *local, struct ip_endpoint *foreign)
{
    struct tcp_pcb *pcb;

    pcb = tcp_pcb_select(local, foreign);
    if (!pcb || pcb->state == TCP_PCB_STATE_CLOSED) {
        if (TCP_FLG_ISSET(flags, TCP_FLG_RST)) {
            return;
        }
        // 使用していないポートに何か飛んで来たら RST を返す
        if (!TCP_FLG_ISSET(flags, TCP_FLG_ACK)) {
            tcp_output_segment(0, seg->seq + seg->len, TCP_FLG_RST | TCP_FLG_ACK, 0, NULL, 0, local, foreign);
        } else {
            tcp_output_segment(seg->ack, 0, TCP_FLG_RST, 0, NULL, 0, local, foreign);
        }
        return;
    }
}

/**
 * TCPデータを処理するための入力関数。
 * この関数は、受信したTCPデータの基本的な検証を行い、
 * 必要に応じてエラーメッセージを出力します。
 *
 * @param data     受信したTCPデータへのポインタ。
 * @param len      受信したデータの長さ。
 * @param src      送信元のIPアドレス。
 * @param dst      送信先のIPアドレス。
 * @param iface    受信したインターフェースの情報。
 */
static void tcp_input(const uint8_t *data, size_t len, ip_addr_t src, ip_addr_t dst, struct ip_iface *iface)
{
    struct tcp_hdr *hdr;
    struct pseudo_hdr pseudo;
    uint16_t psum;
    char addr1[IP_ADDR_STR_LEN];
    char addr2[IP_ADDR_STR_LEN];
    struct ip_endpoint local, foreign;
    uint16_t hlen;
    struct tcp_segment_info seg;


    if (len < sizeof(*hdr))
    {
        errorf("too short");
        return;
    }
    hdr = (struct tcp_hdr *)data;

    // exercise22
    pseudo.src = src;
    pseudo.dst = dst;
    pseudo.zero = 0;
    pseudo.protocol = IP_PROTOCOL_TCP;
    pseudo.len = hton16(len);
    psum = ~cksum16((uint16_t *)&pseudo, sizeof(pseudo), 0);
    if (cksum16((uint16_t *)hdr, len, psum) != 0)
    {
        errorf("checksum error: sum=0x%04x, verify=0x%04x", ntoh16(hdr->sum), ntoh16(cksum16((uint16_t *)hdr, len, -hdr->sum + psum)));
        return;
    }

    // exercise22
    if (src == IP_ADDR_BROADCAST || src == iface->broadcast || dst == IP_ADDR_BROADCAST || dst == iface->broadcast)
    {
        errorf("only supports unicast, src=%s, dst=%s",
               ip_addr_ntop(src, addr1, sizeof(addr1)), ip_addr_ntop(dst, addr2, sizeof(addr2)));
        return;
    }
    debugf("%s:%d => %s:%d, len=%zu (payload=%zu)",
           ip_addr_ntop(src, addr1, sizeof(addr1)), ntoh16(hdr->src),
           ip_addr_ntop(dst, addr2, sizeof(addr2)), ntoh16(hdr->dst),
           len, len - sizeof(*hdr));
    tcp_dump(data, len);

    local.addr = dst;
    local.port = hdr->dst;
    foreign.addr = src;
    foreign.port = hdr->src;
    hlen = (hdr->off >> 4) << 2;
    seg.seq = ntoh32(hdr->seq);
    seg.ack = ntoh32(hdr->ack);
    seg.len = len - hlen;
    // SYNまたはFINフラグがセットされている場合、データ長を1増やす
    if (TCP_FLG_ISSET(hdr->flg, TCP_FLG_SYN)) {
        seg.len++;
    }
    if (TCP_FLG_ISSET(hdr->flg, TCP_FLG_FIN)) {
        seg.len++;
    }
    seg.wnd = ntoh16(hdr->wnd);
    seg.up = ntoh16(hdr->up);
    mutex_lock(&mutex);
    tcp_segment_arrives(&seg, hdr->flg, (uint8_t *)hdr + hlen, len - hlen, &local, &foreign);
    mutex_unlock(&mutex);
    return;
}

/**
 * TCPプロトコルの初期化を行います。
 * IPプロトコルスタックにTCPプロトコルのハンドラを登録します。
 *
 * @return 成功時は0、失敗時は-1を返します。
 */
int tcp_init(void)
{
    // exercise22
    if (ip_protocol_register(IP_PROTOCOL_TCP, tcp_input) == -1)
    {
        errorf("ip_protocol_register() failure");
        return -1;
    }
    return 0;
}
