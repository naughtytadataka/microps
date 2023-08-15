#include <stdio.h>
#include <stdint.h>
#include <string.h>

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
    // デバイスに紐づくIPインタフェースを取得する
    iface = net_device_get_iface(dev, NET_IFACE_FAMILY_IP);
    // ARP要求のターゲットプロトコルアドレスと一致するか確認
    if (iface && ((struct ip_iface *)iface)->unicast == tpa)
    {
        // exercise13
        if (ntoh16(msg->hdr.op) == ARP_OP_REQUEST)
        {
            arp_reply(iface, msg->sha, spa, msg->sha);
        }
    }
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
