#include <stdint.h>
#include <stddef.h>
#include <string.h>

#include "util.h"
#include "ip.h"
#include "icmp.h"

#define ICMP_BUFSIZ IP_PAYLOAD_SIZE_MAX

// ICMP ( Internet Control Message Protocol )

// ICMPヘッダ構造体
struct icmp_hdr
{
    uint8_t type;
    uint8_t code;
    uint16_t sum;
    uint32_t values;
};

// Echo / EchoReply メッセージ構造体（メッセージ種別が判別した段階でこちらにキャストする）
struct icmp_echo
{
    uint8_t type;
    uint8_t code;
    uint16_t sum;
    uint16_t id;
    uint16_t seq;
};

static char *
icmp_type_ntoa(uint8_t type)
{
    switch (type)
    {
    case ICMP_TYPE_ECHOREPLY:
        return "EchoReply";
    case ICMP_TYPE_DEST_UNREACH:
        return "DestinationUnreachable";
    case ICMP_TYPE_SOURCE_QUENCH:
        return "SourceQuench";
    case ICMP_TYPE_REDIRECT:
        return "Redirect";
    case ICMP_TYPE_ECHO:
        return "Echo";
    case ICMP_TYPE_TIME_EXCEEDED:
        return "TimeExceeded";
    case ICMP_TYPE_PARAM_PROBLEM:
        return "ParameterProblem";
    case ICMP_TYPE_TIMESTAMP:
        return "Timestamp";
    case ICMP_TYPE_TIMESTAMPREPLY:
        return "TimestampReply";
    case ICMP_TYPE_INFO_REQUEST:
        return "InformationRequest";
    case ICMP_TYPE_INFO_REPLY:
        return "InformationReply";
    }
    return "Unknown";
}

// デバッグ出力用関数
static void
icmp_dump(const uint8_t *data, size_t len)
{
    struct icmp_hdr *hdr;
    struct icmp_echo *echo;

    // stderrはC言語の標準ライブラリにおいて事前に定義されているファイルストリームの標準エラー出力用ポインタ
    flockfile(stderr);

    // ICMPヘッダにキャスト
    hdr = (struct icmp_hdr *)data;
    // fprintfはC言語の標準ライブラリに含まれる関数で、指定されたファイルストリームに対して書式付きの出力を行うための関数
    // 以下は全メッセージ共通
    fprintf(stderr, "       type: %u (%s)\n", hdr->type, icmp_type_ntoa(hdr->type));
    fprintf(stderr, "       code: %u\n", hdr->code);
    fprintf(stderr, "        sum: 0x%04x\n", ntoh16(hdr->sum));
    switch (hdr->type)
    {
    case ICMP_TYPE_ECHOREPLY:
    case ICMP_TYPE_ECHO:
        // エコーの時の設定
        echo = (struct icmp_echo *)hdr;
        fprintf(stderr, "         id: %u\n", ntoh16(echo->id));
        fprintf(stderr, "        seq: %u\n", ntoh16(echo->seq));
        break;
    default:
        fprintf(stderr, "     values: 0x%08x\n", ntoh32(hdr->values));
        break;
    }
#ifdef HEXDUMP
    hexdump(stderr, data, len);
#endif
    funlockfile(stderr);
}

// ICMPプロトコルの受信
void icmp_input(const uint8_t *data, size_t len, ip_addr_t src, ip_addr_t dst, struct ip_iface *iface)
{
    struct icmp_hdr *hdr;
    char addr1[IP_ADDR_STR_LEN];
    char addr2[IP_ADDR_STR_LEN];

    // exercise10
    // 生成したてのicmpヘッダのデータ型のサイズ(つまり最小サイズ)よりlenが小さいか判定
    if (len < sizeof(*hdr))
    {
        errorf("too short");
        return;
    }
    // 引数のdataのポインタをicmpヘッダのポインタにキャストする
    hdr = (struct icmp_hdr *)data;
    // チェックサムの検証
    if (cksum16((uint16_t *)data, len, 0) != 0)
    {
        errorf("checksum error, sum=0x%04x, verify=0x%04x", ntoh16(hdr->sum), ntoh16(cksum16((uint16_t *)data, len, -hdr->sum)));
        return;
    }

    debugf("ICMPメッセージを受信 : %s => %s, len=%zu", ip_addr_ntop(src, addr1, sizeof(addr1)), ip_addr_ntop(dst, addr2, sizeof(addr2)), len);
    icmp_dump(data, len);
    switch (hdr->type)
    {
    case ICMP_TYPE_ECHO:
        // exercise11
        // ICMPの出力関数呼び出し
        icmp_output(ICMP_TYPE_ECHOREPLY, hdr->code, hdr->values, (uint8_t *)(hdr + 1), len - sizeof(*hdr), iface->unicast, src);
        break;
    default:
        break;
    }
}

/**
 * ICMPメッセージを送信する。
 * 
 * @param type ICMPメッセージのタイプ
 * @param code ICMPメッセージのコード
 * @param values ICMPメッセージの追加情報
 * @param data ICMPデータ部分のポインタ
 * @param len ICMPデータ部分の長さ
 * @param src 送信元IPアドレス
 * @param dst 宛先IPアドレス
 * @return 成功時は0以上、エラー時は-1
 */
int icmp_output(uint8_t type, uint8_t code, uint32_t values, const uint8_t *data, size_t len, ip_addr_t src, ip_addr_t dst)
{
    uint8_t buf[ICMP_BUFSIZ];
    struct icmp_hdr *hdr;
    size_t msg_len;
    char addr1[IP_ADDR_STR_LEN];
    char addr2[IP_ADDR_STR_LEN];

    hdr = (struct icmp_hdr *)buf;

    // exercise11
    hdr->type = type;
    hdr->code = code;
    hdr->sum = 0;
    hdr->values = values;
    memcpy(hdr + 1, data, len);
    msg_len = sizeof(*hdr) + len;
    hdr->sum = cksum16((uint16_t *)hdr, msg_len, 0);

    debugf("ICMPメッセージを送信 : %s => %s, len=%zu", ip_addr_ntop(src, addr1, sizeof(addr1)), ip_addr_ntop(dst, addr2, sizeof(addr2)), msg_len);
    icmp_dump((uint8_t *)hdr, msg_len);

    // exercise11
    // 実際の出力はこちら
    return ip_output(IP_PROTOCOL_ICMP, buf, msg_len, src, dst);
}

// ICMPプロトコルの初期化を行う関数
int icmp_init(void)
{
    // exercise9
    // IPプロトコルにICMPを登録※第二引数のicmp_inputがデータ構造体ip_protocolのhandlerに設定される
    if (ip_protocol_register(IP_PROTOCOL_ICMP, icmp_input) == -1)
    {
        errorf("ip_protocol_register() failure");
        return -1;
    }
    return 0;
}
