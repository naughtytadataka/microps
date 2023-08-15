#include <stdint.h>
#include <stddef.h>

#include "util.h"
#include "ip.h"
#include "icmp.h"

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

// ICMPプロトコルの設定？
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

    debugf("%s => %s, len=%zu", ip_addr_ntop(src, addr1, sizeof(addr1)), ip_addr_ntop(dst, addr2, sizeof(addr2)), len);
    debugdump(data, len);
    icmp_dump(data, len);
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
