#include <stdio.h>
#include <stddef.h>
#include <signal.h>
#include <unistd.h>
#include <string.h>

#include "util.h"
#include "net.h"
#include "driver/ether_tap.h"
#include "driver/loopback.h"
#include "udp.h"
#include "test.h"
#include "ip.h"
#include "icmp.h"

// volatileでコンパイラによる最適化の対象から除外する。
// これは、その変数がプログラムの実行中に予期せず変更される可能性がある変数につける
// C言語では、int型の変数は論理式の中で真偽値として評価可能。値が0=false、0以外=true
static volatile sig_atomic_t terminate;

static void
on_signal(int s)
{
    (void)s;
    terminate = 1;
    close(0); // 標準入力を閉じる（fgetsで待ち続けて固まらないように）
}

static int
setup(void)
{
    struct net_device *dev;
    struct ip_iface *iface;

    signal(SIGINT, on_signal);
    if (net_init() == -1)
    {
        errorf("net_init() failure");
        return -1;
    }
    dev = loopback_init();
    if (!dev)
    {
        errorf("loopback_init() failure");
        return -1;
    }
    iface = ip_iface_alloc(LOOPBACK_IP_ADDR, LOOPBACK_NETMASK);
    if (!iface)
    {
        errorf("ip_iface_alloc() failure");
        return -1;
    }
    if (ip_iface_register(dev, iface) == -1)
    {
        errorf("ip_iface_register() failure");
        return -1;
    }
    dev = ether_tap_init(ETHER_TAP_NAME, ETHER_TAP_HW_ADDR);
    if (!dev)
    {
        errorf("ether_tap_init() failure");
        return -1;
    }
    iface = ip_iface_alloc(ETHER_TAP_IP_ADDR, ETHER_TAP_NETMASK);
    if (!iface)
    {
        errorf("ip_iface_alloc() failure");
        return -1;
    }
    if (ip_iface_register(dev, iface) == -1)
    {
        errorf("ip_iface_register() failure");
        return -1;
    }
    if (ip_route_set_default_gateway(iface, DEFAULT_GATEWAY) == -1)
    {
        errorf("ip_route_set_default_gateway() failure");
        return -1;
    }
    if (net_run() == -1)
    {
        errorf("net_run() failure");
        return -1;
    }
    return 0;
}

static void
cleanup(void)
{
    net_shutdown();
}

/**
 * メイン関数
 * UDPクライアントの実装。標準入力から受け取ったデータを指定されたアドレスとポートに送信する。
 * 
 * @param argc コマンドライン引数の数
 * @param argv コマンドライン引数の配列
 * @return 成功時は0、失敗時は-1
 */
int main(int argc, char *argv[])
{
    int soc;
    struct ip_endpoint foreign;
    uint8_t buf[1024];

    if (setup() == -1)
    {
        errorf("setup() failure");
        return -1;
    }
    soc = udp_open();
    if (soc == -1)
    {
        errorf("udp_open() failure");
        return -1;
    }
    ip_endpoint_pton("192.0.2.1:10007", &foreign);// あて先のIPアドレス＆ポート番号設定

    while (!terminate)
    {
        // 標準入力（キーボード入力）から1行読み込む
        if (!fgets((char *)buf, sizeof(buf), stdin))
        {
            break;
        }
        // あて先へ送信する
        if (udp_sendto(soc, buf, strlen((char *)buf), &foreign) == -1)
        {
            errorf("sock_sendto() failure");
            break;
        }
    }
    udp_close(soc);
    cleanup();
    return 0;
}
