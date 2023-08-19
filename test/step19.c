#include <stdio.h>
#include <stddef.h>
#include <signal.h>
#include <unistd.h>

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
 * UDPサーバーのメイン関数。
 * このサーバーは、指定されたエンドポイント（ここでは "0.0.0.0:7"）でデータを待機し、
 * データが受信されるとそれを処理します。
 *
 * @param argc コマンドライン引数の数。
 * @param argv コマンドライン引数の配列。
 * @return 成功時は0、エラー時は-1。
 */
int main(int argc, char *argv[])
{
    int soc; // UDP通信のためのソケット
    struct ip_endpoint local;

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

    // エンドポイントの情報を設定
    ip_endpoint_pton("0.0.0.0:7", &local); // 0.0.0.0（ワイルドカードアドレス）を指定すると利用可能な全てのアドレスが対象となる
    // ソケットをエンドポイントにバインド
    if (udp_bind(soc, &local) == -1)
    {
        errorf("udp_bind() failure");
        udp_close(soc);
        return -1;
    }
    debugf("waiting for data...");
    while (!terminate)
    {
        sleep(1);
    }
    udp_close(soc);
    cleanup();
    return 0;
}
