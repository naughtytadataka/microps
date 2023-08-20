#include <stdio.h>
#include <stddef.h>
#include <signal.h>
#include <unistd.h>
#include <errno.h>

#include "util.h"
#include "net.h"
#include "driver/ether_tap.h"
#include "driver/loopback.h"
#include "udp.h"
#include "test.h"
#include "ip.h"
#include "icmp.h"
#include "tcp.h"

// volatileでコンパイラによる最適化の対象から除外する。
// これは、その変数がプログラムの実行中に予期せず変更される可能性がある変数につける
// C言語では、int型の変数は論理式の中で真偽値として評価可能。値が0=false、0以外=true
static volatile sig_atomic_t terminate;

static void
on_signal(int s)
{
    (void)s;
    terminate = 1;
    net_raise_event();
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
 * メイン関数。
 * TCPエコーサーバーの実装。特定のポートで接続を待ち、接続が確立されるとデータの受信を開始します。
 * `terminate`変数が真になるまでサーバーは動作し続けます。
 *
 * @param argc コマンドライン引数の数。
 * @param argv コマンドライン引数の文字列配列。
 * @return 成功時は0、失敗時は-1。
 */
int main(int argc, char *argv[])
{
    struct ip_endpoint local;
    int soc;
    uint8_t buf[2048];
    ssize_t ret;

    if (setup() == -1)
    {
        errorf("setup() failure");
        return -1;
    }

    // ローカルのIPアドレスとポート番号を設定
    ip_endpoint_pton("0.0.0.0:7", &local);

    // TCP接続を開く（ここではパッシブオープンを行う）
    soc = tcp_open_rfc793(&local, NULL, 0);
    if (soc == -1)
    {
        errorf("tcp_open_rfc793() failure");
        return -1;
    }

    // 終了シグナルが来るまでデータの受信と送信を繰り返す
    while (!terminate)
    {
        ret = tcp_receive(soc, buf, sizeof(buf)); // データを受信
        if (ret <= 0)
        {
            break;
        }
        hexdump(stderr, buf, ret);
        tcp_send(soc, buf, ret); // 受信データをそのまま送信
    }
    tcp_close(soc);
    cleanup();
    return 0;
}
