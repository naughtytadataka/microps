#ifndef NET_H
#define NET_H

#include <stddef.h>
#include <stdint.h>

#ifndef IFNAMSIZ
#define IFNAMSIZ 16
#endif

#define NET_DEVICE_TYPE_DUMMY 0x0000
#define NET_DEVICE_TYPE_LOOPBACK 0x0001
#define NET_DEVICE_TYPE_ETHERNET 0x0002

#define NET_DEVICE_FLAG_UP 0x0001
#define NET_DEVICE_FLAG_LOOPBACK 0x0010
#define NET_DEVICE_FLAG_BROADCAST 0x0020
#define NET_DEVICE_FLAG_P2P 0x0040
#define NET_DEVICE_FLAG_NEED_ARP 0x0100

#define NET_DEVICE_ADDR_LEN 16

#define NET_DEVICE_IS_UP(x) ((x)->flags & NET_DEVICE_FLAG_UP)
#define NET_DEVICE_STATE(x) (NET_DEVICE_IS_UP(x) ? "up" : "down")

#define NET_PROTOCOL_TYPE_IP   0x0800
#define NET_PROTOCOL_TYPE_ARP  0x0806
#define NTT_PROTOCOL_TYPE_IPV6 0x86dd

/*
■このクラスはヘッダファイル
ヘッダファイルの役割は、関数や変数の「インターフェース」を提供すること。
これにより、他のソースファイルがこのヘッダファイルを#includeすることで、その関数や変数を使用可能になる。
externは、このヘッダファイルが「この関数や変数はどこか他の場所で定義されている」という情報を提供している。
そして、コンパイラとリンカは、実際の関数や変数の定義を探して、正しくプログラムをリンクします。
例えば、あるレストランのメニューを考えてみましょう。
メニューには様々な料理や飲み物がリストアップされていますが、それがどのように作られるのか、具体的なレシピは書かれていません。
それと同じように、ヘッダファイルは関数や変数の「メニュー」のようなもので、実際の「レシピ」（関数の実装）は別の場所にあります。
*/

struct net_device
{
    struct net_device *next; // 次のデバイスへのポインタ
    unsigned int index;
    char name[IFNAMSIZ];
    uint16_t type;  // デバイスの種別（net.h に NET_DEVICE_TYPE_XXX として定義）
    uint16_t mtu;   // mtu … デバイスのMTU(Maximum Transmission Unit)の値
    uint16_t flags; // flags …  各種フラグ（net.h に NET_DEVICE_FLAG_XXX として定義）
    uint16_t hlen;  /* header length */
    uint16_t alen;  /* address length */
    // デバイスのハードウェアアドレス等
    // ・デバイスによってアドレスサイズが異なるので大きめのバッファを用意
    // ・アドレスを持たないデバイスでは値は設定されない
    uint8_t addr[NET_DEVICE_ADDR_LEN];
    union
    {
        uint8_t peer[NET_DEVICE_ADDR_LEN];
        uint8_t broadcast[NET_DEVICE_ADDR_LEN];
    };
    struct net_device_ops *ops; // デバイスドライバに実装されている関数が設定された struct net_device_ops へのポインタ
    void *priv;                 // デバイスドライバが使うプライベートなデータへのポインタ
};

// デバイスドライバに実装されている関数へのポインタを格納
// ・送信関数（transmit）は必須, それ以外の関数は任意
struct net_device_ops
{
    // 二つ目の()で定義されている値か引数を持つ関数を格納できる※C言語は関数も引数に取れる
    int (*open)(struct net_device *dev);
    int (*close)(struct net_device *dev);
    int (*transmit)(struct net_device *dev, uint16_t type, const uint8_t *data, size_t len, const void *dst);
};

extern struct net_device *
net_device_alloc(void);
extern int
net_device_register(struct net_device *dev);
extern int
net_device_output(struct net_device *dev, uint16_t type, const uint8_t *data, size_t len, const void *dst);

extern int
net_protocol_register(uint16_t type, void (*handler)(const uint8_t *data, size_t len, struct net_device *dev));

extern int
net_input_handler(uint16_t type, const uint8_t *data, size_t len, struct net_device *dev);
extern int
net_softirq_handler(void);
extern int
net_run(void);
extern void
net_shutdown(void);
extern int
net_init(void);

#endif
