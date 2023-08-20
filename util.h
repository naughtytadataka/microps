#ifndef UTIL_H
#define UTIL_H

#include <stdio.h>
#include <stdint.h>
#include <unistd.h>

/*
 * Compare
 */

#ifndef MAX
#define MAX(x, y) ((x) > (y) ? (x) : (y))
#endif
// MINは、2つの引数xとyを取り、それらのうち小さい方の値を返します。
#ifndef MIN
#define MIN(x, y) ((x) < (y) ? (x) : (y))
#endif

/*
 * Array
 */

#define countof(x) ((sizeof(x) / sizeof(*x)))
// 配列xの最後の要素の次のアドレスを返すマクロ
#define tailof(x) (x + countof(x))
// このマクロは、yがxの中で何番目に位置しているかのインデックスを返す。
// xは配列の開始アドレス、yは配列内の特定の要素のアドレスを示す。
#define indexof(x, y) (((uintptr_t)y - (uintptr_t)x) / sizeof(*y))

/*
 * Time
 */

// 指定されたtimeval構造体にマイクロ秒を追加するマクロ。
// @param x timeval構造体へのポインタ。この構造体にマイクロ秒が追加されます。
// @param y 追加するマイクロ秒の数。
#define timeval_add_usec(x, y)       \
    do                               \
    {                                \
        (x)->tv_sec += y / 1000000;  \
        (x)->tv_usec += y % 1000000; \
        if ((x)->tv_usec >= 1000000) \
        {                            \
            (x)->tv_sec += 1;        \
            (x)->tv_usec -= 1000000; \
        }                            \
    } while (0);

#define timespec_add_nsec(x, y)         \
    do                                  \
    {                                   \
        (x)->tv_sec += y / 1000000000;  \
        (x)->tv_nsec += y % 1000000000; \
        if ((x)->tv_nsec >= 1000000000) \
        {                               \
            (x)->tv_sec += 1;           \
            (x)->tv_nsec -= 1000000000; \
        }                               \
    } while (0);

/*
 * Logging
 */

#define errorf(...) lprintf(stderr, 'E', __FILE__, __LINE__, __func__, __VA_ARGS__)
#define warnf(...) lprintf(stderr, 'W', __FILE__, __LINE__, __func__, __VA_ARGS__)
#define infof(...) lprintf(stderr, 'I', __FILE__, __LINE__, __func__, __VA_ARGS__)
#define debugf(...) lprintf(stderr, 'D', __FILE__, __LINE__, __func__, __VA_ARGS__)

#ifdef HEXDUMP
#define debugdump(...) hexdump(stderr, __VA_ARGS__)
#else
#define debugdump(...)
#endif

extern int
lprintf(FILE *fp, int level, const char *file, int line, const char *func, const char *fmt, ...);
extern void
hexdump(FILE *fp, const void *data, size_t size);

/*
 * Queue
 */

struct queue_entry;

struct queue_head
{
    struct queue_entry *head;
    struct queue_entry *tail;
    unsigned int num;
};

extern void
queue_init(struct queue_head *queue);
extern void *
queue_push(struct queue_head *queue, void *data);
extern void *
queue_pop(struct queue_head *queue);
extern void *
queue_peek(struct queue_head *queue);
extern void
queue_foreach(struct queue_head *queue, void (*func)(void *arg, void *data), void *arg);

/*
 * Byteorder
 */

extern uint16_t
hton16(uint16_t h);
extern uint16_t
ntoh16(uint16_t n);
extern uint32_t
hton32(uint32_t h);
extern uint32_t
ntoh32(uint32_t n);

/*
 * Checksum
 */

extern uint16_t
cksum16(uint16_t *addr, uint16_t count, uint32_t init);

#endif
