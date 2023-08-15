APPS = 

DRIVERS = driver/dummy.o \
          driver/loopback.o \

OBJS = util.o \
       net.o \
       ip.o \
       icmp.o \
       ether.o \
       arp.o \

TESTS = test/step0.exe \
	test/step1.exe \
	test/step2.exe \
  test/step3.exe \
  test/step4.exe \
  test/step5.exe \
  test/step6.exe \
  test/step7.exe \
  test/step8.exe \
  test/step9.exe \
  test/step10.exe \
  test/step11.exe \
  test/step12.exe \
  test/step13.exe \
  test/step14.exe \
  test/step15.exe \



CFLAGS := $(CFLAGS) -g -W -Wall -Wno-unused-parameter -iquote .

ifeq ($(shell uname),Linux)
  # Linux specific settings
  BASE = platform/linux
  # CFLAGSはコンパイラに渡すフラグを格納する変数
  # `-pthread`、POSIXスレッドを使用するためのフラグ。Linuxでのマルチスレッドプログラムをコンパイルする際に必要。
  # `-iquote $(BASE)`、コンパイラにヘッダファイルを探すための追加のディレクトリを指示するフラグ。ここでは、Linux用のヘッダファイルが格納されているディレクトリを指定しています。
  CFLAGS := $(CFLAGS) -pthread -iquote $(BASE)
  DRIVERS := $(DRIVERS) $(BASE)/driver/ether_tap.o
  # OBJSは、コンパイルが必要なオブジェクトファイルのリストを格納する変数。
  # ここでは、Linux用の`intr.o`オブジェクトファイルをリストに追加。
  # `$(BASE)/intr.o`は、`platform/linux/intr.o`を指す。
  OBJS := $(OBJS) $(BASE)/intr.o
endif

ifeq ($(shell uname),Darwin)
  # macOS specific settings
endif

.SUFFIXES:
.SUFFIXES: .c .o

.PHONY: all clean

all: $(APPS) $(TESTS)

$(APPS): %.exe : %.o $(OBJS) $(DRIVERS)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

$(TESTS): %.exe : %.o $(OBJS) $(DRIVERS) test/test.h
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

.c.o:
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -rf $(APPS) $(APPS:.exe=.o) $(OBJS) $(DRIVERS) $(TESTS) $(TESTS:.exe=.o)
