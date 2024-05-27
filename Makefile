SRC = $(wildcard *.c)
EXE = $(patsubst %.c, %, ${SRC})

# -Wl,--trace-symbol,SYMBOL
# CREF=-Wl,--cref
TRACE=-Wl,--trace # 打印GCC搜寻共享库目录
RPATH=-Wl,-rpath=/usr/local/lib64
PEDANTIC=-pedantic
CFLAGS= -rdynamic -DDEBUG -g -O0 -Wall -Wextra \
	${PEDANTIC} \
	${RPATH} \
	# ${CREF} \
	# ${TRACE} 

# quictls(openssl)
LDFLAGS=-L/usr/local/lib64 

.PHONY: build_dir all
all: build_dir ${EXE}
	
build_dir: 
	@mkdir -p build

%: %.c
	@gcc ${CFLAGS} -o build/$@ $<  \
		${LDFLAGS} \
		-lssl -lcrypto \
		-lngtcp2 -lngtcp2_crypto_quictls \
		-lnghttp3 

http3: build_dir client
	@SSLKEYLOGFILE=keylog.txt ./build/client \
		"www.example.org" 443

clean: 
	rm -rfv build