/**
 * http3 client by using ngtcp2 and nghttp3
 * make http3_client && SSLKEYLOGFILE=keylog.txt ./build/http3_client --disable-early-data -k 142.251.42.238 443
 * make http3_client && SSLKEYLOGFILE=keylog.txt ./build/http3_client --disable-early-data -k www.example.org 443
 * make http3_client && SSLKEYLOGFILE=keylog.txt ./build/http3_client --disable-early-data -k $REMOTE_IP 443
 * make run_http3
 * 1. http3 stream data数据分成2个packet，后面packet只是发送了fin，没有任何数据，nghttp3不能正确处理
 * 比如 make http3_client && SSLKEYLOGFILE=keylog.txt ./build/http3_client 142.251.42.238 443 ca_cert.pem
 * fix: 主要是因为收到服务端数据后，qpack decoder stream blocked, 注释以下两行解决
	// settings.qpack_max_dtable_capacity = 4000;
	// settings.qpack_blocked_streams = 100;
 * 2. connection migration DONE
 * 3. early data 0-RTT DONE
 * 4. getopts for keyupdate, ciphers, groups etc DONE
 * 5. keyupdate DONE
 */
#include <arpa/inet.h>
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/signalfd.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/timerfd.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#include <ngtcp2/ngtcp2.h>
#include <ngtcp2/ngtcp2_crypto.h>
#include <ngtcp2/ngtcp2_crypto_quictls.h>

#include <nghttp3/nghttp3.h>

#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/ssl.h>

#include <execinfo.h>
#include <getopt.h>

#define MAX_EVENTS 64
#define MAX_BUFFER 1280
#define PRINT_BUF 512

#define SOURCE_PORT 9000
#define MIGRATION_PORT 9001

#define LOCAL_MAX_IDLE_TIMEOUT 60
/**
 * https://www.openssl.org/docs/manmaster/man3/SSL_set_alpn_protos.html
 * NOTE关于protocol-lists format
 */
#define ALPN "\x2h3"

int ssl_userdata_idx;
const char LOWER_XDIGITS[] = "0123456789abcdef";

typedef enum
{
	INFO,
	WARNING,
	ERROR
} Level;

void print_debug(int level, const char *fmt, ...)
{
	char msgbuf[PRINT_BUF];
	memset(msgbuf, 0, PRINT_BUF);
	va_list ap;

	va_start(ap, fmt);
	int n = vsnprintf(msgbuf, PRINT_BUF, fmt, ap);
	va_end(ap);

	if (n > PRINT_BUF)
		n = PRINT_BUF;
	msgbuf[n++] = '\n';

	fprintf(stderr, "[%s] %s",
			level == INFO ? "INFO" : (level == WARNING ? "WARNING" : "ERROR"),
			msgbuf);
}

struct stream
{
	int64_t stream_id;
	char *data;
	size_t datalen;
	size_t nwrite;
};

typedef struct
{
	int check_cert;			// 是否检验server证书
	int verbose;			// 是否打印调试信息
	int disable_early_data; // 是否禁用early data功能
	char *ca_file;
	char *private_key_file;
	char *session_file;					 // 保存new session ticket信息的PEM文件，用于session resumption or 0-RTT
	char *quic_transport_parameter_file; // save previous QUIC transprant parameters as PEM file, used for session resumption or 0-RTT
	char *ciphers;
	char *groups;
	int show_secret;
} Config;

struct client
{
	/* TLS1.3 related */
	SSL_CTX *ssl_ctx;
	SSL *ssl;

	/* ngtcp2 related */
	ngtcp2_crypto_conn_ref conn_ref;
	struct sockaddr_storage local_addr;
	socklen_t local_addrlen;
	struct sockaddr_storage remote_addr;
	socklen_t remote_addrlen;
	ngtcp2_conn *conn;
	ngtcp2_ccerr last_error;

	/* nghttp3 related */
	nghttp3_conn *httpconn;

	/* key update counter */
	int nkey_update;

	/* Session Resumption or 0-RTT */
	int early_data_enabled;
	int ticket_received;
	int handshake_confirmed; // 设置状态，暂时没有用到

	Config config;

	struct stream stream; // 暂时没有用到

	/* server交互socket */
	int sock_fd;
	int timer_fd;
	int epoll_fd;
	int sig_fd;
};

int get_ip_port(struct sockaddr_storage *addr, char *ip, uint16_t *port)
{
	if (ip == NULL && port == NULL)
		return 0;
	if (addr->ss_family == AF_INET)
	{
		struct sockaddr_in *addrV4 = (struct sockaddr_in *)addr;
		if (port)
			*port = ntohs(addrV4->sin_port);
		if (ip)
			inet_ntop(addrV4->sin_family, &(addrV4->sin_addr), ip, INET_ADDRSTRLEN);
		return 0;
	}
	else if (addr->ss_family == AF_INET6)
	{
		struct sockaddr_in6 *addrV6 = (struct sockaddr_in6 *)addr;
		if (ip)
			inet_ntop(addrV6->sin6_family, &(addrV6->sin6_addr), ip, INET6_ADDRSTRLEN);
		if (port)
			*port = ntohs(addrV6->sin6_port);
		return 0;
	}
	return -1;
}

void print_backtrace()
{
	void *array[10];
	size_t size;
	char **strings;
	size_t i;

	size = backtrace(array, 10);
	strings = backtrace_symbols(array, size);
	if (strings == NULL)
	{
		perror("backtrace_symbols");
		exit(-1);
	}

	printf("Obtained %zd stack frames.\n", size);
	for (i = 0; i < size; i++)
	{
		printf("%s\n", strings[i]);
	}

	free(strings);
}

uint8_t *hexdump_addr(uint8_t *dest, size_t addr)
{
	// Lower 32 bits are displayed.
	for (size_t i = 0; i < 4; ++i)
	{
		size_t a = (addr >> (3 - i) * 8) & 0xff;

		*dest++ = LOWER_XDIGITS[a >> 4];
		*dest++ = LOWER_XDIGITS[a & 0xf];
	}

	return dest;
}

uint8_t *hexdump_ascii(uint8_t *dest, const uint8_t *data, size_t datalen)
{
	*dest++ = '|';

	for (size_t i = 0; i < datalen; ++i)
	{
		/* ASCII 0x20-0x7e 为可见字符, 30 - 0, 41 - A, 61 - a */
		if (0x20 <= data[i] && data[i] <= 0x7e)
		{
			*dest++ = data[i];
		}
		else /* 不可见字符使用 . 代替 */
		{
			*dest++ = '.';
		}
	}

	*dest++ = '|';

	return dest;
}

uint8_t *hexdump8(uint8_t *dest, const uint8_t *data, size_t datalen)
{
	size_t i;

	for (i = 0; i < datalen; ++i)
	{
		*dest++ = LOWER_XDIGITS[data[i] >> 4];
		*dest++ = LOWER_XDIGITS[data[i] & 0xf];
		*dest++ = ' ';
	}

	for (; i < 8; ++i)
	{
		*dest++ = ' ';
		*dest++ = ' ';
		*dest++ = ' ';
	}

	return dest;
}

uint8_t *hexdump16(uint8_t *dest, const uint8_t *data, size_t datalen)
{
	if (datalen > 8)
	{
		dest = hexdump8(dest, data, 8);
		*dest++ = ' ';
		dest = hexdump8(dest, data + 8, datalen - 8);
		*dest++ = ' ';
	}
	else
	{
		dest = hexdump8(dest, data, datalen);
		*dest++ = ' ';
		dest = hexdump8(dest, NULL, 0);
		*dest++ = ' ';
	}

	return dest;
}

uint8_t *hexdump_line(uint8_t *dest, const uint8_t *data, size_t datalen,
					  size_t addr)
{
	dest = hexdump_addr(dest, addr);
	*dest++ = ' ';
	*dest++ = ' ';

	dest = hexdump16(dest, data, datalen);

	return hexdump_ascii(dest, data, datalen);
}

int hexdump_write(int fd, const uint8_t *data, size_t datalen)
{
	ssize_t nwrite;

	for (; (nwrite = write(fd, data, datalen)) == -1 && errno == EINTR;)
		;
	if (nwrite == -1)
	{
		return -1;
	}

	return 0;
}

int hexdump(FILE *out, const void *data, size_t datalen)
{
	if (datalen == 0)
	{
		return 0;
	}

	// min_space is the additional minimum space that the buffer must
	// accept, which is the size of a single full line output + one
	// repeat line marker ("*\n").  If the remaining buffer size is less
	// than that, flush the buffer and reset.
	const size_t min_space = 79 + 2;

	int fd = fileno(out);
	uint8_t buf[4096];
	uint8_t *last = buf;
	uint8_t *in = (uint8_t *)data;
	int repeated = 0;

	for (size_t offset = 0; offset < datalen; offset += 16)
	{
		size_t n = datalen - offset; /* 当前offset */
		uint8_t *s = in + offset;	 /* 原始数据 */

		if (n >= 16) /* 如果剩下的数据能打印一整行(16 bytes) */
		{
			n = 16;

			if (offset > 0) /* 不是首行 */
			{
				if (!strncmp((char *)s - 16, (char *)s, 16)) /* 判断数据上一行和当前行是否一样 */
				{
					if (repeated)
					{
						continue;
					}

					repeated = 1;

					*last++ = '*';
					*last++ = '\n';

					continue;
				}

				repeated = 0;
			}
		}

		last = hexdump_line(last, s, n, offset);
		*last++ = '\n';

		size_t len = (size_t)(last - buf);
		if (len + min_space > 4096)
		{
			if (hexdump_write(fd, buf, len) != 0)
			{
				return -1;
			}

			last = buf;
		}
	}

	last = hexdump_addr(last, datalen);
	*last++ = '\n';

	size_t len = (size_t)(last - buf);
	if (len)
	{
		return hexdump_write(fd, buf, len);
	}

	return 0;
}

uint64_t timestamp(void)
{
	struct timespec tp;
	if (clock_gettime(CLOCK_MONOTONIC, &tp) < 0)
		return 0;
	return (uint64_t)tp.tv_sec * NGTCP2_SECONDS + (uint64_t)tp.tv_nsec;
}

int send_packet(struct client *c, uint8_t *data, size_t datalen)
{
	struct iovec iov = {data, datalen};
	struct msghdr msg = {0};
	ssize_t nwrite;

	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;

	do
	{
		nwrite = sendmsg(c->sock_fd, &msg, 0);
	} while (nwrite == -1 && errno == EINTR);

	if (nwrite == -1)
	{
		fprintf(stderr, "sendmsg: %s\n", strerror(errno));
		return -1;
	}

	return 0;
}

int write_to_stream(struct client *c)
{
	int res;
	ngtcp2_path_storage ps;
	ngtcp2_path_storage_zero(&ps);

	uint8_t stream_buf[MAX_BUFFER];
	uint64_t ts = timestamp();

	ngtcp2_pkt_info pi;

	nghttp3_vec http3_vec[16];
	for (;;)
	{
		nghttp3_ssize sveccnt = 0;
		int fin = 0;
		int64_t stream_id = -1;

		if (c->httpconn && ngtcp2_conn_get_max_data_left(c->conn))
		{
			sveccnt = nghttp3_conn_writev_stream(c->httpconn, &stream_id, &fin, http3_vec, 16);
			if (sveccnt < 0)
			{
				fprintf(stderr, "nghttp3_conn_writev_stream failed: %s\n", nghttp3_strerror(sveccnt));
				return -1;
			}
		}
		ngtcp2_vec *datav;
		datav = (ngtcp2_vec *)http3_vec;
		uint32_t flags = NGTCP2_WRITE_STREAM_FLAG_MORE;
		if (fin)
			flags |= NGTCP2_WRITE_STREAM_FLAG_FIN;

		/**
		 * https://nghttp2.org/ngtcp2/ngtcp2_conn_writev_stream.html
		 * ndatalen 表示里面有多少stream frame数据, 注意如果只有fin的0 stream数据则值为0
		 * nwrite 表示总共写入stream_buf数据
		 */
		ngtcp2_ssize ndatalen, nwrite;
		nwrite = ngtcp2_conn_writev_stream(c->conn,
										   &ps.path,
										   &pi,
										   stream_buf, sizeof(stream_buf),
										   &ndatalen, flags,
										   stream_id,
										   datav, sveccnt,
										   ts);
		if (nwrite < 0)
		{
			switch (nwrite)
			{
			case NGTCP2_ERR_WRITE_MORE:
				assert(ndatalen >= 0);
				res = nghttp3_conn_add_write_offset(c->httpconn, stream_id, ndatalen);
				if (res < 0)
				{
					fprintf(stderr, "nghttp3_conn_add_write_offset failed: %s\n", nghttp3_strerror(res));
					return -1;
				}
				continue;
			default:
				fprintf(stderr, "ngtcp2_conn_writev_stream: %s\n", ngtcp2_strerror((int)nwrite));
				ngtcp2_ccerr_set_liberr(&c->last_error, (int)nwrite, NULL, 0);
				return -1;
			}
			return -1;
		}
		else if (ndatalen >= 0)
		{
			/* 告诉nghttp3，ngtcp2中的QUIC层接受了多少数据 */
			res = nghttp3_conn_add_write_offset(c->httpconn, stream_id, ndatalen);
			if (res < 0)
			{
				fprintf(stderr, "nghttp3_conn_add_write_offset failed: %s\n", nghttp3_strerror(res));
				ngtcp2_ccerr_set_application_error(&c->last_error, (int)nwrite, NULL, 0);
				return -1;
			}
		}
		// 不能写入frame，可能buffer太小或者拥塞控制了, 只能继续读和等待
		if (nwrite == 0)
		{
			ngtcp2_conn_update_pkt_tx_time(c->conn, ts);
			return 0;
		}

		res = send_packet(c, (uint8_t *)stream_buf, nwrite);
		if (res < 0)
		{
			if (errno == EAGAIN || errno == EWOULDBLOCK)
				break;
			fprintf(stderr, "send_packet失败\n");
			return -1;
		}

		ngtcp2_conn_update_pkt_tx_time(c->conn, ts);
		return 0;
	}
	return 0;
}

int connection_write(struct client *c)
{
	write_to_stream(c);

	ngtcp2_tstamp expiry = ngtcp2_conn_get_expiry(c->conn);
	ngtcp2_tstamp now = timestamp();
	struct itimerspec it;
	memset(&it, 0, sizeof(it));
	if (timerfd_settime(c->timer_fd, 0, &it, NULL) < 0)
	{
		perror("timerfd_settime发生错误");
		return -1;
	}
	if (expiry < now) /* 已经过期了，立即触发调用 ngtcp2_conn_handle_expiry */
	{
		it.it_value.tv_sec = 0;
		it.it_value.tv_nsec = 1;
	}
	else
	{
		it.it_value.tv_sec = (expiry - now) / NGTCP2_SECONDS;
		it.it_value.tv_nsec = ((expiry - now) % NGTCP2_SECONDS) / NGTCP2_NANOSECONDS;
	}
	if (timerfd_settime(c->timer_fd, 0, &it, NULL) < 0)
	{
		perror("timerfd_settime发生错误");
		return -1;
	}

	return 0;
}

void connection_free(struct client *c)
{
	if (c->conn)
		ngtcp2_conn_del(c->conn);
	SSL_free(c->ssl);
	SSL_CTX_free(c->ssl_ctx);

	epoll_ctl(c->epoll_fd, EPOLL_CTL_DEL, c->sock_fd, NULL);
	if (c->timer_fd > 0)
		close(c->timer_fd);
	if (c->sock_fd > 0)
		close(c->sock_fd);
	if (c->epoll_fd > 0)
		close(c->epoll_fd);
}

void connection_close(struct client *c)
{
	ngtcp2_ssize nwrite;
	ngtcp2_pkt_info pi;
	ngtcp2_path_storage ps;
	uint8_t buf[MAX_BUFFER];

	if (ngtcp2_conn_in_closing_period(c->conn) ||
		ngtcp2_conn_in_draining_period(c->conn))
	{
		goto fin;
	}

	ngtcp2_path_storage_zero(&ps);

	nwrite = ngtcp2_conn_write_connection_close(
		c->conn, &ps.path, &pi, buf, sizeof(buf), &c->last_error, timestamp());
	if (nwrite < 0)
	{
		fprintf(stderr, "ngtcp2_conn_write_connection_close: %s\n",
				ngtcp2_strerror((int)nwrite));
		goto fin;
	}

	send_packet(c, buf, (size_t)nwrite);
fin:
	epoll_ctl(c->epoll_fd, EPOLL_CTL_DEL, c->timer_fd, NULL);
}

nghttp3_nv make_nv(char *name, char *value, size_t namelen, size_t valuelen, int flags)
{
	nghttp3_nv nv = {
		(uint8_t *)name,
		(uint8_t *)value,
		namelen,
		valuelen,
		flags,
	};
	return nv;
}

int submit_http_request(struct client *c)
{
	assert(c->httpconn);
	int64_t stream_id;
	int res;

	res = ngtcp2_conn_open_bidi_stream(c->conn, &stream_id, NULL);
	if (res != 0)
	{
		fprintf(stderr, "ngtcp2_conn_open_bidi_stream failed: %s\n", ngtcp2_strerror(res));
		return -1;
	}

	nghttp3_nv nva[] = {
		make_nv(":method", "GET", 7, 3, NGHTTP3_NV_FLAG_NO_COPY_NAME | NGHTTP3_NV_FLAG_NO_COPY_VALUE),
		make_nv(":scheme", "https", 7, 5, NGHTTP3_NV_FLAG_NO_COPY_NAME | NGHTTP3_NV_FLAG_NO_COPY_VALUE),
		make_nv(":authority", "47.96.31.23", 10, 11, NGHTTP3_NV_FLAG_NO_COPY_NAME | NGHTTP3_NV_FLAG_NO_COPY_VALUE),
		make_nv(":path", "/", 5, 1, NGHTTP3_NV_FLAG_NO_COPY_NAME | NGHTTP3_NV_FLAG_NO_COPY_VALUE),
		make_nv("user-agent", "nghttp3/ngtcp2 client", 10, 21, NGHTTP3_NV_FLAG_NO_COPY_NAME | NGHTTP3_NV_FLAG_NO_COPY_VALUE),
	};
	size_t nvlen = sizeof(nva) / sizeof(nghttp3_nv);

	res = nghttp3_conn_submit_request(c->httpconn, stream_id, nva, nvlen, NULL, c);
	if (res != 0)
	{
		fprintf(stderr, "nghttp3_conn_submit_request failed: %s\n", nghttp3_strerror(res));
		return -1;
	}
	return 0;
}

int handle_keyupdate(struct client *c)
{
	int res;
	if (c->config.verbose)
	{
		print_debug(INFO, "Initiate key update");
	}

	if ((res = ngtcp2_conn_initiate_key_update(c->conn, timestamp())) != 0)
	{
		print_debug(ERROR, "ngtcp2_conn_initiate_key_update: %s(The previous key update has not been confirmed yet; or key update is too frequent; or new keys are not available yet.)", ngtcp2_strerror(res));
		return -1;
	}
	return 0;
}

int handle_migration(struct client *c)
{
	int fd, res, oldfd;
	fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if (fd < 0)
	{
		perror("socket create error");
		return -1;
	}
	struct sockaddr_in source;
	source.sin_addr.s_addr = htonl(INADDR_ANY);
	source.sin_family = AF_INET;
	source.sin_port = htons(MIGRATION_PORT);

	if (bind(fd, (struct sockaddr *)&source, sizeof(source)) == -1)
	{
		perror("udp socket bind error");
		close(fd);
		return -1;
	}

	if (connect(fd, (struct sockaddr *)(&c->remote_addr), c->remote_addrlen) == -1)
	{
		perror("migration connection failed");
		close(fd);
		return -1;
	}

	struct sockaddr_in local;
	local.sin_family = AF_INET;
	socklen_t local_len;
	if (getsockname(fd, (struct sockaddr *)&local, &local_len) == -1)
	{
		print_debug(ERROR, "migration getsockname failed: %s", strerror(errno));
		close(fd);
		return -1;
	}

	oldfd = c->sock_fd;
	c->sock_fd = fd;
	memcpy(&c->local_addr, &local, local_len);
	c->local_addrlen = local_len;

	ngtcp2_addr addr;
	ngtcp2_addr_init(&addr, (struct sockaddr *)&local, local_len);

	/**
	 * https://nghttp2.org/ngtcp2/ngtcp2_conn_set_local_addr.html
	 * This function is provided for testing purpose only
	 */
	// config.nat_rebinding
	if (0)
	{
		ngtcp2_conn_set_local_addr(c->conn, &addr);
		ngtcp2_conn_set_path_user_data(c->conn, c);
	}
	else
	{
		ngtcp2_path path = {
			addr,
			{
				(struct sockaddr *)&c->remote_addr,
				c->remote_addrlen,
			},
			c,
		};
		/* ngtcp2_conn_initiate_migration 会发送path challenge frame,  ngtcp2_conn_initiate_immediate_migration不会? */
		if ((res = ngtcp2_conn_initiate_immediate_migration(c->conn, &path, timestamp())) != 0)
		// if ((res = ngtcp2_conn_initiate_migration(c->conn, &path, timestamp())) != 0)
		{
			fprintf(stderr, "ngtcp2_conn_initiate_immediate_migration: %s\n", ngtcp2_strerror(res));
			return -1;
		}
	}

	struct epoll_event ev;
	ev.events = EPOLLIN | EPOLLOUT | EPOLLET;
	ev.data.fd = c->sock_fd;
	if (epoll_ctl(c->epoll_fd, EPOLL_CTL_ADD, c->sock_fd, &ev) == -1)
	{
		perror("epoll_ctl添加quic socket失败");
		close(fd);
		return -1;
	}
	if (epoll_ctl(c->epoll_fd, EPOLL_CTL_DEL, oldfd, NULL) == -1)
	{
		perror("migration epoll_ctl delete fd failed");
		return -1;
	}
	close(oldfd);
	return 0;
}

/**
 * \q exit
 * \m migration from port 9000 to 9001
 * \k key update manually
 */
int handle_stdin(struct client *c)
{
	int ret;
	char buf[MAX_BUFFER];
	size_t nread = 0;

	memset(buf, 0, MAX_BUFFER);
	while (nread < sizeof(buf))
	{
		ret = read(STDIN_FILENO, buf + nread, sizeof(buf) - nread);
		if (ret == -1)
		{
			if (errno == EAGAIN || errno == EWOULDBLOCK)
				break;
			perror("读取STDIN_FILENO错误");
			return -1;
		}
		else if (ret == 0)
		{
			return 0;
		}
		else
			nread += ret;
	}
	if (nread == sizeof(buf))
	{
		perror("读取STDIN_FILENO的buf满了");
		return -1;
	}

	if (strncmp(buf, "\\q", 2) == 0)
	{
		connection_close(c);
		connection_free(c);
		exit(0);
	}

	if (strncmp(buf, "\\m", 2) == 0)
	{
		return handle_migration(c);
	}

	if (strncmp(buf, "\\k", 2) == 0)
	{
		return handle_keyupdate(c);
	}

	if (submit_http_request(c) == -1)
	{
		fprintf(stderr, "submit_http_request failed\n");
		return -1;
	}

	connection_write(c);
	return nread;
}

int handle_timer(struct client *c)
{
	int ret;
	ret = ngtcp2_conn_handle_expiry(c->conn, timestamp());
	if (ret < 0)
	{
		fprintf(stderr, "ngtcp2_conn_handle_expiry: %s\n", ngtcp2_strerror((int)ret));
		return -1;
	}
	ret = connection_write(c);
	if (ret < 0)
	{
		fprintf(stderr, "connection_write出问题了\n");
		return -1;
	}
	return 0;
}

int setup_stdin(int epoll_fd)
{
	int flags;
	struct epoll_event ev;

	flags = fcntl(STDIN_FILENO, F_GETFL, 0);
	if (flags < 0)
	{
		perror("获取STDIN_FILENO F_GETFL错误");
		return -1;
	}
	flags = fcntl(STDIN_FILENO, F_SETFL, flags | O_NONBLOCK);
	if (flags < 0)
	{
		perror("设置STDIN_FILENO F_SETFL错误");
		return -1;
	}

	ev.events = EPOLLIN | EPOLLET;
	ev.data.fd = STDIN_FILENO;
	if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, STDIN_FILENO, &ev) == -1)
	{
		perror("epoll_ctl添加STDIN_FILENO失败");
		return -1;
	}
	return 0;
}

int setup_timer(int epoll_fd)
{
	struct epoll_event ev;
	int timer_fd = -1;

	timer_fd = timerfd_create(CLOCK_MONOTONIC, TFD_NONBLOCK);
	if (timer_fd < 0)
	{
		perror("timerfd_create失败");
		return -1;
	}
	ev.events = EPOLLIN | EPOLLET;
	ev.data.fd = timer_fd;
	if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, timer_fd, &ev) == -1)
	{
		perror("epoll_ctl添加timer_fd失败");
		return -1;
	}
	return timer_fd;
}

int resolve_and_connect(const char *host, const char *port,
						struct sockaddr *local_addr, size_t *local_addrlen,
						struct sockaddr *remote_addr, size_t *remote_addrlen)
{
	struct addrinfo hints;
	struct addrinfo *result, *rp;
	int ret, fd;

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_DGRAM;

	ret = getaddrinfo(host, port, &hints, &result);
	if (ret != 0)
		return -1;

	for (rp = result; rp != NULL; rp = rp->ai_next)
	{
		fd = socket(rp->ai_family, rp->ai_socktype | SOCK_NONBLOCK,
					rp->ai_protocol);
		if (fd == -1)
			continue;

		struct sockaddr_in source;
		source.sin_addr.s_addr = htonl(INADDR_ANY);
		source.sin_family = rp->ai_family;
		source.sin_port = htons(SOURCE_PORT);

		if (bind(fd, (struct sockaddr *)&source, sizeof(source)) == -1)
		{
			perror("udp socket bind error");
			return -1;
		}

		if (connect(fd, rp->ai_addr, rp->ai_addrlen) == 0)
		{
			*remote_addrlen = rp->ai_addrlen;
			memcpy(remote_addr, rp->ai_addr, rp->ai_addrlen);

			socklen_t len = (socklen_t)*local_addrlen;
			if (getsockname(fd, local_addr, &len) == -1)
				return -1;
			*local_addrlen = len;
			break;
		}

		close(fd);
	}

	freeaddrinfo(result);

	if (rp == NULL)
		return -1;

	return fd;
}

int verify_callback(int preverify_ok, X509_STORE_CTX *x509_store_ctx)
{
	char *issuer_name;
	X509 *current_cert;
	X509_NAME *current_cert_subject;
	X509_NAME *current_cert_issuer;

	int ssl_ex_data_idx = SSL_get_ex_data_X509_STORE_CTX_idx();
	SSL *ssl = X509_STORE_CTX_get_ex_data(x509_store_ctx, ssl_ex_data_idx);
	ngtcp2_crypto_conn_ref *conn_ref = (ngtcp2_crypto_conn_ref *)(SSL_get_app_data(ssl));
	struct client *c = (struct client *)(conn_ref->user_data);

	int depth = X509_STORE_CTX_get_error_depth(x509_store_ctx);

	current_cert = X509_STORE_CTX_get_current_cert(x509_store_ctx);
	char buf[256];
	current_cert_subject = X509_get_subject_name(current_cert);
	X509_NAME_oneline(current_cert_subject, buf, 256);

	current_cert_issuer = X509_get_issuer_name(current_cert);
	if (current_cert_issuer)
	{
		issuer_name = X509_NAME_oneline(current_cert_issuer, NULL, 0);
	}

	/* preverify_ok = 1 表示现在这个证书及前面证书链没有错误 */
	int error_code = preverify_ok ? X509_V_OK : X509_STORE_CTX_get_error(x509_store_ctx);
	if (error_code != X509_V_OK)
	{
		const char *error_string = X509_verify_cert_error_string(error_code);
		print_debug(ERROR, "verify_callback失败: %s", error_string);
	}

	if (c->config.verbose)
	{
		print_debug(INFO, "depth: %d, preverify_ok: %d, error_code: %d, error_string: %s, \n\tcert subject: %s\n\tcert issuer: %s",
					depth,
					preverify_ok,
					error_code,
					X509_verify_cert_error_string(error_code),
					buf,
					issuer_name);
	}

	OPENSSL_free(issuer_name);
	return preverify_ok;
}

int numeric_host_family(const char *hostname, int family)
{
	uint8_t dst[sizeof(struct in6_addr)];
	return inet_pton(family, hostname, dst) == 1;
}

int numeric_host(const char *hostname)
{
	return numeric_host_family(hostname, AF_INET) ||
		   numeric_host_family(hostname, AF_INET6);
}

void keylog_callback(const SSL *ssl, const char *line)
{
	int res;

	char *keylogfile_path = (char *)SSL_get_ex_data(ssl, ssl_userdata_idx);
	if (!keylogfile_path)
	{
		fprintf(stderr, "keylogfile_path为空\n");
		return;
	}

	int keylogfile = open(keylogfile_path, O_CREAT | O_RDWR | O_APPEND, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);
	if (keylogfile == -1)
	{
		perror("open keylogfile");
		exit(-1);
	}

	res = write(keylogfile, line, strlen(line));
	if (res == -1)
	{
		perror("write keylogfile line");
		close(keylogfile);
		exit(-1);
	}
	res = write(keylogfile, "\n", 1);
	if (res == -1)
	{
		perror("write keylogfile nextline");
		close(keylogfile);
		exit(-1);
	}
	close(keylogfile);
}

int new_session_cb(SSL *ssl, SSL_SESSION *session)
{
	ngtcp2_crypto_conn_ref *conn_ref = (ngtcp2_crypto_conn_ref *)(SSL_get_app_data(ssl));
	struct client *c = (struct client *)(conn_ref->user_data);

	c->ticket_received = 1;

	uint32_t max_early_data;

	if ((max_early_data = SSL_SESSION_get_max_early_data(session)) != UINT32_MAX)
	{
		fprintf(stderr, "max_early_data_size is not 0xffffffff: %#x\n", max_early_data);
	}
	BIO *f = BIO_new_file(c->config.session_file, "w");
	if (f == NULL)
	{
		fprintf(stderr, "Could not write TLS session in %s\n", c->config.session_file);
		return 0;
	}

	if (!PEM_write_bio_SSL_SESSION(f, session))
	{
		fprintf(stderr, "Unable to write TLS session to file\n");
	}

	BIO_free(f);

	return 0;
}

int client_ssl_init(struct client *c, char *host, const char *cafile, const char *private_key_file)
{
	int err;

	c->ssl_ctx = SSL_CTX_new(TLS_client_method());
	if (!c->ssl_ctx)
	{
		fprintf(stderr, "SSL_CTX_new: %s\n",
				ERR_error_string(ERR_get_error(), NULL));
		return -1;
	}
	if (cafile && private_key_file) /* NOTICE: 也可以将self-signed cert先导入系统证书，然后使用系统默认目录 */
	{
		if (SSL_CTX_use_PrivateKey_file(c->ssl_ctx, private_key_file, SSL_FILETYPE_PEM) != 1)
		{
			fprintf(stderr, "SSL_CTX_use_PrivateKey_file: %s\n", ERR_error_string(ERR_get_error(), NULL));
			return -1;
		}

		if (SSL_CTX_load_verify_locations(c->ssl_ctx, cafile, NULL) == 0)
		{
			fprintf(stderr, "SSL_CTX_load_verify_locations: %s\n", ERR_error_string(ERR_get_error(), NULL));
			return -1;
		}
	}
	else
	{
		/* NOTICE: 使用QUICTLS默认的目录证书相关配置为空，需要手动修改配置各种软连接到系统证书，详见note.md->2024-04-24 */
		err = SSL_CTX_set_default_verify_paths(c->ssl_ctx);
		if (err <= 0)
		{
			fprintf(stderr, "Could not load trusted certificates: %s\n", ERR_error_string(ERR_get_error(), NULL));
			return -1;
		}
	}

	if (c->config.check_cert)
	{
		SSL_CTX_set_verify(c->ssl_ctx, SSL_VERIFY_PEER, verify_callback); // 证书校验
	}
	else
	{
		SSL_CTX_set_verify(c->ssl_ctx, SSL_VERIFY_NONE, NULL); // 不校验证书
	}

	if (!c->config.disable_early_data && c->config.session_file)
	{
		// session stored externally by hand in callback function
		SSL_CTX_set_session_cache_mode(c->ssl_ctx, SSL_SESS_CACHE_CLIENT | SSL_SESS_CACHE_NO_INTERNAL);
		SSL_CTX_sess_set_new_cb(c->ssl_ctx, new_session_cb);
	}

	if (c->config.ciphers && SSL_CTX_set_ciphersuites(c->ssl_ctx, c->config.ciphers) != 1)
	{
		print_debug(ERROR, "SSL_CTX_set_ciphersuites: %s", ERR_error_string(ERR_get_error(), NULL));
		return -1;
	}

	if (c->config.groups && SSL_CTX_set1_groups_list(c->ssl_ctx, c->config.groups) != 1)
	{
		print_debug(ERROR, "SSL_CTX_set1_groups_list failed");
		return -1;
	}

	if (ngtcp2_crypto_quictls_configure_client_context(c->ssl_ctx) != 0)
	{
		fprintf(stderr, "ngtcp2_crypto_quictls_configure_client_context failed\n");
		return -1;
	}

	c->ssl = SSL_new(c->ssl_ctx);
	if (!c->ssl)
	{
		fprintf(stderr, "SSL_new: %s\n", ERR_error_string(ERR_get_error(), NULL));
		return -1;
	}

	SSL_set_app_data(c->ssl, &c->conn_ref);
	SSL_set_connect_state(c->ssl);
	err = SSL_set_alpn_protos(c->ssl, (const unsigned char *)ALPN, sizeof(ALPN) - 1);
	if (err != 0)
	{
		ERR_print_errors_fp(stderr);
		return -1;
	}
	if (!numeric_host(host))
	{
		SSL_set_tlsext_host_name(c->ssl, host); // SNI
	}

	err = SSL_set1_host(c->ssl, host); // cert hostname
	if (err != 1)
	{
		fprintf(stderr, "SSL_set1_host失败\n");
		return -1;
	}

	/* For NGTCP2_PROTO_VER_V1 */
	SSL_set_quic_transport_version(c->ssl, TLSEXT_TYPE_quic_transport_parameters);

	char *keylogfile = getenv("SSLKEYLOGFILE");
	if (keylogfile)
	{
		SSL_CTX_set_keylog_callback(c->ssl_ctx, keylog_callback);
		ssl_userdata_idx = SSL_get_ex_new_index(0, NULL, NULL, NULL, NULL);
		if (SSL_set_ex_data(c->ssl, ssl_userdata_idx, keylogfile) == 0)
		{
			fprintf(stderr, "SSL_set_ex_data failed\n");
			return -1;
		}
	}

	if (!c->config.disable_early_data && c->config.session_file) /* 只有使用early data时才设置session, 如果做session resumption可以放开 */
	{
		BIO *f = BIO_new_file(c->config.session_file, "r");
		if (f == NULL) /* open BIO file failed */
		{
			fprintf(stderr, "BIO_new_file: Could not read TLS session file %s\n", c->config.session_file);
		}
		else
		{
			SSL_SESSION *session = PEM_read_bio_SSL_SESSION(f, NULL, 0, NULL);
			BIO_free(f);
			if (session == NULL)
			{
				fprintf(stderr, "PEM_read_bio_SSL_SESSION: Could not read TLS session file %s\n", c->config.session_file);
			}
			else
			{
				if (!SSL_set_session(c->ssl, session))
				{
					fprintf(stderr, "SSL_set_session: Could not set session\n");
				}
				/* SSL_SESSION_get_max_early_data获取server是否支持early data，如果为0表示不支持, 其他数据表示最大的传输数据 */
				else if (!c->config.disable_early_data && SSL_SESSION_get_max_early_data(session))
				{
					c->early_data_enabled = 1;
					SSL_set_quic_early_data_enabled(c->ssl, 1);
				}
				SSL_SESSION_free(session);
			}
		}
	}
	return 0;
}

void log_printf(void *user_data, const char *fmt, ...)
{
	va_list ap;
	(void)user_data;

	va_start(ap, fmt);
	vfprintf(stderr, fmt, ap);
	va_end(ap);

	fprintf(stderr, "\n");
}

void rand_cb(uint8_t *dest, size_t destlen,
			 const ngtcp2_rand_ctx *rand_ctx)
{
	size_t i;
	(void)rand_ctx;

	for (i = 0; i < destlen; ++i)
	{
		*dest = (uint8_t)random();
	}
}

int get_new_connection_id_cb(ngtcp2_conn *conn, ngtcp2_cid *cid,
							 uint8_t *token, size_t cidlen,
							 void *user_data)
{
	(void)conn;
	(void)user_data;

	if (RAND_bytes(cid->data, (int)cidlen) != 1)
	{
		return NGTCP2_ERR_CALLBACK_FAILURE;
	}

	cid->datalen = cidlen;

	if (RAND_bytes(token, NGTCP2_STATELESS_RESET_TOKENLEN) != 1)
	{
		return NGTCP2_ERR_CALLBACK_FAILURE;
	}

	return 0;
}

int recv_stream_data_cb(ngtcp2_conn *conn __attribute__((unused)),
						uint32_t flags,
						int64_t stream_id,
						uint64_t offset __attribute__((unused)),
						const uint8_t *data, size_t datalen,
						void *user_data,
						void *stream_user_data __attribute__((unused)))
{
	struct client *c = (struct client *)user_data;
	nghttp3_ssize nconsumed = nghttp3_conn_read_stream(c->httpconn, stream_id, data, datalen, flags & NGTCP2_STREAM_DATA_FLAG_FIN);
	if (nconsumed < 0)
	{
		fprintf(stderr, "nghttp3_conn_read_stream: %s\n", nghttp3_strerror(nconsumed));
		ngtcp2_ccerr_set_application_error(
			&c->last_error, nghttp3_err_infer_quic_app_error_code(nconsumed), NULL,
			0);
		return NGTCP2_ERR_CALLBACK_FAILURE;
	}
	// fprintf(stdout, "收到 %zu 字节 from stream #%zd, consumed: %ld\n", datalen, stream_id, nconsumed);
	ngtcp2_conn_extend_max_stream_offset(c->conn, stream_id, nconsumed);
	ngtcp2_conn_extend_max_offset(c->conn, nconsumed);
	return 0;
}

void print_http_data(int64_t stream_id, const uint8_t *data __attribute__((unused)), size_t datalen)
{
	print_debug(INFO, "http: stream 0x%ld body %zu bytes", stream_id, datalen);
	hexdump(stdout, data, datalen);
}

int http_recv_data(nghttp3_conn *conn __attribute__((unused)), int64_t stream_id, const uint8_t *data,
				   size_t datalen, void *user_data, void *stream_user_data __attribute__((unused)))
{
	struct client *c = (struct client *)user_data;
	ngtcp2_conn_extend_max_stream_offset(c->conn, stream_id, datalen);
	ngtcp2_conn_extend_max_offset(c->conn, datalen);

	print_http_data(stream_id, data, datalen);
	return 0;
}

int http_begin_headers(nghttp3_conn *conn __attribute__((unused)), int64_t stream_id, void *user_data __attribute__((unused)),
					   void *stream_user_data)
{
	struct client *c = (struct client *)stream_user_data;
	if (c->config.verbose)
		print_debug(INFO, "http: stream 0x%ld response headers started", stream_id);
	return 0;
}

void print_http_header(const nghttp3_rcbuf *name, const nghttp3_rcbuf *value,
					   uint8_t flags)
{
	nghttp3_vec namebuf = nghttp3_rcbuf_get_buf(name);
	nghttp3_vec valuebuf = nghttp3_rcbuf_get_buf(value);
	fprintf(stdout, "[%.*s: %.*s]%s\n", (int)(namebuf.len), namebuf.base,
			(int)(valuebuf.len), valuebuf.base,
			(flags & NGHTTP3_NV_FLAG_NEVER_INDEX) ? "(sensitive)" : "");
}

int http_recv_header(nghttp3_conn *conn __attribute__((unused)), int64_t stream_id __attribute__((unused)), int32_t token __attribute__((unused)),
					 nghttp3_rcbuf *name __attribute__((unused)), nghttp3_rcbuf *value __attribute__((unused)), uint8_t flags __attribute__((unused)),
					 void *user_data, void *stream_user_data __attribute__((unused)))
{
	struct client *c = (struct client *)user_data;
	if (c->config.verbose)
		print_http_header(name, value, flags);
	return 0;
}

int http_end_headers(nghttp3_conn *conn __attribute__((unused)), int64_t stream_id, int fin __attribute__((unused)),
					 void *user_data, void *stream_user_data __attribute__((unused)))
{
	struct client *c = (struct client *)user_data;
	if (c->config.verbose)
		print_debug(INFO, "http: stream 0x%ld response headers ended", stream_id);
	return 0;
}

int http_begin_trailers(nghttp3_conn *conn __attribute__((unused)), int64_t stream_id, void *user_data,
						void *stream_user_data __attribute__((unused)))
{
	struct client *c = (struct client *)user_data;
	if (c->config.verbose)
		print_debug(INFO, "http: stream 0x%ld trailers started", stream_id);
	return 0;
}

int http_recv_trailer(nghttp3_conn *conn __attribute__((unused)), int64_t stream_id __attribute__((unused)), int32_t token __attribute__((unused)),
					  nghttp3_rcbuf *name, nghttp3_rcbuf *value, uint8_t flags,
					  void *user_data, void *stream_user_data __attribute__((unused)))
{
	struct client *c = (struct client *)user_data;
	if (c->config.verbose)
		print_http_header(name, value, flags);
	return 0;
}

int http_end_trailers(nghttp3_conn *conn __attribute__((unused)), int64_t stream_id, int fin __attribute__((unused)),
					  void *user_data, void *stream_user_data __attribute__((unused)))
{
	struct client *c = (struct client *)user_data;
	if (c->config.verbose)
		print_debug(INFO, "http: stream 0x%ld trailers ended", stream_id);
	return 0;
}

int http_deferred_consume(nghttp3_conn *conn __attribute__((unused)), int64_t stream_id,
						  size_t nconsumed, void *user_data,
						  void *stream_user_data __attribute__((unused)))
{
	struct client *c = (struct client *)(user_data);
	ngtcp2_conn_extend_max_stream_offset(c->conn, stream_id, nconsumed);
	ngtcp2_conn_extend_max_offset(c->conn, nconsumed);
	return 0;
}

int http_recv_settings(nghttp3_conn *conn __attribute__((unused)), const nghttp3_settings *settings,
					   void *conn_user_data __attribute__((unused)))
{
	print_debug(INFO,
				"http: remote settings\n"
				"http: SETTINGS_MAX_FIELD_SECTION_SIZE=%ld\n"
				"http: SETTINGS_QPACK_MAX_TABLE_CAPACITY=%zu\n"
				"http: SETTINGS_QPACK_BLOCKED_STREAMS=%zu\n"
				"http: SETTINGS_ENABLE_CONNECT_PROTOCOL=%d\n"
				"http: SETTINGS_H3_DATAGRAM=%d\n",
				settings->max_field_section_size, settings->qpack_max_dtable_capacity,
				settings->qpack_blocked_streams, settings->enable_connect_protocol,
				settings->h3_datagram);
	return 0;
}

int setup_httpconn(struct client *c)
{
	int res;
	if (c->httpconn)
		return 0;
	if (ngtcp2_conn_get_streams_uni_left(c->conn) < 3)
	{
		fprintf(stderr, "peer does not allow at least 3 unidirectional streams.\n");
		return -1;
	}
	nghttp3_callbacks callbacks = {
		NULL, // acked_stream_data
		NULL, // http_stream_close,
		http_recv_data,
		http_deferred_consume,
		http_begin_headers,
		http_recv_header,
		http_end_headers,
		http_begin_trailers,
		http_recv_trailer,
		http_end_trailers,
		NULL, // http_stop_sending,
		NULL, // end_stream
		NULL, // http_reset_stream,
		NULL, // shutdown
		http_recv_settings,
	};
	nghttp3_settings settings;
	nghttp3_settings_default(&settings);
	// settings.qpack_max_dtable_capacity = 4000;
	// settings.qpack_blocked_streams = 100;

	if ((res = nghttp3_conn_client_new(&c->httpconn, &callbacks, &settings, NULL, c)) != 0)
	{
		fprintf(stderr, "nghttp3_conn_client_new: %s\n", nghttp3_strerror(res));
		return -1;
	}

	int64_t ctrl_stream_id;
	if ((res = ngtcp2_conn_open_uni_stream(c->conn, &ctrl_stream_id, NULL)) != 0)
	{
		fprintf(stderr, "ngtcp2_conn_open_uni_stream: %s\n", ngtcp2_strerror(res));
		return -1;
	}
	if ((res = nghttp3_conn_bind_control_stream(c->httpconn, ctrl_stream_id)) != 0)
	{
		fprintf(stderr, "nghttp3_conn_bind_control_stream: %s\n", nghttp3_strerror(res));
		return -1;
	}

	if (c->config.verbose)
		print_debug(INFO, "http: control stream=%ld", ctrl_stream_id);

	int64_t qpack_enc_stream_id, qpack_dec_stream_id;

	if ((res = ngtcp2_conn_open_uni_stream(c->conn, &qpack_enc_stream_id, NULL)) != 0)
	{
		fprintf(stderr, "ngtcp2_conn_open_uni_stream: %s\n", ngtcp2_strerror(res));
		return -1;
	}

	if ((res = ngtcp2_conn_open_uni_stream(c->conn, &qpack_dec_stream_id, NULL)) != 0)
	{
		fprintf(stderr, "ngtcp2_conn_open_uni_stream: %s\n", ngtcp2_strerror(res));
		return -1;
	}

	if ((res = nghttp3_conn_bind_qpack_streams(c->httpconn, qpack_enc_stream_id, qpack_dec_stream_id)) != 0)
	{
		fprintf(stderr, "nghttp3_conn_bind_qpack_streams: %s\n", nghttp3_strerror(res));
		return -1;
	}

	if (c->config.verbose)
		print_debug(INFO, "http: QPACK streams encoder=%ld decoder=%ld", qpack_enc_stream_id, qpack_dec_stream_id);
	return 0;
}

int write_pem(char *filename, char *name, char *type, const uint8_t *data, size_t datalen)
{
	BIO *f = BIO_new_file(filename, "w");
	if (f == NULL)
	{
		fprintf(stderr, "Could not write %s in %s\n", name, filename);
		return -1;
	}

	PEM_write_bio(f, type, "", data, datalen);
	BIO_free(f);
	return 0;
}

int write_transport_params(char *filename, const uint8_t *data, size_t datalen)
{
	return write_pem(filename, "transport parameters", "QUIC TRANSPORT PARAMETERS", data, datalen);
}

int handle_handshake_completed(ngtcp2_conn *conn, void *userdata)
{
	struct client *c = (struct client *)userdata;
	const unsigned char *alpn = NULL;
	unsigned int alpnlen;

	SSL_get0_alpn_selected(c->ssl, &alpn, &alpnlen);
	if (c->config.verbose)
	{
		print_debug(INFO, "Negotiated ALPN is %.*s", alpnlen, alpn);
		print_debug(INFO, "Negotiated cipher suite is %s", SSL_get_cipher_name(c->ssl));
		int group_nid = SSL_get_negotiated_group(c->ssl);
		print_debug(INFO, "Negotiated group is %s", group_nid == NID_undef ? "NULL" : OBJ_nid2ln(group_nid));
	}

	ngtcp2_duration timeout;
	const ngtcp2_transport_params *params;
	params = ngtcp2_conn_get_remote_transport_params(conn);
	if (!params)
	{
		fprintf(stderr, "没有服务端transport params\n");
		return NGTCP2_ERR_CALLBACK_FAILURE;
	}

	timeout = params->max_idle_timeout == 0 ? UINT64_MAX : params->max_idle_timeout / NGTCP2_SECONDS;
	if (LOCAL_MAX_IDLE_TIMEOUT < timeout)
		timeout = LOCAL_MAX_IDLE_TIMEOUT;
	ngtcp2_conn_set_keep_alive_timeout(conn, timeout == UINT64_MAX ? UINT64_MAX : (timeout - 1) * NGTCP2_SECONDS);

	if (c->config.verbose)
		print_debug(INFO, "quic: server max_idle_timeout: %ld, timeout: %ld", params->max_idle_timeout, timeout - 1);

	if (setup_httpconn(userdata) == -1)
	{
		fprintf(stderr, "setup_httpconn failed\n");
		return -1;
	}

	if (!c->config.disable_early_data && c->config.quic_transport_parameter_file)
	{
		uint8_t data[256];
		ngtcp2_ssize datalen = ngtcp2_conn_encode_0rtt_transport_params(c->conn, data, 256);
		if (datalen < 0)
		{
			fprintf(stderr, "Could not encode 0-RTT transport parameters: %s\n", ngtcp2_strerror(datalen));
			return -1;
		}
		else if (write_transport_params(c->config.quic_transport_parameter_file, data, datalen) != 0)
		{
			fprintf(stderr, "Could not write transport parameters in %s\n", c->config.quic_transport_parameter_file);
		}
	}
	return 0;
}

int extend_max_local_streams_bidi(ngtcp2_conn *conn, uint64_t max_streams,
								  void *user_data)
{
	(void)conn;
	(void)max_streams;
	(void)user_data;

	return 0;
}

int handshake_confirmed(ngtcp2_conn *conn, void *user_data)
{
	(void)conn;
	struct client *c = (struct client *)user_data;
	c->handshake_confirmed = 1;
	// start changeg local addr timer
	// start keyt update timer
	// start delay stream timer
	char ip[INET_ADDRSTRLEN];
	uint16_t port;
	char buf[128];
	get_ip_port(&c->local_addr, ip, &port);
	sprintf(buf, "now CLIENT(%s, %d) connected to ", ip, port);
	get_ip_port(&c->remote_addr, ip, &port);
	sprintf(buf + strlen(buf), "SERVER(%s, %d)", ip, port);
	print_debug(INFO, "%s", buf);
	return 0;
}

int extend_max_stream_data(ngtcp2_conn *conn __attribute_maybe_unused__, int64_t stream_id,
						   uint64_t max_data __attribute_maybe_unused__, void *user_data,
						   void *stream_user_data __attribute_maybe_unused__)
{
	struct client *c = (struct client *)(user_data);
	int res = nghttp3_conn_unblock_stream(c->httpconn, stream_id);
	if (res != 0)
	{
		fprintf(stderr, "nghttp3_conn_unblock_stream failed: %s\n", nghttp3_strerror(res));
		return NGTCP2_ERR_CALLBACK_FAILURE;
	}
	return 0;
}

int acked_stream_data_offset(ngtcp2_conn *conn __attribute__((unused)), int64_t stream_id,
							 uint64_t offset __attribute__((unused)), uint64_t datalen, void *user_data,
							 void *stream_user_data __attribute__((unused)))
{
	struct client *c = (struct client *)(user_data);
	int res;
	if ((res = nghttp3_conn_add_ack_offset(c->httpconn, stream_id, datalen)) != 0)
	{
		fprintf(stderr, "nghttp3_conn_add_ack_offset failed: %s\n", nghttp3_strerror(res));
		return -1;
	}

	return 0;
}

int path_validation(ngtcp2_conn *conn, uint32_t flags, const ngtcp2_path *path,
					const ngtcp2_path *old_path,
					ngtcp2_path_validation_result res, void *user_data)
{
	(void)conn;
	char ip[INET_ADDRSTRLEN];
	uint16_t port;
	char buf[128];

	get_ip_port((struct sockaddr_storage *)(path->local.addr), ip, &port);
	sprintf(buf, "Path validation against path { new local: %s:%d", ip, port);
	if (old_path)
	{
		get_ip_port((struct sockaddr_storage *)(old_path->local.addr), ip, &port);
		sprintf(buf + strlen(buf), ", old local: %s:%d", ip, port);
	}
	get_ip_port((struct sockaddr_storage *)(path->remote.addr), ip, &port);
	sprintf(buf + strlen(buf), ", remote: %s:%d } %s", ip, port, res == NGTCP2_PATH_VALIDATION_RESULT_SUCCESS ? "succeeded" : "failed");
	print_debug(INFO, "%s", buf);

	if (flags & NGTCP2_PATH_VALIDATION_FLAG_PREFERRED_ADDR)
	{
		print_debug(WARNING, "NGTCP2_PATH_VALIDATION_FLAG_PREFERRED_ADDR");
		struct client *c = (struct client *)(user_data);
		memcpy(&c->remote_addr, path->remote.addr, path->remote.addrlen);
		c->remote_addrlen = path->remote.addrlen;
	}

	return 0;
}

char *read_pem(const char *filename, const char *name, const char *type, long *pdatalen)
{
	BIO *f = BIO_new_file(filename, "r");
	if (f == NULL)
	{
		fprintf(stderr, "BIO_new_file: Could not open %s file %s\n", name, filename);
		return NULL;
	}

	char *pem_type, *header;
	unsigned char *data;
	long datalen;

	if (PEM_read_bio(f, &pem_type, &header, &data, &datalen) != 1)
	{
		fprintf(stderr, "PEM_read_bio: Could not open %s file %s\n", name, filename);
		return NULL;
	}

	if (strncmp(type, pem_type, strlen(type)) != 0)
	{
		fprintf(stderr, "%s file %s contains unexpected type: current type: %s, expected type: %s\n", name, filename, type, pem_type);
		return NULL;
	}

	*pdatalen = datalen;
	char *pdata = malloc(datalen + 1);
	memcpy(pdata, data, datalen);
	pdata[datalen] = '\0';

	BIO_free(f);
	OPENSSL_free(pem_type);
	OPENSSL_free(header);
	OPENSSL_free(data);

	return pdata;
}

int make_stream_early(struct client *c)
{
	if (setup_httpconn(c) != 0)
		return -1;
	return submit_http_request(c);
}

void print_secret(const uint8_t *secret, size_t secret_len, const uint8_t *key, size_t key_len, const uint8_t *iv, size_t iv_len)
{
	size_t i;
	fprintf(stdout, "\tsecret: ");
	for (i = 0; i < secret_len; i++)
	{
		fprintf(stdout, "%02x", secret[i]);
	}
	fprintf(stdout, "\n");
	fprintf(stdout, "\tkey: ");
	for (i = 0; i < key_len; i++)
	{
		fprintf(stdout, "%02x", key[i]);
	}
	fprintf(stdout, "\n");
	fprintf(stdout, "\tiv: ");
	for (i = 0; i < iv_len; i++)
	{
		fprintf(stdout, "%02x", iv[i]);
	}
	fprintf(stdout, "\n");
}

int update_key(
	ngtcp2_conn *conn __attribute__((unused)), uint8_t *rx_secret, uint8_t *tx_secret,
	ngtcp2_crypto_aead_ctx *rx_aead_ctx, uint8_t *rx_iv,
	ngtcp2_crypto_aead_ctx *tx_aead_ctx, uint8_t *tx_iv,
	const uint8_t *current_rx_secret, const uint8_t *current_tx_secret,
	size_t secretlen, void *user_data)
{
	struct client *c = (struct client *)user_data;
	if (c->config.verbose)
	{
		print_debug(INFO, "Updating traffic key");
	}
	const ngtcp2_crypto_ctx *crypto_ctx = ngtcp2_conn_get_crypto_ctx(c->conn);
	const ngtcp2_crypto_aead *aead = &(crypto_ctx->aead);
	int keylen = ngtcp2_crypto_aead_keylen(aead);
	int ivlen = ngtcp2_crypto_packet_protection_ivlen(aead);

	c->nkey_update++; /* -> 和 ++ 具有相同的precedense */

	uint8_t rx_key[64], tx_key[64];
	if (ngtcp2_crypto_update_key(c->conn, rx_secret, tx_secret, rx_aead_ctx,
								 rx_key, rx_iv, tx_aead_ctx, tx_key, tx_iv, current_rx_secret, current_tx_secret, secretlen) != 0)
	{
		print_debug(ERROR, "ngtcp2_crypto_update_key failed");
		return -1;
	}

	if (c->config.verbose && c->config.show_secret)
	{
		print_debug(INFO, "application traffic rx secret: %d", c->nkey_update);
		print_secret(rx_secret, secretlen, rx_key, keylen, rx_iv, ivlen);
		print_debug(INFO, "application traffic tx secret: %d", c->nkey_update);
		print_secret(tx_secret, secretlen, tx_key, keylen, tx_iv, ivlen);
	}

	return 0;
}

int client_quic_init(struct client *c,
					 struct sockaddr *remote_addr,
					 socklen_t remote_addrlen,
					 struct sockaddr *local_addr,
					 socklen_t local_addrlen)
{
	ngtcp2_path path = {
		{
			(struct sockaddr *)local_addr,
			local_addrlen,
		},
		{
			(struct sockaddr *)remote_addr,
			remote_addrlen,
		},
		NULL,
	};
	ngtcp2_callbacks callbacks = {
		/* Use the default implementation from ngtcp2_crypto */
		.client_initial = ngtcp2_crypto_client_initial_cb,
		.recv_crypto_data = ngtcp2_crypto_recv_crypto_data_cb,
		.encrypt = ngtcp2_crypto_encrypt_cb,
		.decrypt = ngtcp2_crypto_decrypt_cb,
		.hp_mask = ngtcp2_crypto_hp_mask_cb,
		.recv_retry = ngtcp2_crypto_recv_retry_cb,
		.delete_crypto_aead_ctx = ngtcp2_crypto_delete_crypto_aead_ctx_cb,
		.delete_crypto_cipher_ctx = ngtcp2_crypto_delete_crypto_cipher_ctx_cb,
		.get_path_challenge_data = ngtcp2_crypto_get_path_challenge_data_cb,

		.update_key = update_key,
		.acked_stream_data_offset = acked_stream_data_offset,
		.recv_stream_data = recv_stream_data_cb,
		.rand = rand_cb,
		.get_new_connection_id = get_new_connection_id_cb,
		.handshake_completed = handle_handshake_completed,

		.handshake_confirmed = handshake_confirmed,
		.extend_max_local_streams_bidi = extend_max_local_streams_bidi,
		.extend_max_stream_data = extend_max_stream_data,
		.path_validation = path_validation,
	};
	ngtcp2_cid dcid, scid;
	ngtcp2_settings settings;
	ngtcp2_transport_params params;
	int rv;

	dcid.datalen = NGTCP2_MIN_INITIAL_DCIDLEN;
	if (RAND_bytes(dcid.data, (int)dcid.datalen) != 1)
	{
		fprintf(stderr, "RAND_bytes failed\n");
		return -1;
	}

	scid.datalen = 8;
	if (RAND_bytes(scid.data, (int)scid.datalen) != 1)
	{
		fprintf(stderr, "RAND_bytes failed\n");
		return -1;
	}

	ngtcp2_settings_default(&settings);

	settings.initial_ts = timestamp();
	// settings.log_printf = log_printf;

	ngtcp2_transport_params_default(&params);

	params.initial_max_streams_uni = 3;
	params.initial_max_stream_data_bidi_local = 128 * 1024;
	params.initial_max_data = 1024 * 1024;
	params.max_idle_timeout = LOCAL_MAX_IDLE_TIMEOUT * NGTCP2_SECONDS;

	rv = ngtcp2_conn_client_new(&c->conn, &dcid, &scid, &path, NGTCP2_PROTO_VER_V1,
								&callbacks, &settings, &params, NULL, c);
	if (rv != 0)
	{
		fprintf(stderr, "ngtcp2_conn_client_new: %s\n", ngtcp2_strerror(rv));
		return -1;
	}

	assert(c->conn);
	assert(c->ssl);
	ngtcp2_conn_set_tls_native_handle(c->conn, c->ssl);

	if (c->early_data_enabled && c->config.quic_transport_parameter_file)
	{
		char *data;
		long datalen;
		if ((data = read_pem(c->config.quic_transport_parameter_file, "transport parameters", "QUIC TRANSPORT PARAMETERS", &datalen)) == NULL)
		{
			fprintf(stderr, "client quic init early data read pem failed\n");
			c->early_data_enabled = 0;
		}
		else
		{
			rv = ngtcp2_conn_decode_and_set_0rtt_transport_params(c->conn, (uint8_t *)data, (size_t)datalen);
			if (rv != 0)
			{
				fprintf(stderr, "ngtcp2_conn_decode_and_set_0rtt_transport_params failed: %s\n", ngtcp2_strerror(rv));
				c->early_data_enabled = 0;
			}
			else if (make_stream_early(c) != 0)
			{
				free(data); // free memory which allocated in read_pem function
				return -1;
			}
		}
		free(data); // free memory which allocated in read_pem function
	}

	return 0;
}

ngtcp2_conn *get_conn(ngtcp2_crypto_conn_ref *conn_ref)
{
	struct client *c = conn_ref->user_data;
	return c->conn;
}

ssize_t recv_packet(int fd, uint8_t *data, size_t data_size,
					struct sockaddr *remote_addr, size_t *remote_addrlen)
{
	struct iovec iov;
	iov.iov_base = data;
	iov.iov_len = data_size;

	struct msghdr msg;
	memset(&msg, 0, sizeof(msg));

	msg.msg_name = remote_addr;
	msg.msg_namelen = *remote_addrlen;
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;

	ssize_t ret;

	do
		ret = recvmsg(fd, &msg, MSG_DONTWAIT);
	while (ret < 0 && errno == EINTR);

	*remote_addrlen = msg.msg_namelen;

	return ret;
}

int connection_read(struct client *c)
{
	uint8_t buf[MAX_BUFFER];
	ngtcp2_ssize ret;
	for (;;)
	{
		struct sockaddr_storage remote_addr;
		size_t remote_addrlen = sizeof(remote_addr);
		ret = recv_packet(c->sock_fd, buf, sizeof(buf),
						  (struct sockaddr *)&remote_addr, &remote_addrlen);
		if (ret < 0)
		{
			if (errno == EAGAIN || errno == EWOULDBLOCK)
				break;
			perror("recv_packet发生错误");
			return -1;
		}

		ngtcp2_path path;
		memcpy(&path, ngtcp2_conn_get_path(c->conn), sizeof(path));
		path.remote.addrlen = remote_addrlen;
		path.remote.addr = (struct sockaddr *)&remote_addr;

		ngtcp2_pkt_info pi;
		memset(&pi, 0, sizeof(pi));

		ret = ngtcp2_conn_read_pkt(c->conn, &path, &pi, buf, ret,
								   timestamp());
		if (ret < 0)
		{
			fprintf(stderr, "ngtcp2_conn_read_pkt发生错误: %s \n", ngtcp2_strerror(ret));
			if (ret == NGTCP2_ERR_CRYPTO)
			{
				uint8_t e = ngtcp2_conn_get_tls_alert(c->conn);
				fprintf(stderr, "%s\n", SSL_alert_desc_string_long(e));
			}
			exit(-1);
		}
		break;
	}
	return 0;
}

int handle_sig(struct client *c)
{
	struct signalfd_siginfo sfd_si;
	if (read(c->sig_fd, &sfd_si, sizeof(struct signalfd_siginfo)) == -1)
		return -1;

	if (sfd_si.ssi_signo == SIGQUIT)
	{
		fprintf(stdout, "QUIT信号触发\n");
	}
	if (sfd_si.ssi_signo == SIGINT)
	{
		fprintf(stdout, "INT信号触发\n");
	}
	if (c->conn)
	{
		connection_close(c);
	}
	connection_free(c);
	exit(0);
}

int setup_sig(int epoll_fd)
{
	sigset_t mask;
	int sig_fd;
	/*
	 * Setup SIGALRM to be delivered via SignalFD
	 * */
	sigemptyset(&mask);
	sigaddset(&mask, SIGINT);
	sigaddset(&mask, SIGQUIT);
	/*
	 * Block these signals so that they are not handled
	 * in the usual way. We want them to be handled via
	 * SignalFD.
	 * */
	if (sigprocmask(SIG_BLOCK, &mask, NULL) == -1)
	{
		perror("sigprocmask失败");
		return -1;
	}
	sig_fd = signalfd(-1, &mask, 0);
	if (sig_fd == -1)
	{
		perror("signalfd失败");
		return -1;
	}

	struct epoll_event ev;
	ev.events = EPOLLIN | EPOLLET;
	ev.data.fd = sig_fd;
	if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, sig_fd, &ev) == -1)
	{
		close(sig_fd);
		perror("epoll_ctl添加signal fd失败");
		return -1;
	}
	return sig_fd;
}

int init_default_config(Config *config)
{
	config->check_cert = 1;
	config->disable_early_data = 0;
	config->verbose = 1;
	config->ca_file = NULL;
	config->private_key_file = NULL;
	config->session_file = "quic_session.pem";
	config->quic_transport_parameter_file = "quic_transport_parameter.pem";
	config->ciphers = NULL;
	config->groups = NULL;
	config->show_secret = 0;
	return 0;
}

void print_usage()
{
	fprintf(stderr, "client [OPTIONS] HOST PORT\n");
}

int main(int argc, char *argv[])
{
	/* ./client HOST PORT CACERT */
	/**
	 * $0 [options] HOST PORT
	 * options:
	 * --disable-early-data --ca --key -k(don't check cert) --help(-h help) --verbose(-v)
	 */
	Config config;
	init_default_config(&config);

	int longind, flag;
	int res;
	char *shortopts = "hvk";
	struct option longopts[] = {
		{.name = "help", .has_arg = no_argument, .flag = NULL, .val = 'h'},
		{.name = "insecure", .has_arg = no_argument, .flag = NULL, .val = 'k'},
		{.name = "verbose", .has_arg = no_argument, .flag = NULL, .val = 'v'},
		{.name = "ca-file", .has_arg = required_argument, .flag = &flag, .val = 1},
		{.name = "private-key-file", .has_arg = required_argument, .flag = &flag, .val = 2},
		{.name = "disable-early-data", .has_arg = no_argument, .flag = &flag, .val = 3},
		{.name = "session-file", .has_arg = required_argument, .flag = &flag, .val = 4},
		{.name = "quic-tansport-parameter-file", .has_arg = required_argument, .flag = &flag, .val = 5},
		/* ciphers="TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256:TLS_AES_128_CCM_SHA256:TLS_AES_128_CCM_8_SHA256" */
		/* https://datatracker.ietf.org/doc/html/rfc8446#appendix-B.4 */
		{.name = "ciphers", .has_arg = required_argument, .flag = &flag, .val = 6},
		/* TLSv1.3 groups="P-256:P-384:P-521:X25519:X448:ffdhe2048:ffdhe3072:ffdhe4096:ffdhe6144:ffdhe8192" etc (https://www.openssl.org/docs/manmaster/man3/SSL_CTX_set1_groups_list.html)*/
		/* TLSv1.3 groups参考文档 https://datatracker.ietf.org/doc/html/rfc8446#section-4.2.7 */
		{.name = "groups", .has_arg = required_argument, .flag = &flag, .val = 7},
		{.name = "show-secret", .has_arg = no_argument, .flag = &flag, .val = 8},
		{0, 0, 0, 0},
	};
	while (1)
	{
		res = getopt_long(argc, argv, shortopts, longopts, &longind);
		if (res == -1) /* argument parse end */
			break;
		switch (res)
		{
		case 'h':
			print_usage();
			return 0;
		case 'v':
			config.verbose = 1;
			break;
		case 'k':
			config.check_cert = 0;
			break;
		case 0:
			if (flag == 1) /* ca path */
				config.ca_file = optarg;
			else if (flag == 2) /* ca key path */
				config.private_key_file = optarg;
			else if (flag == 3) /* disable-early-data */
				config.disable_early_data = 1;
			else if (flag == 4)
				config.session_file = optarg;
			else if (flag == 5)
				config.quic_transport_parameter_file = optarg;
			else if (flag == 6) /* ciphers */
				config.ciphers = optarg;
			else if (flag == 7) /* groups */
				config.groups = optarg;
			else if (flag == 8) /* show-secret */
				config.show_secret = 1;
			else
			{
				fprintf(stderr, "[ERROR] other flags\n");
				print_usage();
				return -1;
			}
			break;
		default: /* ? : etc means error, print help info and exit */
			fprintf(stderr, "[ERROR] ? or :\n");
			print_usage();
			return -1;
		}
	}
	if (argc - optind < 2)
	{
		fprintf(stderr, "[ERROR] few argv\n");
		print_usage();
		return -1;
	}
	char *host = argv[optind++];
	char *port = argv[optind++];
	int epoll_fd = -1, timer_fd = -1, sock_fd = -1, sig_fd = -1;
	struct sockaddr_storage local_addr, remote_addr;
	size_t local_addrlen = sizeof(local_addr), remote_addrlen;
	struct client c;
	c.config = config;

	c.ticket_received = 0;
	c.early_data_enabled = 0;

	ngtcp2_ccerr_default(&c.last_error);
	c.stream.stream_id = -1;

	sock_fd = resolve_and_connect(
		host, port,
		(struct sockaddr *)&local_addr,
		&local_addrlen,
		(struct sockaddr *)&remote_addr,
		&remote_addrlen);

	if (sock_fd < 0)
	{
		fprintf(stderr, "resolve_and_connect失败\n");
		return -1;
	}
	c.sock_fd = sock_fd;
	c.local_addr = local_addr;
	c.local_addrlen = local_addrlen;
	c.remote_addr = remote_addr;
	c.remote_addrlen = remote_addrlen;
	c.httpconn = NULL;
	c.handshake_confirmed = 0;
	c.nkey_update = 0;

	c.ssl_ctx = NULL;
	c.ssl = NULL;

	if (client_ssl_init(&c, host, c.config.ca_file, c.config.private_key_file) < 0)
	{
		fprintf(stderr, "client_ssl_init失败\n");
		return -1;
	}

	if (client_quic_init(&c,
						 (struct sockaddr *)&remote_addr,
						 remote_addrlen,
						 (struct sockaddr *)&local_addr,
						 local_addrlen) < 0)
	{
		fprintf(stderr, "client_quic_init错误\n");
		return -1;
	}

	c.conn_ref.get_conn = get_conn;
	c.conn_ref.user_data = &c;

	epoll_fd = epoll_create1(0);
	if (epoll_fd == -1)
	{
		perror("创建epoll fd错误");
		return -1;
	}
	c.epoll_fd = epoll_fd;

	if (setup_stdin(epoll_fd) < 0)
	{
		fprintf(stderr, "setup_stdin失败\n");
		return -1;
	}

	timer_fd = setup_timer(epoll_fd);
	if (timer_fd < 0)
	{
		fprintf(stderr, "setup_timer失败\n");
		return -1;
	}
	c.timer_fd = timer_fd;

	sig_fd = setup_sig(epoll_fd);
	if (sig_fd < 0)
	{
		fprintf(stderr, "setup_sig失败\n");
		return -1;
	}
	c.sig_fd = sig_fd;

	struct epoll_event ev;
	ev.events = EPOLLIN | EPOLLOUT | EPOLLET;
	ev.data.fd = c.sock_fd;
	if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, c.sock_fd, &ev) == -1)
	{
		perror("epoll_ctl添加quic socket失败");
		return -1;
	}

	for (;;)
	{
		struct epoll_event events[MAX_EVENTS];
		int nfds;

		nfds = epoll_wait(epoll_fd, events, MAX_EVENTS, -1);
		if (nfds < 0)
		{
			perror("epoll_wait发生错误");
			return -1;
		}

		for (int n = 0; n < nfds; n++)
		{
			if (events[n].data.fd == sig_fd)
			{
				if (handle_sig(&c) < 0)
					return -1;
			}
			if (events[n].data.fd == c.sock_fd)
			{
				if (events[n].events & EPOLLIN)
				{
					if (connection_read(&c) < -1)
					{
						fprintf(stderr, "connection_read错误\n");
						return -1;
					}
				}
				if (events[n].events & EPOLLOUT)
				{
					if (connection_write(&c) < -1)
					{
						fprintf(stderr, "connection_write错误\n");
						return -1;
					}
				}
			}
			if (events[n].data.fd == timer_fd)
			{
				if (handle_timer(&c) < 0)
					return -1;
			}
			if (events[n].data.fd == STDIN_FILENO)
			{
				if (handle_stdin(&c) < 0)
					return -1;
			}
		}
	}

	return 0;
}
