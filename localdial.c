// sysctl net.inet.ip.portrange.first=10000
// sysctl net.inet.ip.portrange.last=10005

#include <arpa/inet.h>
#include <err.h>
#include <getopt.h>
#include <memory.h>
#include <netdb.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sysexits.h>
#include <threads.h>
#include <unistd.h>

static int opt_shutdown;
static int opt_quiet;

static cnd_t server_cnd;
static mtx_t server_mtx;
static int   server_count;

static int
server4_func(void *arg)
{
	int                 sfd;
	struct sockaddr_in *saddr;
	socklen_t           saddr_len;
	char                saddr_str[INET_ADDRSTRLEN];

	sfd = socket(PF_INET, SOCK_STREAM, 0);
	if (sfd < 0)
		err(EX_OSERR, "server4: socket");

	saddr = (struct sockaddr_in *)arg;
	memset(saddr, 0, sizeof(*saddr));
	saddr->sin_family = AF_INET;
	saddr->sin_addr.s_addr = INADDR_ANY;

	if (bind(sfd, (struct sockaddr *)saddr, sizeof(*saddr)) < 0)
		err(EX_OSERR, "server4: bind");

	saddr_len = sizeof(*saddr);
	if (getsockname(sfd, (struct sockaddr *)saddr, &saddr_len) < 0)
		err(EX_OSERR, "server4: getsockname");

	if (listen(sfd, -1) < 0)
		err(EX_OSERR, "server4: listen");

	inet_ntop(AF_INET, &saddr->sin_addr, saddr_str, sizeof(saddr_str));
	fprintf(stderr, "server4: listening on %s:%u\n", saddr_str, ntohs(saddr->sin_port));

	mtx_lock(&server_mtx);
	++server_count;
	cnd_signal(&server_cnd);
	mtx_unlock(&server_mtx);

	for (;;) {
		int                cfd;
		struct sockaddr_in caddr;
		socklen_t          caddr_len;

		caddr_len = sizeof(caddr);
		cfd = accept(sfd, (struct sockaddr *)&caddr, &caddr_len);
		if (cfd < 0) {
			warn("server4: accept");
			continue;
		}

		char caddr_str[INET_ADDRSTRLEN];
		inet_ntop(AF_INET, &caddr.sin_addr, caddr_str, sizeof(caddr_str));

		if (!opt_quiet)
			fprintf(stderr,
					"server4: accepted   %16s:%-5u -> %9s:%-5u\n",
					caddr_str,
					ntohs(caddr.sin_port),
					saddr_str,
					ntohs(saddr->sin_port));

		if (opt_shutdown)
			shutdown(cfd, SHUT_RDWR);
		close(cfd);
	}

	return 0;
}

static int
server6_func(void *arg)
{
	int                  sfd, zero = 0;
	struct sockaddr_in6 *saddr;
	socklen_t            saddr_len;
	char                 saddr_str[INET6_ADDRSTRLEN];

	sfd = socket(PF_INET6, SOCK_STREAM, 0);
	if (sfd < 0)
		err(EX_OSERR, "server6: socket");

	if (setsockopt(sfd, IPPROTO_IPV6, IPV6_BINDV6ONLY, &zero, sizeof(zero)) < 0)
		err(EX_OSERR, "server6: setsockopt");

	saddr = (struct sockaddr_in6 *)arg;
	memset(saddr, 0, sizeof(*saddr));
	saddr->sin6_family = AF_INET6;
	saddr->sin6_addr = in6addr_any;

	if (bind(sfd, (struct sockaddr *)saddr, sizeof(*saddr)) < 0)
		err(EX_OSERR, "server6: bind");

	saddr_len = sizeof(*saddr);
	if (getsockname(sfd, (struct sockaddr *)saddr, &saddr_len) < 0)
		err(EX_OSERR, "server6: getsockname");

	if (listen(sfd, -1) < 0)
		err(EX_OSERR, "server6: listen");

	inet_ntop(AF_INET6, &saddr->sin6_addr, saddr_str, sizeof(saddr_str));
	fprintf(stderr, "server6: listening on %s:%u\n", saddr_str, ntohs(saddr->sin6_port));

	mtx_lock(&server_mtx);
	++server_count;
	cnd_signal(&server_cnd);
	mtx_unlock(&server_mtx);

	for (;;) {
		int                 cfd;
		struct sockaddr_in6 caddr;
		socklen_t           caddr_len;

		caddr_len = sizeof(caddr);
		cfd = accept(sfd, (struct sockaddr *)&caddr, &caddr_len);
		if (cfd < 0) {
			warn("server6: accept");
			continue;
		}

		char caddr_str[INET6_ADDRSTRLEN];
		inet_ntop(AF_INET6, &caddr.sin6_addr, caddr_str, sizeof(caddr_str));

		if (!opt_quiet)
			fprintf(stderr,
					"server6: accepted   %16s:%-5u -> %9s:%-5u\n",
					caddr_str,
					ntohs(caddr.sin6_port),
					saddr_str,
					ntohs(saddr->sin6_port));

		if (opt_shutdown)
			shutdown(cfd, SHUT_RDWR);
		close(cfd);
	}

	return 0;
}

void
client4(const char *laddr_str, const char *raddr_str, in_port_t rport)
{
	struct addrinfo    aih, *ai;
	int                fd, res;
	char               laddr_buf[INET_ADDRSTRLEN], raddr_buf[INET_ADDRSTRLEN];
	struct sockaddr_in laddr, raddr;
	socklen_t          laddr_len;

	memset(&aih, 0, sizeof(aih));
	aih.ai_family = AF_INET;
	aih.ai_flags = AI_NUMERICHOST;

	res = getaddrinfo(laddr_str, NULL, &aih, &ai);
	if (res != 0)
		err(EX_OSERR, "client4: getaddrinfo: %s", gai_strerror(res));
	laddr = *(struct sockaddr_in *)ai->ai_addr;
	freeaddrinfo(ai);

	res = getaddrinfo(raddr_str, NULL, &aih, &ai);
	if (res != 0)
		err(EX_OSERR, "client4: getaddrinfo: %s", gai_strerror(res));
	raddr = *(struct sockaddr_in *)ai->ai_addr;
	freeaddrinfo(ai);
	raddr.sin_port = rport;

	inet_ntop(AF_INET, &laddr.sin_addr, laddr_buf, sizeof(laddr_buf));
	inet_ntop(AF_INET, &raddr.sin_addr, raddr_buf, sizeof(raddr_buf));

	if (!opt_quiet)
		fprintf(stderr,
				"client4: connecting %16s:%-5u -> %9s:%-5u\n",
				laddr_buf,
				ntohs(laddr.sin_port),
				raddr_buf,
				ntohs(raddr.sin_port));

	fd = socket(PF_INET, SOCK_STREAM, 0);
	if (fd < 0)
		err(EX_OSERR, "client4: socket");

	if (bind(fd, (struct sockaddr *)&laddr, sizeof(laddr)) < 0)
		err(EX_OSERR, "client4: bind");

	if (connect(fd, (struct sockaddr *)&raddr, sizeof(raddr)) < 0)
		err(EX_OSERR, "client4: connect");

	laddr_len = sizeof(laddr);
	if (getsockname(fd, (struct sockaddr *)&laddr, &laddr_len) < 0)
		err(EX_OSERR, "client4: getsockname");

	inet_ntop(AF_INET, &laddr.sin_addr, laddr_buf, sizeof(laddr_buf));

	if (!opt_quiet)
		fprintf(stderr,
				"client4: connected  %16s:%-5u -> %9s:%-5u\n",
				laddr_buf,
				ntohs(laddr.sin_port),
				raddr_buf,
				ntohs(raddr.sin_port));

	if (opt_shutdown)
		shutdown(fd, SHUT_RDWR);
	close(fd);
}

void
client6(const char *laddr_str, const char *raddr_str, in_port_t rport)
{
	struct addrinfo     aih, *ai;
	int                 fd, res, zero = 0;
	char                laddr_buf[INET6_ADDRSTRLEN], raddr_buf[INET6_ADDRSTRLEN];
	struct sockaddr_in6 laddr, raddr;
	socklen_t           laddr_len;

	memset(&aih, 0, sizeof(aih));
	aih.ai_family = AF_INET6;
	aih.ai_flags = AI_NUMERICHOST | AI_V4MAPPED;

	res = getaddrinfo(laddr_str, NULL, &aih, &ai);
	if (res != 0)
		err(EX_OSERR, "client6: getaddrinfo: %s", gai_strerror(res));
	laddr = *(struct sockaddr_in6 *)ai->ai_addr;
	freeaddrinfo(ai);

	res = getaddrinfo(raddr_str, NULL, &aih, &ai);
	if (res != 0)
		err(EX_OSERR, "client6: getaddrinfo: %s", gai_strerror(res));
	raddr = *(struct sockaddr_in6 *)ai->ai_addr;
	freeaddrinfo(ai);
	raddr.sin6_port = rport;

	inet_ntop(AF_INET6, &laddr.sin6_addr, laddr_buf, sizeof(laddr_buf));
	inet_ntop(AF_INET6, &raddr.sin6_addr, raddr_buf, sizeof(raddr_buf));

	if (!opt_quiet)
		fprintf(stderr,
				"client6: connecting %16s:%-5u -> %9s:%-5u\n",
				laddr_buf,
				ntohs(laddr.sin6_port),
				raddr_buf,
				ntohs(raddr.sin6_port));

	fd = socket(PF_INET6, SOCK_STREAM, 0);
	if (fd < 0)
		err(EX_OSERR, "client6: socket");

	if (setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, &zero, sizeof(zero)) < 0)
		err(EX_OSERR, "client6: setsockopt");

	if (bind(fd, (struct sockaddr *)&laddr, sizeof(laddr)) < 0)
		err(EX_OSERR, "client6: bind");

	if (connect(fd, (struct sockaddr *)&raddr, sizeof(raddr)) < 0)
		err(EX_OSERR, "client6: connect");

	laddr_len = sizeof(laddr);
	if (getsockname(fd, (struct sockaddr *)&laddr, &laddr_len) < 0)
		err(EX_OSERR, "client6: getsockname");

	inet_ntop(AF_INET6, &laddr.sin6_addr, laddr_buf, sizeof(laddr_buf));

	if (!opt_quiet)
		fprintf(stderr,
				"client6: connected  %16s:%-5u -> %9s:%-5u\n",
				laddr_buf,
				ntohs(laddr.sin6_port),
				raddr_buf,
				ntohs(raddr.sin6_port));

	if (opt_shutdown)
		shutdown(fd, SHUT_RDWR);
	close(fd);
}

struct conn {
	sa_family_t family;
	const char *laddr;
	const char *raddr;
};

struct conn conns[] = {
	// IPv4
	{.family = AF_INET, .laddr = "0.0.0.0", .raddr = "127.0.0.1"},
	{.family = AF_INET, .laddr = "127.0.0.1", .raddr = "127.0.0.1"},
	// IPv6
	{.family = AF_INET6, .laddr = "::", .raddr = "::1"},
	{.family = AF_INET6, .laddr = "::1", .raddr = "::1"},
	// IPv4-mapped
	{.family = AF_INET6, .laddr = "::", .raddr = "127.0.0.1"},
	{.family = AF_INET6, .laddr = "127.0.0.1", .raddr = "127.0.0.1"},
};

int
main(int argc, char *argv[])
{
	int                 opt;
	struct sockaddr_in  saddr4;
	struct sockaddr_in6 saddr6;
	thrd_t              thr4, thr6;

	while ((opt = getopt(argc, argv, "sqh")) != -1) {
		switch (opt) {
			case 's':
				opt_shutdown = 1;
				break;
			case 'q':
				opt_quiet = 1;
				break;
			case 'h':
				fprintf(stderr, "usage: localdial [-sqh]\n");
				exit(EX_USAGE);
				break;
			default:
				exit(EX_USAGE);
		}
	}

	cnd_init(&server_cnd);
	mtx_init(&server_mtx, mtx_plain);

	if (thrd_create(&thr4, server4_func, &saddr4) != thrd_success)
		err(EX_OSERR, "main: thrd_create: server4_func");
	if (thrd_create(&thr6, server6_func, &saddr6) != thrd_success)
		err(EX_OSERR, "main: thrd_create: server6_func");

	mtx_lock(&server_mtx);
	while (server_count < 2)
		cnd_wait(&server_cnd, &server_mtx);
	mtx_unlock(&server_mtx);

	for (;;) {
		for (size_t i = 0; i < sizeof(conns) / sizeof(conns[0]); i++) {
			switch (conns[i].family) {
				case AF_INET:
					client4(conns[i].laddr, conns[i].raddr, saddr4.sin_port);
					break;
				case AF_INET6:
					client6(conns[i].laddr, conns[i].raddr, saddr6.sin6_port);
					break;
			}
			// usleep(100);
		}
	}

	return 0;
}
