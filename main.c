#include <errno.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <netdb.h>
#include <string.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <linux/if.h>
#include <linux/if_tun.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <signal.h>
#include <sys/syscall.h>
#include <linux/futex.h>
#include <stdatomic.h>

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/rand.h>

#define NAME "dtlsvpn"

#define VPN_CIPHER "ECDHE-ECDSA-AES256-GCM-SHA384"

#define MTU 1500
#define TIMEOUT 250
/* connection will be kept alive for (TIMEOUT * MAX_TIMEOUTS / 1000) seconds */
#define MAX_TIMEOUTS (2 * 60 * 60) /* 30 minutes */

/* is not running but may be started */
#define STATE_STOP    0
/* is currently running */
#define STATE_RUNNING 1
/* is signalled to stop */
#define STATE_SIGSTOP 2

typedef uint32_t state_t;

struct thread_ctx {
	state_t state;
	pthread_t thread_id;
};

int futex_wait(uint32_t * x, uint32_t value, int timeout)
{
	struct timespec ts;
	if(timeout > 0) {
		ts.tv_sec = timeout / 1000;
		ts.tv_nsec = (timeout % 1000) * 1000000;
	}
	return syscall(SYS_futex, x, FUTEX_WAIT, value, timeout > 0 ? &ts : NULL, NULL, 0);
}

void futex_wake(uint32_t * x)
{
	if(syscall(SYS_futex, x, FUTEX_WAKE, 1, NULL, NULL, 0) < 0) {
		fprintf(stderr, "%s: %s\n", __func__, strerror(errno));
	}
}

int gracefully_terminate_thread(struct thread_ctx * ctx)
{
	state_t s;

	while(1) {
		s = ctx->state;
		switch(s) {
		case STATE_RUNNING:
			if(atomic_compare_exchange_strong(&ctx->state, &s, STATE_SIGSTOP))
				return futex_wait(&ctx->state, STATE_SIGSTOP, 1000);
			break;
		case STATE_STOP:
			return 0;
		default:
			errno = EINVAL;
			return -1;
		}
	}
}

int forcefully_terminate_read(struct thread_ctx * ctx)
{
	return pthread_cancel(ctx->thread_id);
}

static struct conn {
	SSL * ssl;
	int tfd;
	struct thread_ctx tun_read_thr;
	struct thread_ctx ssl_read_thr;

	/* methods. */
	void (* free_ssl)(struct conn * this);
} conn;

static struct thread_ctx listen_thr;

void free_tun(struct conn * c)
{
	if(!c->tfd) {
		fprintf(stderr, "%s: WARN: tun is not set\n", __func__);
		return;
	}

	close(c->tfd);
}

void free_ssl(struct conn * c)
{
	if(!c->ssl) {
		fprintf(stderr, 
			"%s: WARN: ssl is NULL\n", __func__);
		return;
	}

	int sfd = SSL_get_fd(c->ssl);
	if(sfd >= 0)
		close(sfd);
	SSL_free(c->ssl);
	c->ssl = NULL;
}

void free_ssl_w_shutdown(struct conn * c)
{
	if(!c->ssl) {
		fprintf(stderr, 
			"%s: WARN: ssl is NULL\n", __func__);
		return;
	}

	SSL_shutdown(c->ssl);
	free_ssl(c);
}

static unsigned char secret[32];

static int systemf(char * fmt, ...)
{
        va_list l;
        va_start(l, fmt);
        static char b[1024];
        vsnprintf(b, sizeof(b), fmt, l);
        va_end(l);
        printf("%s: %s\n", __func__, b);
	return system(b);
}

char * prefix(char * buf, const char * pref)
{
        int len = strlen(pref);
        char * tmpstart = buf - len;
        memcpy(tmpstart, pref, len);
        return strdup(tmpstart);
}

struct accept_args {
	struct conn * conn;
	BIO_ADDR * addr;
	SSL * ssl;
};

static struct cmd {
	char * add;
	char * del;
} cmds[10];
static int cmds_len = 0;

enum cmd_type {
	CMD_ROUTE = 1,
	CMD_RULE = 2,
	CMD_IPTABLES = 3,
};

static int managed_cmd(enum cmd_type t, char * _fmt, ...)
{
	char cmdb[2048];
	char * cmdbm = cmdb + 128;
	const int cmdbm_sz = sizeof(cmdb) - sizeof(cmdbm);
	int w;
	va_list l;
	va_start(l, _fmt);
	w = vsnprintf(cmdbm, cmdbm_sz, _fmt, l);
	va_end(l);

	if(w > cmdbm_sz) {
		errno = ERANGE;
		return -1;
	}

	if(cmds_len == sizeof(cmds)) {
		errno = ENOMEM;
		return -1;
	}

	char * add_cmd, * del_cmd;

	switch(t) {
	case CMD_ROUTE:
		add_cmd = prefix(cmdbm, "ip route add ");
		del_cmd = prefix(cmdbm, "ip route del ");
		break;
	case CMD_RULE:
		add_cmd = prefix(cmdbm, "ip rule add ");
		del_cmd = prefix(cmdbm, "ip rule del ");
		break;
	case CMD_IPTABLES:
		add_cmd = prefix(cmdbm, "iptables -A ");
		del_cmd = prefix(cmdbm, "iptables -D ");
		break;
	default:
		errno = EINVAL;
		return -1;
	}

	printf("%s: %s\n", __func__, add_cmd);

	if(system(add_cmd)) {
			return -1;
	}

	cmds[cmds_len].add = add_cmd;
	cmds[cmds_len].del = del_cmd;

	cmds_len++;

	return 0;
}

static struct opts {
	int is_server;
	char * host;
	char * svc;
	char * cert;
	char * key;
	char * cacert;
	char tun_name[IFNAMSIZ];
	char * tun_dev_addr;
} opts;

static int parse_opts(int argc, char ** argv) 
{
	int o;
	const char * optstring = "csh:p:C:K:A:n:a:";
	
	while((o = getopt(argc, argv, optstring)) != -1) {
		switch(o) {
		case 'c': /* client mode */
			opts.is_server = 0;
			break;
		case 's': /* server mode */
			opts.is_server = 1;
			break;
		case 'h': /* internet host, see `man 3 getaddrinfo` ; 'node' argument */
			opts.host = strdup(optarg);
			break;
		case 'p': /* service, see `man 3 getaddrinfo` ; 'service' argument  */
			opts.svc = strdup(optarg);
			break;
		case 'C': /* certificate file path, must be PEM */
			opts.cert = strdup(optarg);
			break;
		case 'K': /* key file path, must be PEM */
			opts.key = strdup(optarg);
			break;
		case 'A': /* CA certificate file path, must be PEM */
			opts.cacert = strdup(optarg);
			break;
		case 'n':
			strncpy(opts.tun_name, optarg, IFNAMSIZ);
			break;
		case 'a':
			opts.tun_dev_addr = strdup(optarg); 
			break;
		default:
			fprintf(stderr, "unkown option: %d, optstring is %s\n", o, optstring);
			return -1;
		}
	}
	
	int ok = 0;

	/* defaults */

	if(!opts.svc) {
		opts.svc = "7754";
	}

	if(!opts.cert) {
		opts.cert = "/etc/ssl/" NAME "/cert.pem";
	}

	if(!opts.key) {
		opts.key = "/etc/ssl/" NAME "/key.pem";
	}

	if(!opts.cacert) {
		opts.cacert = "/etc/ssl/" NAME "/ca.pem";
	}

	if(!*opts.tun_name) {
		strncpy(opts.tun_name, "tun0", IFNAMSIZ);
	}

	if(!opts.tun_dev_addr) {
		if(opts.is_server)
			opts.tun_dev_addr = "10.1.2.229/30";
		else
			opts.tun_dev_addr = "10.1.2.230/30";
	}

	if(opts.is_server) {
		if(!opts.host) {
			opts.host = "0.0.0.0";
		}
	} else if(!opts.host) { /* client */
		fprintf(stderr, "%s: no server host specified\n", __func__);
		ok = -1;
	}

	if(ok != 0)
		return ok;

	printf("%s: running as: %s\n", __func__, opts.is_server ? "server" : "client");
	printf("%s: using certificate: %s\n", __func__, opts.cert);
	printf("%s: using key: %s\n", __func__, opts.key);
	printf("%s: using CA certificate: %s\n", __func__, opts.cacert);
	printf("%s: configured host: %s\n", __func__, opts.host);
	printf("%s: configured service: %s\n", __func__, opts.svc);
	printf("%s: configured tun: %s\n", __func__, opts.tun_name);
	printf("%s: configured tun addr: %s\n", __func__, opts.tun_dev_addr);

	return ok;
}

static int create_tun(char * name, int namel)
{
	int fd;
	static struct ifreq ifr;


	if(namel > IFNAMSIZ) {
		errno = EINVAL;
		return -1;
	}

	if((fd = open("/dev/net/tun", O_RDWR)) < 0)
		return -1;

	/* L3 forwarding */
	ifr.ifr_flags = IFF_TUN | IFF_NO_PI;

	strncpy(ifr.ifr_name, name, IFNAMSIZ);

	if(ioctl(fd, TUNSETIFF, &ifr) < 0)
		return -1;

	strncpy(name, ifr.ifr_name, namel);

	return fd;
}

/* if ok return 0, otherwise -1 and errno is set */
static int setto(int socket, int sndto_ms, int rcvto_ms) 
{
	struct timeval tv;
	
	if(sndto_ms > 0) {
		tv.tv_sec = sndto_ms / 1000;
		tv.tv_usec = (sndto_ms % 1000) * 1e3;
		if(setsockopt(socket, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv)) == -1)
			return -1;
	}

	if(rcvto_ms > 0) {
		tv.tv_sec = rcvto_ms / 1000;
		tv.tv_usec = (rcvto_ms % 1000) * 1e3;
		if(setsockopt(socket, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) == -1)
			return -1;
	}

	return 0;
}

/*
 * 0 if ok, otherwise -1 and error is printed to stderr
 */
static int mkdgram(const char * host, const char * svc, int remote)
{
	struct addrinfo hint, *info, *cp;
	int s, sfd;

	memset(&hint, 0, sizeof(hint));
	hint.ai_family = AF_UNSPEC;
	hint.ai_socktype = SOCK_DGRAM;
	hint.ai_flags = remote ? 0 : AI_PASSIVE;

	if((s = getaddrinfo(host, svc, &hint, &info)) != 0){
		fprintf(stderr, "%s: %s\n", __func__, gai_strerror(s));
		return -1;
	}
	
	int one = 1;

	for(cp = info; cp ; cp = cp->ai_next) {
		sfd = socket(cp->ai_family, cp->ai_socktype, cp->ai_protocol);
		if(sfd == -1)
			continue;
		
		if(remote)
			break;
		
		one = 1;
		if(setsockopt(sfd, 
				SOL_SOCKET, 
				SO_REUSEADDR | SO_REUSEPORT, 
				&one, sizeof(int)
			) != 0)
			break;

		if(bind(sfd, cp->ai_addr, cp->ai_addrlen) == 0)
			break;
	}

	freeaddrinfo(info);
	if(!cp) {
		fprintf(stderr, "%s: failed to find socket\n", __func__);
		return -1;
	}

	return sfd;
}

/*
 * buff size must be at least EVP_MAX_MD_SIZE
 * */
static void hmac_peer(SSL * ssl, unsigned char * buff, unsigned int * buffsz) 
{
	struct sockaddr_storage peer;
	bzero(&peer, sizeof(peer));
	BIO_dgram_get_peer(SSL_get_rbio(ssl), &peer);
	HMAC(EVP_sha256(), secret, sizeof(secret), 
			(unsigned char *)&peer, sizeof(peer),
			buff, buffsz);
}

static int generate_cookie(SSL * ssl, unsigned char * cookie, unsigned int * cookie_len) 
{
	unsigned char buf[EVP_MAX_MD_SIZE];
	unsigned int l = 0;

	hmac_peer(ssl, buf, &l);
	if(l > DTLS1_COOKIE_LENGTH) {
		fprintf(stderr, "%s: couldnt generate cookie, buffer too small\n", __func__);
		return 0;
	}

	memcpy(cookie, buf, l);
	*cookie_len = l;
	return 1;
}

static int verify_cookie(SSL * ssl, const unsigned char * cookie, unsigned int cookie_len) 
{	
	unsigned char buf[EVP_MAX_MD_SIZE];
	unsigned int l = 0;
	hmac_peer(ssl, buf, &l);

	if(cookie_len == l && !memcmp(buf, cookie, l))
		return 1;	

	return 0;
}

static int verify_peer_cert(int ok, X509_STORE_CTX *ctx) {

	(void)ctx;
	
	/*
	 * TODO: verify san
	 * */
	
	return ok;
}

int start_thread(struct thread_ctx * r, void * (* fn)(void *), void * args)
{
	r->state = STATE_RUNNING;

	int ret = pthread_create(&r->thread_id, NULL, fn, args);

	if(ret != 0)
		r->state = STATE_STOP;

	return ret;
}

void * run_tun_read_loop(void * args)
{
	char buf[MTU];
	struct conn * conn = args;
	struct thread_ctx * rs = &conn->tun_read_thr;
	struct timeval tv;
	fd_set set;
	int r, w;;
	int sel;

	printf("%s: enter\n", __func__);

	while(rs->state == STATE_RUNNING) {
		
		tv.tv_sec = TIMEOUT / 1000;
		tv.tv_usec = (TIMEOUT % 1000) * 1000;
		FD_ZERO(&set);
		FD_SET(conn->tfd, &set);

		sel = select(conn->tfd + 1, &set, NULL, NULL, &tv);
		switch(sel){
		case -1:
			fprintf(stderr, "%s: select: %s\n", __func__, strerror(errno));
			goto end;
		case 0:
			break;
		default:
			r = read(conn->tfd, buf, sizeof(buf));
			if(r < 0) {
				fprintf(stderr, 
					"%s: failed to read from tun: %s\n", 
					__func__, strerror(errno));
				goto end;
			}

			if(!conn->ssl) {
				fprintf(stderr, 
					"%s: warn: tun got something but ssl is void\n", 
					__func__);
				break;
			}

			w = SSL_write(conn->ssl, buf, r);
			if(w <= 0) {
				w = SSL_get_error(conn->ssl, w);
				fprintf(stderr, "%s: SSL_write returned %d\n", __func__, w);
			}
		}
	}

end:
	printf("%s: terminated\n", __func__);
	rs->state = STATE_STOP;
	futex_wake(&rs->state);
	return NULL;
}


void * run_ssl_read_loop(void * args) 
{
	char buf[MTU];
	struct conn * conn = args;
	struct thread_ctx * rs = &conn->ssl_read_thr;
	int timeouts = 0, read, err, w, sfd, no_shutdown = 0;

	printf("%s: enter\n", __func__);

	SSL * ssl = conn->ssl;

	BIO * bio = SSL_get_rbio(ssl);
	if(!bio) {
		ERR_print_errors_fp(stderr);
		goto end;
	}

	sfd = SSL_get_fd(ssl);
	if(sfd <= 0) {
		ERR_print_errors_fp(stderr);
		goto end;
	}

	while(rs->state == STATE_RUNNING) {

		if(SSL_get_shutdown(ssl) & SSL_RECEIVED_SHUTDOWN) {
			printf("%s: got shutdown", __func__);
			break;
		}

		if(timeouts >= MAX_TIMEOUTS) {
			printf("%s: read timeout\n", __func__);
			break;
		}

		read = SSL_read(ssl, buf, sizeof(buf));
		err = SSL_get_error(ssl, read);
		switch(err) {
		case SSL_ERROR_NONE:
			timeouts = 0;

			if(!conn->tfd) {
				fprintf(stderr, 
					"%s: warn: ssl got something but tun is void\n", __func__);
				break;
			}

			w = write(conn->tfd, buf, sizeof(buf));
			if(w < 0) {
				fprintf(stderr, 
					"%s: write to tun: %s\n", __func__, strerror(errno));
				goto end;
			}
			break;
		case SSL_ERROR_WANT_READ:
			if(BIO_ctrl(bio, BIO_CTRL_DGRAM_GET_RECV_TIMER_EXP, 0, NULL)) {
				timeouts++;
			}
			break;
		case SSL_ERROR_ZERO_RETURN:
			goto end;
		case SSL_ERROR_SYSCALL:
			if(errno == EAGAIN || errno == EWOULDBLOCK) {
				timeouts++;
				break;
			}
			no_shutdown = 1;
			goto end;
		default:
			no_shutdown = 1;
			goto end;
		}
	}

end:
	if(no_shutdown)
		conn->free_ssl = free_ssl;
	else
		conn->free_ssl = free_ssl_w_shutdown;

	printf("%s: terminated (%d)\n", __func__, err);
	
	rs->state = STATE_STOP;
	futex_wake(&rs->state);

	return NULL;
}


static void * dtls_accept(void * args) 
{
	struct accept_args * r = (struct accept_args *)args;
	struct conn * c = r->conn;
	int s = 0;

	int sfd = mkdgram(opts.host, opts.svc, 0);	
	if(sfd <= 0)
		goto err; /* err is printed to stderr */

	BIO * rbio = SSL_get_rbio(r->ssl);

	if(!rbio) {
		fprintf(stderr, "couldnt get rbio\n");
		goto err;
	}

	switch(BIO_ADDR_family(r->addr)) {
	case AF_INET:
		s = connect(sfd, (struct sockaddr*)r->addr, sizeof(struct sockaddr_in));
		break;
	case AF_INET6:
		s = connect(sfd, (struct sockaddr*)r->addr, sizeof(struct sockaddr_in6));
		break;
	default:
		fprintf(stderr, "unkown peer AF_FAMILY\n");
		goto err;
	}

	if(s != 0) {
		perror("connect");
		goto err;
	}

	if(setto(sfd, TIMEOUT, TIMEOUT) != 0) {
		perror("setto");
		goto err;
	}

	BIO_set_fd(rbio, sfd, BIO_NOCLOSE);

	do {
		s = SSL_accept(r->ssl);
	} while(!s);

	if(s < 0) {
		ERR_print_errors_fp(stderr);
		goto err;
	}

	/* for now accept() is done in the same thread as listen,
	   so this is fine. But later locking must be implemented.
	*/
	if(c->ssl) {
		printf("%s: freeing old connection\n", __func__);
		if(gracefully_terminate_thread(&r->conn->ssl_read_thr)) {
			fprintf(stderr, "%s: failed to gracefully_terminate_read.\n"
				"Error was: %s\n"
				"Is it already terminating? If so then try again.\n", 
					__func__, strerror(errno));
			goto err;
		}

		r->conn->free_ssl(r->conn);
	}

	c->ssl = r->ssl;
	c->free_ssl = free_ssl_w_shutdown;

	BIO_ADDR_free(r->addr);
	free(r);

	if(start_thread(&c->ssl_read_thr, run_ssl_read_loop, c) == 0) {
		printf("%s: accepted new connection\n", __func__);
		return NULL;
	}

	fprintf(stderr, "%s: failed to start_thread(run_ssl_read_loop), error was: %s\n",
		__func__, strerror(errno));
	
	c->free_ssl(c);

	return NULL;
err:
	if(sfd > 0)
		close(sfd);
	SSL_free(r->ssl);
	BIO_ADDR_free(r->addr);
	free(r);
	return NULL;
}

static void * run_dtls_listen(void * args) 
{
	int socket = *(int *)args; 
	SSL_CTX * ctx = NULL;
	SSL * ssl = NULL;
	BIO * bio = NULL;
	BIO_ADDR * addr = NULL;

	int s = -1;
	int err = -1;

	if(RAND_bytes(secret, sizeof(secret)) != 1)
		goto end;
	
	if(!(ctx = SSL_CTX_new(DTLS_server_method())))
		goto end;

	if(SSL_CTX_set_cipher_list(ctx, VPN_CIPHER) != 1)
		goto end;

	SSL_CTX_set_session_cache_mode(ctx, SSL_SESS_CACHE_OFF);
	SSL_CTX_set_cookie_generate_cb(ctx, generate_cookie);
	SSL_CTX_set_cookie_verify_cb(ctx, verify_cookie);

	if(SSL_CTX_use_certificate_file(ctx, opts.cert, SSL_FILETYPE_PEM) != 1)
		goto end;

	if(SSL_CTX_use_PrivateKey_file(ctx, opts.key, SSL_FILETYPE_PEM) != 1)
		goto end;

	if(SSL_CTX_load_verify_locations(ctx, opts.cacert, NULL) != 1)
		goto end;

	SSL_CTX_set_options(ctx, SSL_OP_NO_COMPRESSION);
	SSL_CTX_set_options(ctx, SSL_OP_COOKIE_EXCHANGE);

	if(SSL_CTX_check_private_key(ctx) != 1)
		goto end;

	SSL_CTX_set_verify(ctx, 
			SSL_VERIFY_PEER | SSL_VERIFY_CLIENT_ONCE | SSL_VERIFY_FAIL_IF_NO_PEER_CERT,
			verify_peer_cert);

	SSL_CTX_set_read_ahead(ctx, 1);

	printf("%s: listening...\n", __func__);

	while(listen_thr.state == STATE_RUNNING) {

		addr = NULL;
		ssl = NULL;

		if(!(bio = BIO_new_dgram(socket, BIO_NOCLOSE)))
			goto end;

		addr = BIO_ADDR_new();

		if(!(ssl = SSL_new(ctx)))
			goto end;

		SSL_set_bio(ssl, bio, bio);
		
		while((s = DTLSv1_listen(ssl, addr)) <= 0) {
			if(s < 0) {
				ERR_print_errors_fp(stderr);
			}
			if(listen_thr.state != STATE_RUNNING)
				goto end;
		}

		/* for now accept is synchronous. It makes it easier to synchronize everything.
			but can can lead to DoS. TODO: move it to separate thread
		*/

		struct accept_args * a = malloc(sizeof(struct accept_args));
		a->ssl = ssl;
		a->addr = addr;
		/* for now only one peer can be maintained.
		 */
		a->conn = &conn;

		dtls_accept(a);
	}

end:
	if(ctx) 
		SSL_CTX_free(ctx);
	if(ssl)
		SSL_free(ssl);
	if(addr)
		BIO_ADDR_free(addr);
	
	printf("%s: terminated (%d)\n", __func__, err);

	listen_thr.state = STATE_STOP;
	futex_wake(&listen_thr.state);
	
	return NULL;
}

static int dtls_connect(int sfd, struct sockaddr_storage * ss, 
		const char * keypath, const char * certpath, const char * capath) 
{
	SSL_CTX * ctx = NULL;
	BIO * bio;
	SSL * _ssl = NULL;
	int err = -1;
	int s;

	if(!(ctx = SSL_CTX_new(DTLS_client_method())))
		goto end;

	if(SSL_CTX_set_cipher_list(ctx, VPN_CIPHER) != 1)
		goto end;

	SSL_CTX_set_options(ctx, SSL_OP_NO_COMPRESSION);

	if(SSL_CTX_use_certificate_file(ctx, certpath, SSL_FILETYPE_PEM) != 1)
		goto end;
	if(SSL_CTX_use_PrivateKey_file(ctx, keypath, SSL_FILETYPE_PEM) != 1)
		goto end;

	if(SSL_CTX_load_verify_locations(ctx, capath, NULL) != 1)
		goto end;	

	if(SSL_CTX_check_private_key(ctx) != 1)
		goto end;

	SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, verify_peer_cert);

	SSL_CTX_set_read_ahead(ctx, 1);

	if(!(_ssl = SSL_new(ctx)))
		goto end;

	if(!(bio = BIO_new_dgram(sfd, BIO_NOCLOSE)))
		goto end;

	BIO_ctrl(bio, BIO_CTRL_DGRAM_SET_CONNECTED, 0, ss);

	SSL_set_bio(_ssl, bio, bio);

	if((s = SSL_connect(_ssl)) != 1) {
		s = SSL_get_error(_ssl, s);
		switch(s) {
		case SSL_ERROR_SYSCALL:
			/* client will print errno */
			/* fprintf(stderr, "%s: connect: %s\n", __func__, strerror(errno)); */
			break;
		default:
			fprintf(stderr, "%s: connect: %s\n", __func__, ERR_error_string(s, NULL));
		}
		goto end;
	}

	printf("%s: connection established\n", __func__);

	conn.ssl = _ssl;
	conn.free_ssl = free_ssl_w_shutdown;
	s = start_thread(&conn.ssl_read_thr, run_ssl_read_loop, &conn);

	SSL_CTX_free(ctx);
	
	if(s != 0) {
		conn.free_ssl(&conn);
		return s;
	}

	return 0;

end:

	if(ctx)
		SSL_CTX_free(ctx);
	if(_ssl)
		SSL_free(_ssl);

	return err;
}

void cleanup(int sig)
{
	(void)sig;

	printf("%s\n", __func__);

	if(opts.is_server && gracefully_terminate_thread(&listen_thr)) {
		fprintf(stderr, "%s: failed to terminate listen_thr, err: %s\n", 
			__func__, strerror(errno));
		forcefully_terminate_read(&listen_thr);
	}

	if(gracefully_terminate_thread(&conn.ssl_read_thr)) {
		fprintf(stderr, "%s: failed to terminate ssl_read, err: %s\n", 
			__func__, strerror(errno));
		forcefully_terminate_read(&conn.ssl_read_thr);
	}

	if(gracefully_terminate_thread(&conn.tun_read_thr)) {
		fprintf(stderr, "%s: failed to terminate tun_read, err: %s\n", 
			__func__, strerror(errno));
		forcefully_terminate_read(&conn.tun_read_thr);
	}

	if(conn.ssl)
		conn.free_ssl(&conn);
	if(conn.tfd)
		close(conn.tfd);

	for(int i =0; i < cmds_len; i++) {
		printf("%s: system: %s\n", __func__, cmds[i].del);
		if(system(cmds[i].del)) {
			fprintf(stderr, "failed, errno is = [%s]\n", strerror(errno));
		}
	}

	printf("%s: done\n", __func__);
	_exit(0);
}

int setup_signals(void)
{
	struct sigaction sa;
	sa.sa_handler = &cleanup;
	sigfillset(&sa.sa_mask); /* block all signals during cleanup */
	if (sigaction(SIGHUP, &sa, NULL) < 0) {
		perror("Cannot handle SIGHUP");
	}
	if (sigaction(SIGINT, &sa, NULL) < 0) {
		perror("Cannot handle SIGINT");
		return EXIT_FAILURE;
	}
	if (sigaction(SIGTERM, &sa, NULL) < 0) {
		perror("Cannot handle SIGTERM");
	}
	
	return 0;
}

int main(int argc, char ** argv)
{
	OpenSSL_add_ssl_algorithms();
	SSL_load_error_strings();

	if(parse_opts(argc, argv) != 0)
		return EXIT_FAILURE; /* err is printed to stderr */

	struct sockaddr_storage ss;
	int sfd;

	if(opts.is_server) {
		sfd = mkdgram(opts.host, opts.svc, 0);
		if(sfd == -1)
			return 1; /* err is printed */
	} else {
		sfd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
		if(sfd == -1) {
			perror("socket");
			return EXIT_FAILURE;
		}
		struct sockaddr_in * rsin = (struct sockaddr_in *)&ss;
		rsin->sin_family = AF_INET;
		rsin->sin_port = htons(atoi(opts.svc));
		inet_aton(opts.host, &rsin->sin_addr);
		if(connect(sfd, (struct sockaddr*)rsin, sizeof(*rsin)) != 0) {
			perror("connect");
			return EXIT_FAILURE;
		}
	}

	if(setto(sfd, TIMEOUT, TIMEOUT) != 0) {
		perror("set timeout");
		return EXIT_FAILURE;
	}


	if(setup_signals() != 0)
		return EXIT_FAILURE;

	
	char ptun[IFNAMSIZ];
	strncpy(ptun, opts.tun_name, IFNAMSIZ);
	conn.tfd = create_tun(opts.tun_name, strlen(opts.tun_name));
	if(conn.tfd <= 0) {
		perror("create tun");
		return EXIT_FAILURE;
	}

	if(strcmp(ptun, opts.tun_name)) {
		fprintf(stderr, "warn: tun changed to %s\n", opts.tun_name);
	}

	if(systemf("ip a a %s dev %s", opts.tun_dev_addr, opts.tun_name)) {
		fprintf(stderr, "couldnt set tun address\n");
		return EXIT_FAILURE;
	}

	if(systemf("ip l set dev %s mtu %d", opts.tun_name, MTU)) {
		fprintf(stderr, "couldnt set tun mtu\n");
		return EXIT_FAILURE;
	}

	if(systemf("ip l set dev %s up", opts.tun_name)) {
		fprintf(stderr, "couldnt set tun up");
		return EXIT_FAILURE;
	}

	if(start_thread(&conn.tun_read_thr, run_tun_read_loop, &conn) != 0) {
		perror("create run_tun_read_loop thread");
		return EXIT_FAILURE;
	}

	if(opts.is_server) {
		if(managed_cmd(CMD_IPTABLES, "POSTROUTING -t nat -s %s ! -d %s -j MASQUERADE", 
				opts.tun_dev_addr, opts.tun_dev_addr)) {
			fprintf(stderr, "couldnt set masquerade\n");
			goto cleanup;
		}

		if(managed_cmd(CMD_IPTABLES, "FORWARD -s %s -j ACCEPT", opts.tun_dev_addr)) {
			fprintf(stderr, "couldnt setup forwarding\n");
			goto cleanup;
		}
		
		if(managed_cmd(CMD_IPTABLES, 
				"FORWARD -d %s -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT", 
				opts.tun_dev_addr)) {
			fprintf(stderr, "couldnt forward to client");
			goto cleanup;
		}

		if(start_thread(&listen_thr, run_dtls_listen, &sfd) != 0) {
			perror("start_thread(run_dtls_listen)");
			return EXIT_FAILURE;
		}

		if(futex_wait(&listen_thr.state, STATE_RUNNING, 0)) {
			perror("futex_wait(listen_thr)");
			return EXIT_FAILURE;
		}
	} else {
		int last_errno = 0, err;

		while(1) {
			err = dtls_connect(sfd, &ss, opts.key, opts.cert, opts.cacert);

			if(err) {
				if(errno != last_errno) {
					fprintf(stderr, "dtls_connect: %s\n", 
						errno ? strerror(errno) : "unkown/ssl error");
				}

				last_errno = errno;
				ERR_print_errors_fp(stderr);
				sleep(1);
				continue;
			}

			last_errno = 0;

			if(futex_wait(&conn.ssl_read_thr.state, STATE_RUNNING, 0)) {
				perror("futex_wait(ssl_read_thr)");
				goto cleanup;
			}
		}	
	}

cleanup:
	printf("%s: exit\n", __func__);
	cleanup(0);
}
