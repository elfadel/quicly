#ifndef _XOPEN_SOURCE
#define _XOPEN_SOURCE 700 /* required for glibc to use getaddrinfo, etc. */
#endif
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <netdb.h>
#include <stdio.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>
#include <stdbool.h>
#include <openssl/pem.h>
#include "../deps/picotls/include/picotls.h"
#include "../deps/picotls/include/picotls/openssl.h"
#include "../include/quicly.h"
#include "../include/quicly/defaults.h"
#include "../include/quicly/streambuf.h"

#define SERVER_CERT_FILE            "/home/vtl_server/quicly/examples/ca-cert.pem"
#define SERVER_KEYS_FILE            "/home/vtl_server/quicly/examples/server-key.pem"
#define SERVER 						1
#define CLIENT 						2
#define MAX_BURST_PACKETS 			10
#define MAX_PKT_SIZE 				4096

static int host_mode = CLIENT /* default value */;

typedef struct vtl_quic_socket {
	int fd;

	quicly_context_t ctx;
	quicly_cid_plaintext_t next_cid;
	
	quicly_conn_t *quic_cnx;
	quicly_stream_t *stream;
	
	struct sockaddr_storage src;
	struct sockaddr_storage dst;
} vtl_quic_socket_t;

struct st_stream_data_t {
	quicly_streambuf_t streambuf;

	/* others useful vars */
	int count;
};

struct shared_mem_t {
	uint8_t *buff;
	int len;
	int offset;
};

struct shared_mem_t rx_sh_mem;
struct tm *current_time;
time_t s;

static ptls_context_t tlsctx = {
        .random_bytes = ptls_openssl_random_bytes,
        .get_time = &ptls_get_time,
        .key_exchanges = ptls_openssl_key_exchanges,
        .cipher_suites = ptls_openssl_cipher_suites,
};

static void on_stop_sending(quicly_stream_t *stream, int err);
static void on_receive_reset(quicly_stream_t *stream, int err);
static void server_on_receive(quicly_stream_t *stream, size_t off, const void *src, size_t len);
static void client_on_receive(quicly_stream_t *stream, size_t off, const void *src, size_t len);

static int on_stream_open(quicly_stream_open_t *self, quicly_stream_t *stream) {
    
    static const quicly_stream_callbacks_t client_stream_callbacks = {
        									quicly_streambuf_destroy, 
        									quicly_streambuf_egress_shift, 
        									quicly_streambuf_egress_emit, 
        									on_stop_sending, 
        									client_on_receive,
        									on_receive_reset
    },

     			  						   server_stream_callbacks = {
        									quicly_streambuf_destroy, 
        									quicly_streambuf_egress_shift, 
        									quicly_streambuf_egress_emit, 
        									on_stop_sending, 
        									server_on_receive,
        									on_receive_reset
    };

    int ret;

    if ((ret = quicly_streambuf_create(stream, sizeof(struct st_stream_data_t))) != 0)
        return ret;
    stream->callbacks = host_mode == SERVER ? &server_stream_callbacks : &client_stream_callbacks;
    return 0;
}

static int resolve_address(struct sockaddr *l_addr, socklen_t *l_alen, const char *l_host, const char *l_port, 
						   struct sockaddr *r_addr, socklen_t *r_alen, const char *r_host, const char *r_port)
{
    struct addrinfo hints, *l_res, *r_res;
    int err;

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_DGRAM;
    hints.ai_protocol = 0;
    hints.ai_flags = AI_ADDRCONFIG | AI_NUMERICSERV | AI_PASSIVE;
    if ((err = getaddrinfo(l_host, l_port, &hints, &l_res)) != 0 || l_res == NULL) {
        fprintf(stderr, "failed to resolve address:%s:%s:%s\n", l_host, l_port,
                err != 0 ? gai_strerror(err) : "getaddrinfo returned NULL");
        return -1;
    }

    memcpy(l_addr, l_res->ai_addr, l_res->ai_addrlen);
    *l_alen = l_res->ai_addrlen;

    freeaddrinfo(l_res);

    /* Destination adress resolving */
    memset(&hints, 0, sizeof(hints));

    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_DGRAM;
    hints.ai_protocol = 0;
    hints.ai_flags = AI_ADDRCONFIG | AI_NUMERICSERV | AI_PASSIVE;
    if ((err = getaddrinfo(r_host, r_port, &hints, &r_res)) != 0 || r_res == NULL) {
        fprintf(stderr, "failed to resolve address:%s:%s:%s\n", r_host, r_port,
                err != 0 ? gai_strerror(err) : "getaddrinfo returned NULL");
        return -1;
    }

    memcpy(r_addr, r_res->ai_addr, r_res->ai_addrlen);
    *r_alen = r_res->ai_addrlen;

    freeaddrinfo(r_res);

    return 0;
}

static void send_packets(int fd, struct sockaddr *dest, struct iovec *packets, size_t num_packets) {

	for(size_t i = 0; i != num_packets; ++i) {
		struct msghdr msg;
		memset(&msg, 0, sizeof(msg));

		msg.msg_name = dest;
		msg.msg_namelen = quicly_get_socklen(dest);
		msg.msg_iov	= &packets[i];
		msg.msg_iovlen = 1;

		int ret;
		while((ret = (int)sendmsg(fd, &msg, 0)) == -1 && errno == EINTR)
			;
		if(ret == -1)
			perror("send_packets(): sendmsg failed.");

		/* TODO: uncomment to allow probes */
		/*
		 * s = time(NULL);
		 *
		 * current_time = localtime(&s);
		 * 
		 * printf("send QUIC packets %dB at %02d:%02d:%02d\n", ret,
		 *		current_time->tm_hour, 
		 *		current_time->tm_min,
		 *		current_time->tm_sec);
		*/
	}
}

static int send_pending(int fd, quicly_conn_t *conn) {
	quicly_address_t dest, src;
	struct iovec packets[MAX_BURST_PACKETS];
	uint8_t buffer[MAX_BURST_PACKETS * quicly_get_context(conn)->transport_params.max_udp_payload_size];
	size_t num_packets = MAX_BURST_PACKETS;
	int ret;

	ret = quicly_send(conn, &dest, &src, packets, &num_packets, buffer, sizeof(buffer));
	if(ret == 0 && num_packets != 0) {
		send_packets(fd, &dest.sa, packets, num_packets);
	}

	return ret; 
}

vtl_quic_socket_t* vtl_quic_init(int mode, 
									const char *src, const char *l_port,
									const char *dst, const char *r_port) 
{
	int ret = 0;

	vtl_quic_socket_t *sock = NULL;
	sock = calloc(1, sizeof(vtl_quic_socket_t));
	if(sock == NULL) {
		printf("calloc() failed.\n");
		return NULL;
	}

	sock->fd = socket(AF_INET, SOCK_DGRAM, 0);
    if(sock->fd < 0) {
        perror("socket() failed.");
        return NULL;
    }

    if(mode == SERVER) {
    	int one = 1;
    	ret = setsockopt(sock->fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
    	if(ret < 0) {
        	perror("setsockopt() failed.");
        	return NULL;
    	}
    	host_mode = SERVER;
    }

    struct sockaddr_storage local_addr, remote_addr;
    socklen_t l_addr_len, r_addr_len;
    ret = resolve_address((struct sockaddr *)&local_addr, &l_addr_len, src, l_port,
    					  (struct sockaddr *)&remote_addr, &r_addr_len, dst, r_port);
    if(ret != 0) {
        perror("resolve_address(): resolve_address failed.");
        return NULL;
    }

    memcpy(&(sock->src), &local_addr, l_addr_len);
    memcpy(&(sock->dst), &remote_addr, r_addr_len);

    ret = bind(sock->fd, (struct sockaddr *)&local_addr, l_addr_len);
    if(ret != 0) {
        perror("bind(1) failed.");
      	return NULL;
    }
    
    /* setup quic context */
    static quicly_stream_open_t stream_open = {&on_stream_open};
    sock->ctx = quicly_spec_context /*in quicly/defaults.h*/;
    sock->ctx.tls = &tlsctx;
    quicly_amend_ptls_context(sock->ctx.tls);
    sock->ctx.stream_open = &stream_open;

    /* load certificates and keys */
    if(mode == SERVER) {
    	ptls_openssl_sign_certificate_t sign_certificate;
    	
    	ret = ptls_load_certificates(&tlsctx, SERVER_CERT_FILE);
    	if(ret != 0) {
    		fprintf(stderr, "failed to load certificates from file %s:%d\n", SERVER_CERT_FILE, ret);
        	return NULL;
    	}

    	FILE *fp;
    	if((fp = fopen(SERVER_KEYS_FILE, "r")) == NULL) {
        	fprintf(stderr, "failed to open file:%s:%s\n", SERVER_KEYS_FILE, strerror(errno));
        	return NULL;
    	}

    	EVP_PKEY *pkey = PEM_read_PrivateKey(fp, NULL, NULL, NULL);
    	fclose(fp);
    	if(pkey == NULL) {
        	fprintf(stderr, "failed to load private key from file:%s\n", optarg);
        	return NULL;
    	}
    	ptls_openssl_init_sign_certificate(&sign_certificate, pkey);
    	EVP_PKEY_free(pkey);
    	tlsctx.sign_certificate = &sign_certificate.super;
    }

    return sock;
}

int vtl_quic_recv_loop(vtl_quic_socket_t *sock, int loop_count, bool reset_timeout) {

	if(loop_count == 0) {
		while(1) {
			fd_set read_fds;
			struct timeval tv;
			/* QUIC socket monitoring */
			do {
				int64_t first_timeout = INT64_MAX;
				int64_t now = sock->ctx.now->cb(sock->ctx.now);
				if(sock->quic_cnx != NULL) {
					int64_t conn_timeout = quicly_get_first_timeout(sock->quic_cnx);
					if(conn_timeout < first_timeout)
						first_timeout = conn_timeout;
				}

				if(now < first_timeout) {
					int64_t delta = first_timeout - now;
					if(delta > (1000*1000)/2)
						delta = (1000*1000)/2;
					tv.tv_sec = (delta / 1000)/2;
					tv.tv_usec = ((delta % 1000) * 1000)/2;
				}
				else {
					tv.tv_sec = 1000/2;
					tv.tv_usec = 0;
				}

				FD_ZERO(&read_fds);
				FD_SET(sock->fd, &read_fds);
			} while(select(sock->fd + 1, &read_fds, NULL, NULL, &tv) == -1 && errno == EINTR);

			/* process received event */
			if(FD_ISSET(sock->fd, &read_fds)) {
				uint8_t buffer[MAX_PKT_SIZE/* arbitrary */];
				struct sockaddr sa;
				struct iovec vec = {
					.iov_base = buffer,
					.iov_len = sizeof(buffer)
				};
				struct msghdr msg;
				memset(&msg, 0, sizeof(msg));
				msg.msg_name = &sa;
				msg.msg_namelen = sizeof(sa);
				msg.msg_iov = &vec;
				msg.msg_iovlen = 1;
				ssize_t rret;

				/* retrieve packet on QUIC socket */
				while((rret = recvmsg(sock->fd, &msg, 0)) == -1 && errno == EINTR)
					;
				if(rret <= 0) return -1;

				/* Let QUIC stack process received packets */
				size_t off = 0;
				while(off < rret) {
					quicly_decoded_packet_t decoded_pkt;
					if(quicly_decode_packet(&(sock->ctx), &decoded_pkt, buffer, rret, &off) == SIZE_MAX)
						break;
					quicly_receive(sock->quic_cnx, NULL, &sa, &decoded_pkt);
				}
			}

			/* Send QUIC packets if any */
			int ret = send_pending(sock->fd, sock->quic_cnx);
			if(ret != 0) {
				quicly_free(sock->quic_cnx);
				sock->quic_cnx = NULL;

				if(ret == QUICLY_ERROR_FREE_CONNECTION)
					return 0;
				else {
					fprintf(stderr, "quicly_send() returned %d\n", ret);
					return -1;
				}
			}
		}
	}
	else {
		int j = 0;
		while(j < loop_count) {
			fd_set read_fds;
			struct timeval tv;
			/* QUIC socket monitoring */
			do {
				/*printf("waiting event on QUIC socket %d at loop %d !\n", sock->fd,
						j+1);*/
				int64_t first_timeout = INT64_MAX;
				int64_t now = sock->ctx.now->cb(sock->ctx.now);
				if(sock->quic_cnx != NULL) {
					int64_t conn_timeout = quicly_get_first_timeout(sock->quic_cnx);
					if(conn_timeout < first_timeout)
						first_timeout = conn_timeout;
				}

				if(now < first_timeout) {
					int64_t delta = first_timeout - now;
					if(delta > (1000*1000)/2)
						delta = (1000*1000)/2;
					tv.tv_sec = (delta / 1000)/2;
					tv.tv_usec = ((delta % 1000) * 1000)/2;
				}
				else {
					tv.tv_sec = 1000/2;
					tv.tv_usec = 0;
				}
				
				if(reset_timeout) {
					tv.tv_sec = 0;
					tv.tv_usec = 0;
				}
				//printf("\t tv.tv_sec  = %ld\n", tv.tv_sec);
				//printf("\t tv.tv_usec = %ld\n", tv.tv_usec);
				FD_ZERO(&read_fds);
				FD_SET(sock->fd, &read_fds);
			} while(select(sock->fd + 1, &read_fds, NULL, NULL, &tv) == -1 && errno == EINTR);

			/* process received event */
			if(FD_ISSET(sock->fd, &read_fds)) {
				/*printf("processing event on QUIC socket %d at loop_count %d !\n", sock->fd,
						j+1);*/
				uint8_t buffer[MAX_PKT_SIZE/* arbitrary */];
				struct sockaddr sa;
				struct iovec vec = {
					.iov_base = buffer,
					.iov_len = sizeof(buffer)
				};
				struct msghdr msg;
				memset(&msg, 0, sizeof(msg));
				msg.msg_name = &sa;
				msg.msg_namelen = sizeof(sa);
				msg.msg_iov = &vec;
				msg.msg_iovlen = 1;
				ssize_t rret;

				/* retrieve packet on QUIC socket */
				while((rret = recvmsg(sock->fd, &msg, 0)) == -1 && errno == EINTR)
					;
				if(rret <= 0) return -1;

				/* Let QUIC stack process received packets */
				size_t off = 0;
				while(off < rret) {
					quicly_decoded_packet_t decoded_pkt;
					if(quicly_decode_packet(&(sock->ctx), &decoded_pkt, buffer, rret, &off) == SIZE_MAX)
						break;
					quicly_receive(sock->quic_cnx, NULL, &sa, &decoded_pkt);
				}

				/* Send QUIC packets if any */
				int ret = send_pending(sock->fd, sock->quic_cnx);
				if(ret != 0) {
					quicly_free(sock->quic_cnx);
					sock->quic_cnx = NULL;

					if(ret == QUICLY_ERROR_FREE_CONNECTION)
						return 0;
					else {
						fprintf(stderr, "quicly_send() returned %d\n", ret);
						return -1;
					}
				}
			}
			j++;
		}
	}

	return 0;
}

int vtl_quic_connect(vtl_quic_socket_t **sock_ptr, const char *server_name) {
	printf("\nvtl_quic_connect() START\n");
	int ret = -1;

	/* initiate quic connexion */
	ret = quicly_connect(&((*sock_ptr)->quic_cnx), &((*sock_ptr)->ctx), server_name, (struct sockaddr *)&((*sock_ptr)->dst), 
							NULL, &((*sock_ptr)->next_cid), ptls_iovec_init(NULL, 0), NULL, NULL);

	if(ret != 0) {
		fprintf(stderr, "vtl_quic_connect(): quicly_connect failed %d\n", ret);
		return -1;
	}

	/* open stream */
	ret = quicly_open_stream((*sock_ptr)->quic_cnx, &((*sock_ptr)->stream), 0);
	if(ret != 0) {
		perror("quicly_open_stream() failed.");
		return -1;
	}

	/* TODO: init stream_data if any*/
	/* 
	 * quicly_stream_t *stream = (*sock_ptr)->stream;
	 * struct st_stream_data_t *stream_data = stream->data;
	*/

	send_pending((*sock_ptr)->fd, (*sock_ptr)->quic_cnx);

	vtl_quic_recv_loop(*sock_ptr, 3, false);

	printf("\nvtl_quic_connect() END\n");

	return 0;
}

int vtl_quic_accept(vtl_quic_socket_t **sock_ptr) {
	printf("\nvtl_quic_accept() START\n");

	fd_set read_fds;
	struct timeval tv;
	
	for(int j = 0; j < 3; j++) {
		/* QUIC socket monitoring */
		do {
			int64_t first_timeout = INT64_MAX;
			int64_t now = (*sock_ptr)->ctx.now->cb((*sock_ptr)->ctx.now);
			if((*sock_ptr)->quic_cnx != NULL) {
				int64_t conn_timeout = quicly_get_first_timeout((*sock_ptr)->quic_cnx);
				if(conn_timeout < first_timeout)
					first_timeout = conn_timeout;
			}

			if(now < first_timeout) {
				int64_t delta = first_timeout - now;
				if(delta > 1000*1000)
					delta = 1000*1000;
				tv.tv_sec = delta / 1000;
				tv.tv_usec = (delta % 1000) * 1000;
			}
			else {
				tv.tv_sec = 1000;
				tv.tv_usec = 0;
			}

			FD_ZERO(&read_fds);
			FD_SET((*sock_ptr)->fd, &read_fds);
		} while(select((*sock_ptr)->fd + 1, &read_fds, NULL, NULL, &tv) == -1 && errno == EINTR);

		/* process received event */
		if(FD_ISSET((*sock_ptr)->fd, &read_fds)) {
			uint8_t buffer[MAX_PKT_SIZE /*arbitrary*/];
			quicly_address_t remote;
			struct iovec vec = {
				.iov_base = buffer,
				.iov_len = sizeof(buffer)
			};
			struct msghdr msg;
			memset(&msg, 0, sizeof(msg));
			msg.msg_name = &remote.sa;
			msg.msg_namelen = sizeof(remote);
			msg.msg_iov = &vec;	
			msg.msg_iovlen = 1;

			ssize_t rret;

			/* retrieve packet on QUIC socket */
			while((rret = recvmsg((*sock_ptr)->fd, &msg, 0))== -1 && errno == EINTR)
				;
			if(rret == -1) {
				fprintf(stderr, "vtl_quic_accept(): recvmsg failed. err=%d\n", errno);
				return -1;
			}

			size_t off = 0;
			/* Let QUIC stack process received packets */
			while(off < rret) {
				quicly_decoded_packet_t decoded_pkt;
				if(quicly_decode_packet(&((*sock_ptr)->ctx), &decoded_pkt, msg.msg_iov[0].iov_base, rret, &off) == SIZE_MAX) {
					fprintf(stderr, "vtl_quic_accept(): WARN - quicly_decode_packet failed.\n");
					break;
				}

				if((*sock_ptr)->quic_cnx != NULL) {
					/* connextion exist */
					quicly_receive((*sock_ptr)->quic_cnx, NULL, msg.msg_name, &decoded_pkt);
				}
				else {
					/* new connection */
					quicly_accept(&((*sock_ptr)->quic_cnx), &((*sock_ptr)->ctx), NULL, msg.msg_name, &decoded_pkt, NULL, 
								&((*sock_ptr)->next_cid), NULL);
				}
			}
			/* Send QUIC packets if any */
			send_pending((*sock_ptr)->fd, (*sock_ptr)->quic_cnx);
		}
	}

	/* open stream */
	int ret = -1;
	ret = quicly_open_stream((*sock_ptr)->quic_cnx, &((*sock_ptr)->stream), 0);
	if(ret != 0) {
		perror("quicly_open_stream() failed.");
		return -1;
	}
	
	printf("\nvtl_quic_accept() END\n");

	return 0;
}

int vtl_quic_send(vtl_quic_socket_t *sock, uint8_t *buffer, size_t buff_len) {
	
	quicly_stream_t *stream0;

	stream0 = sock->stream;
	if(stream0 == NULL || !quicly_sendstate_is_open(&stream0->sendstate)) {
		fprintf(stderr, "vtl_quic_send(): stream empty or sendstate not open.\n");
		return -1;
	}

	/* write data to send buffer */
	quicly_streambuf_egress_write(stream0, buffer, buff_len);

	/* ... and send quic packets to remote peer */
	send_pending(sock->fd, sock->quic_cnx);

	/* process ACK */
	vtl_quic_recv_loop(sock, 1, true);
	
	return 0;
}

int vtl_quic_recv(vtl_quic_socket_t *sock, uint8_t *rx_buff, size_t *buff_len) {

	vtl_quic_recv_loop(sock, 2, false);
	//TODO: two separate calls ???

	if(1) { /* TODO: add condition if any */
		*buff_len = rx_sh_mem.len;
		memcpy(rx_buff, rx_sh_mem.buff, *buff_len);

		/* reinit rx_sh_mem */
		rx_sh_mem.offset = 0;
		rx_sh_mem.len = 0;
		free(rx_sh_mem.buff);
		rx_sh_mem.buff = NULL;
	}
	
	return 0;
}

int vtl_quic_close(vtl_quic_socket_t *sock) {
	/* TODO: fill */
	
	return 0;
}

static void client_on_receive(quicly_stream_t *stream, size_t off, const void *src, size_t len) {

	struct st_stream_data_t *stream_data = stream->data;
	/* read input to receive buffer */
	if(quicly_streambuf_ingress_receive(stream, off, src, len) != 0)
		return;

	/* obtain contiguous bytes from the receive buffer */
	ptls_iovec_t input = quicly_streambuf_ingress_get(stream);

	if(input.len != 0) {
		stream_data->count++;
		
		if(rx_sh_mem.buff == NULL) {
			rx_sh_mem.buff = calloc(1, input.len);
		}
		else {
			rx_sh_mem.buff = (uint8_t *) realloc(rx_sh_mem.buff, input.len + rx_sh_mem.offset);
		}

		if(rx_sh_mem.buff != NULL) {
			memcpy(rx_sh_mem.buff + rx_sh_mem.offset, input.base, input.len);
			rx_sh_mem.len += input.len;
			rx_sh_mem.offset += rx_sh_mem.len;
		}
		else {
			printf("client_on_receive(): WARN - unable to calloc() or realloc()\n");
			rx_sh_mem.len = -1;
		}

		/*
		 * //This is a example code to store data directly in file.//
		 *
		 * if(stream_data->rx_file != NULL) {
		 *		fwrite(input.base, 1, input.len, stream_data->rx_file);
		 *		fflush(stream_data->rx_file);
		 * }
		 * else {
		 *	printf("init stream file to write on it\n");
		 *	stream_data->rx_file = fopen("./out_file_cpy.png", "w");
		 *	if(stream_data->rx_file == NULL) {
		 *		printf("WARN - unable to definetly open stream file\n");
		 *	}
		 *	fwrite(input.base, 1, input.len, stream_data->rx_file);
		 *	fflush(stream_data->rx_file);
		 *	}
		 *  
		*/

		/* removed used bytes from received buffer */
		quicly_streambuf_ingress_shift(stream, input.len);

	}
}

static void server_on_receive(quicly_stream_t *stream, size_t off, const void *src, size_t len) {
	return;
}

static void on_stop_sending(quicly_stream_t *stream, int err) {
    fprintf(stderr, "received STOP_SENDING: %" PRIu16 "\n", QUICLY_ERROR_GET_ERROR_CODE(err));
    quicly_close(stream->conn, QUICLY_ERROR_FROM_APPLICATION_ERROR_CODE(0), "");
}

static void on_receive_reset(quicly_stream_t* stream, int err) {
    fprintf(stderr, "received RESET_STREAM: %" PRIu16 "\n", QUICLY_ERROR_GET_ERROR_CODE(err));
    quicly_close(stream->conn, QUICLY_ERROR_FROM_APPLICATION_ERROR_CODE(0), "");
}