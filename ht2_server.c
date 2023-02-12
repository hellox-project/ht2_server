#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <assert.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <netdb.h>
#include <fcntl.h>
#include <signal.h>
#include <linux/if.h>
#include <linux/if_tun.h>
#include <arpa/inet.h>

#include "aes.h"

/*
 * The following lines serve as configurations
 * Uncomment first 2 lines to run as vpn client
 */

// #define AS_CLIENT YES
// #define SERVER_HOST ""

#define PORT 56893
#define MTU 1800
#define BIND_HOST "0.0.0.0"

/* Debug ciphering. */
#define DEBUG_CIPHERING 0

/* Sequence number for tx. */
static uint32_t global_seqno_tx = 0;
/* Cipher context related variables. */
static mbedtls_aes_context cipher_ctx;
static unsigned char __key[] =
	{ 0x36, 0x49, 0xC9, 0x86, 0x32, 0xAA, 0x27, 0xDB,
	  0x80, 0xFD, 0x48, 0xE7, 0xE8, 0xFE, 0x23, 0x09,
	  0xEC, 0x2F, 0x1E, 0xCF, 0x28, 0xDD, 0x32, 0xC8,
	  0x3F, 0x5E, 0x80, 0x0D, 0x09, 0x42, 0xEB, 0x82 };
static unsigned char __iv[16];

static int max(int a, int b) {
  return a > b ? a : b;
}

/* Init intial vector. */
static void __init_cipher_iv(unsigned char* iv)
{
  for(int i = 0; i < 16; i++)
  {
    iv[i] = (unsigned char)rand();
  }
}

/* Load ciphering key. */
static int __load_cipher_key(unsigned char* key)
{
  memcpy(key, __key, 32);
  return 0;
}

static int __init_cipher_context()
{
  mbedtls_aes_init(&cipher_ctx);
  return 0;
}

/*
 * Create VPN interface /dev/tun0 and return a fd
 */
int tun_alloc() {
  struct ifreq ifr;
  int fd, e;

  if ((fd = open("/dev/net/tun", O_RDWR)) < 0) {
    perror("Cannot open /dev/net/tun");
    return fd;
  }

  memset(&ifr, 0, sizeof(ifr));

  ifr.ifr_flags = IFF_TUN | IFF_NO_PI;
  strncpy(ifr.ifr_name, "tun0", IFNAMSIZ);

  if ((e = ioctl(fd, TUNSETIFF, (void *) &ifr)) < 0) {
    perror("ioctl[TUNSETIFF]");
    close(fd);
    return e;
  }

  return fd;
}


/*
 * Execute commands
 */
static void run(char *cmd) {
  printf("Execute `%s`\n", cmd);
  if (system(cmd)) {
    perror(cmd);
    exit(1);
  }
}


/*
 * Configure IP address and MTU of VPN interface /dev/tun0
 */
void ifconfig() {
  char cmd[1024];

#ifdef AS_CLIENT
  snprintf(cmd, sizeof(cmd), "ifconfig tun0 192.168.0.2/16 mtu %d up", MTU);
#else
  snprintf(cmd, sizeof(cmd), "ifconfig tun0 192.168.0.1/16 mtu %d up", MTU);
#endif
  run(cmd);
}


/*
 * Setup route table via `iptables` & `ip route`
 */
void setup_route_table() {
  run("sysctl -w net.ipv4.ip_forward=1");

#ifdef AS_CLIENT
  run("iptables -t nat -A POSTROUTING -o tun0 -j MASQUERADE");
  run("iptables -I FORWARD 1 -i tun0 -m state --state RELATED,ESTABLISHED -j ACCEPT");
  run("iptables -I FORWARD 1 -o tun0 -j ACCEPT");
  char cmd[1024];
  snprintf(cmd, sizeof(cmd), "ip route add %s via $(ip route show 0/0 | sed -e 's/.* via \([^ ]*\).*/\1/')", SERVER_HOST);
  run(cmd);
  run("ip route add 0/1 dev tun0");
  run("ip route add 128/1 dev tun0");
#else
  run("iptables -t nat -A POSTROUTING -s 192.168.0.0/16 ! -d 192.168.0.0/16 -m comment --comment 'vpndemo' -j MASQUERADE");
  run("iptables -A FORWARD -s 192.168.0.0/16 -m state --state RELATED,ESTABLISHED -j ACCEPT");
  run("iptables -A FORWARD -d 192.168.0.0/16 -j ACCEPT");
#endif
}

/*
 * Cleanup route table
 */
void cleanup_route_table() {
#ifdef AS_CLIENT
  run("iptables -t nat -D POSTROUTING -o tun0 -j MASQUERADE");
  run("iptables -D FORWARD -i tun0 -m state --state RELATED,ESTABLISHED -j ACCEPT");
  run("iptables -D FORWARD -o tun0 -j ACCEPT");
  char cmd[1024];
  snprintf(cmd, sizeof(cmd), "ip route del %s", SERVER_HOST);
  run(cmd);
  run("ip route del 0/1");
  run("ip route del 128/1");
#else
  run("iptables -t nat -D POSTROUTING -s 192.168.0.0/16 ! -d 192.168.0.0/16 -m comment --comment 'vpndemo' -j MASQUERADE");
  run("iptables -D FORWARD -s 192.168.0.0/16 -m state --state RELATED,ESTABLISHED -j ACCEPT");
  run("iptables -D FORWARD -d 192.168.0.0/16 -j ACCEPT");
#endif
}

/*
 * Bind UDP port
 */
int udp_bind(struct sockaddr *addr, socklen_t* addrlen) {
  struct addrinfo hints;
  struct addrinfo *result;
  int sock, flags;

  memset(&hints, 0, sizeof(hints));
  hints.ai_socktype = SOCK_DGRAM;
  hints.ai_protocol = IPPROTO_UDP;

#ifdef AS_CLIENT
  const char *host = SERVER_HOST;
#else
  const char *host = BIND_HOST;
#endif
  if (0 != getaddrinfo(host, NULL, &hints, &result)) {
    perror("getaddrinfo error");
    return -1;
  }

  if (result->ai_family == AF_INET)
    ((struct sockaddr_in *)result->ai_addr)->sin_port = htons(PORT);
  else if (result->ai_family == AF_INET6)
    ((struct sockaddr_in6 *)result->ai_addr)->sin6_port = htons(PORT);
  else {
    fprintf(stderr, "unknown ai_family %d", result->ai_family);
    freeaddrinfo(result);
    return -1;
  }
  memcpy(addr, result->ai_addr, result->ai_addrlen);
  *addrlen = result->ai_addrlen;

  if (-1 == (sock = socket(result->ai_family, SOCK_DGRAM, IPPROTO_UDP))) {
    perror("Cannot create socket");
    freeaddrinfo(result);
    return -1;
  }

#ifndef AS_CLIENT
  if (0 != bind(sock, result->ai_addr, result->ai_addrlen)) {
    perror("Cannot bind");
    close(sock);
    freeaddrinfo(result);
    return -1;
  }
#endif

  freeaddrinfo(result);

  flags = fcntl(sock, F_GETFL, 0);
  if (flags != -1) {
    if (-1 != fcntl(sock, F_SETFL, flags | O_NONBLOCK))
      return sock;
  }
  perror("fcntl error");

  close(sock);
  return -1;
}

/*
 * Catch Ctrl-C and `kill`s, make sure route table gets 
 * cleaned before this process exit
 */
void cleanup(int signo) {
  printf("Goodbye, cruel world....\n");
  if (signo == SIGHUP || signo == SIGINT || signo == SIGTERM) {
    cleanup_route_table();
    exit(0);
  }
}

void cleanup_when_sig_exit() {
  struct sigaction sa;
  sa.sa_handler = &cleanup;
  sa.sa_flags = SA_RESTART;
  sigfillset(&sa.sa_mask);

  if (sigaction(SIGHUP, &sa, NULL) < 0) {
    perror("Cannot handle SIGHUP");
  }
  if (sigaction(SIGINT, &sa, NULL) < 0) {
    perror("Cannot handle SIGINT");
  }
  if (sigaction(SIGTERM, &sa, NULL) < 0) {
    perror("Cannot handle SIGTERM");
  }
}

/* helper routine to align a value to AES alignment. */
static int aes_align(int length)
{
  int align_len = 0;
  align_len = ((length + 15) & ~15);
  return align_len;
}

/*
 * Encrypt a clear packet using AES algorithm.
 * The routine returns cipher text's length if success,
 * which different with len, since alignment
 * applied to the buffer, and ht2 header appended in
 * front of the buffer.
 */
static int encrypt(char *plaintext, char *ciphertext, int len) 
{
  int error = -1;
  unsigned char* payload = NULL;
  uint16_t align_len = 0;
  uint8_t padsz = 0;

  if(len > 1600)
  {
    printf("packet too big[%d]\r\n", len);
    return -1;
  }

  /* Buffer must align with AES alignment. */
  align_len = aes_align(len);
  padsz = align_len - len;

  /* Init ciphering context. */
  mbedtls_aes_init(&cipher_ctx);
  mbedtls_aes_setkey_enc(&cipher_ctx, __key, 256);
  __init_cipher_iv(__iv);

  /* Setup ht2 header. */
  payload = ciphertext;
  *payload = 1;               /* version. */
  payload += 1;
  *payload = padsz;           /* pad size. */
  payload += 1;
  *(uint16_t*)payload = 0;    /* session id. */
  payload += sizeof(uint16_t);
  *(uint32_t*)payload = global_seqno_tx++;  /* seqno. */
  payload += sizeof(uint32_t);
  memcpy(payload, __iv, 16);  /* iv. */
  payload += 16;

  /* Carry out encryption. */
  error = mbedtls_aes_crypt_cbc(&cipher_ctx,
    MBEDTLS_AES_ENCRYPT,
    align_len,
    __iv,
    plaintext, /* clear text. */
    payload);  /* cipher text. */
  if(error < 0)
  {
    printf("Encrypt failed[%d]\r\n", error);
    return error;
  }

#if DEBUG_CIPHERING
  /* for debugging. */
  printf("encrypt packet: cipher_length[%d], seqno[%d], pad[%d]\r\n",
    align_len + 24,
    global_seqno_tx - 1,
    padsz);
  #endif

  //memcpy(ciphertext, plaintext, len);
  return (align_len + 24);
}

/* Decrypt a packet. */
static int decrypt(char *ciphertext, char *plaintext, int len) 
{
  int cipher_txt_length = 0;
  unsigned char* payload = NULL;
  int padsz = 0;
  uint32_t seqno = 0;

  /* Init ciphering context and set key. */
  mbedtls_aes_init(&cipher_ctx);
  mbedtls_aes_setkey_dec(&cipher_ctx, __key, 256);

  /* Process ht2 header. */
  payload = (unsigned char*)ciphertext;
  payload++; /* skip version. */
  padsz = *payload;
  payload += 3; /* skip pad, session id. */
  seqno = htonl(*(uint32_t*)payload);
  payload += 4; /* skip seqno. */
  memcpy(__iv, payload, 16); /* load IV. */
  payload += 16; /* Now payload points to cipher text. */
  cipher_txt_length = len - 24; /* skip the ht2 header. */

#if DEBUG_CIPHERING
  printf("Decrypt a packet: length[%d], seqno[%d], pad[%d]....\r\n",
    cipher_txt_length,
    seqno,
    padsz);
#endif

  /* Carryout decryption. */
  int result = mbedtls_aes_crypt_cbc(&cipher_ctx, 
    MBEDTLS_AES_DECRYPT,
    cipher_txt_length,
    __iv,
    payload, plaintext);
  
  if(result < 0)
  {
    /* error */
    return result;
  }
  //memcpy(plaintext, payload, cipher_txt_length);

  /* 
   * Clear text after decryption contains the 
   * pad bytes so we must omit them.
   */
  return (cipher_txt_length - padsz);
}

int main(int argc, char **argv) {
  int tun_fd;

  /* Init ciphering context. */
  if(__init_cipher_context())
  {
    printf("Init ciphering context fail.\r\n");
    return 1;
  }
  
  if ((tun_fd = tun_alloc()) < 0) {
    return 1;
  }

  ifconfig();
  setup_route_table();
  cleanup_when_sig_exit();

  int udp_fd;
  struct sockaddr_storage client_addr;
  socklen_t client_addrlen = sizeof(client_addr);

  if ((udp_fd = udp_bind((struct sockaddr *)&client_addr, &client_addrlen)) < 0) {
    return 1;
  }

  /*
   * tun_buf - memory buffer read from/write to tun dev - is always plain
   * udp_buf - memory buffer read from/write to udp fd - is always encrypted
   */
  char tun_buf[MTU], udp_buf[MTU];
  bzero(tun_buf, MTU);
  bzero(udp_buf, MTU);

  while (1) {
    fd_set readset;
    FD_ZERO(&readset);
    FD_SET(tun_fd, &readset);
    FD_SET(udp_fd, &readset);
    int max_fd = max(tun_fd, udp_fd) + 1;

    if (-1 == select(max_fd, &readset, NULL, NULL, NULL)) {
      perror("select error");
      break;
    }

    int r;
    if (FD_ISSET(tun_fd, &readset)) {
      r = read(tun_fd, tun_buf, MTU);
      if (r < 0) {
        // TODO: ignore some errno
        perror("read from tun_fd error");
        //break;
        continue;
      }

      int cipher_txt_len = encrypt(tun_buf, udp_buf, r);
      if(cipher_txt_len < 0)
      {
        printf("Error on encryption[%d]\r\n", cipher_txt_len);
        continue;
      }

      //r = sendto(udp_fd, udp_buf, r, 0, 
      r = sendto(udp_fd, udp_buf, cipher_txt_len, 0, 
        (const struct sockaddr *)&client_addr, 
        client_addrlen);
      if (r < 0) {
        // TODO: ignore some errno
        perror("sendto udp_fd error");
        //break;
       continue;
      }
    }

    if (FD_ISSET(udp_fd, &readset)) {
      r = recvfrom(udp_fd, udp_buf, MTU, 0, (struct sockaddr *)&client_addr, 
        &client_addrlen);
      if (r < 0) {
        // TODO: ignore some errno
        perror("recvfrom udp_fd error");
        //break;
       continue;
      }

      /* Decrypt the text, 
       * returns the actual plain text 
       * with out pad. 
       */
      int plain_txt_length = decrypt(udp_buf, tun_buf, r);
      if(plain_txt_length < 0)
      {
        printf("decrypt failed[%d]\r\n", plain_txt_length);
        continue;
      }
      r = write(tun_fd, tun_buf, plain_txt_length);
      //r = write(tun_fd, tun_buf, r);
      if (r < 0) {
        // TODO: ignore some errno
        perror("write tun_fd error");
        //break;
        continue;
      }
    }
  }

  close(tun_fd);
  close(udp_fd);

  cleanup_route_table();

  return 0;
}
