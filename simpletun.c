/**************************************************************************
 * simpletun_encrypted.c                                                   *
 *                                                                         *
 * Based on simpletun.c by Davide Brini (2010).                            *
 * Extended with AES-256-CBC encryption + HMAC-SHA256 integrity.           *
 *                                                                         *
 * Compile:                                                                *
 *   gcc simpletun_encrypted.c -o simpletun_encrypted -lssl -lcrypto       *
 *                                                                         *
 * Usage (same as original, but with -k for key file):                     *
 *   ./simpletun_encrypted -i tun0 -s -k keyfile                           *
 *   ./simpletun_encrypted -i tun0 -c 10.0.0.1 -k keyfile                  *
 *                                                                         *
 * Generate a key file:                                                    *
 *   openssl rand -out keyfile 64                                          *
 *   (first 32 bytes = AES key, last 32 bytes = HMAC key)                  *
 *                                                                         *
 * WARNING: This is for LEARNING PURPOSES ONLY. Do not use in production.  *
 **************************************************************************/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <net/if.h>
#include <linux/if_tun.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <arpa/inet.h>
#include <sys/select.h>
#include <sys/time.h>
#include <errno.h>
#include <stdarg.h>

/* -------- NEW: OpenSSL headers for encryption -------- */
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>
#include <openssl/err.h>
/* ----------------------------------------------------- */

/* buffer for reading from tun/tap interface, must be >= 1500 */
#define BUFSIZE 2000
/* encrypted buffer needs room for: IV + ciphertext (padded) + HMAC */
#define CRYPT_BUFSIZE (BUFSIZE + EVP_MAX_BLOCK_LENGTH + EVP_MAX_IV_LENGTH + 32)
#define CLIENT 0
#define SERVER 1
#define PORT 55555

/* -------- NEW: Crypto constants -------- */
#define AES_KEY_LEN  32   /* AES-256 = 32 bytes */
#define HMAC_KEY_LEN 32   /* HMAC-SHA256 key = 32 bytes */
#define IV_LEN       16   /* AES-CBC IV = 16 bytes */
#define HMAC_LEN     32   /* SHA256 digest = 32 bytes */
#define KEY_FILE_LEN (AES_KEY_LEN + HMAC_KEY_LEN)  /* 64 bytes total */
/* --------------------------------------- */

int debug;
char *progname;

/* -------- NEW: Key material (loaded from file) -------- */
unsigned char aes_key[AES_KEY_LEN];
unsigned char hmac_key[HMAC_KEY_LEN];
/* ------------------------------------------------------ */

/**************************************************************************
 * tun_alloc: allocates or reconnects to a tun/tap device.                *
 *            (UNCHANGED from original)                                    *
 **************************************************************************/
int tun_alloc(char *dev, int flags) {

  struct ifreq ifr;
  int fd, err;
  char *clonedev = "/dev/net/tun";

  if( (fd = open(clonedev, O_RDWR)) < 0 ) {
    perror("Opening /dev/net/tun");
    return fd;
  }

  memset(&ifr, 0, sizeof(ifr));
  ifr.ifr_flags = flags;

  if (*dev) {
    strncpy(ifr.ifr_name, dev, IFNAMSIZ);
  }

  if( (err = ioctl(fd, TUNSETIFF, (void *)&ifr)) < 0 ) {
    perror("ioctl(TUNSETIFF)");
    close(fd);
    return err;
  }

  strcpy(dev, ifr.ifr_name);
  return fd;
}

/**************************************************************************
 * cread / cwrite / read_n: I/O helpers (UNCHANGED from original)         *
 **************************************************************************/
int cread(int fd, char *buf, int n) {
  int nread;
  if((nread = read(fd, buf, n)) < 0) {
    perror("Reading data");
    exit(1);
  }
  return nread;
}

int cwrite(int fd, char *buf, int n) {
  int nwrite;
  if((nwrite = write(fd, buf, n)) < 0) {
    perror("Writing data");
    exit(1);
  }
  return nwrite;
}

int read_n(int fd, char *buf, int n) {
  int nread, left = n;
  while(left > 0) {
    if ((nread = cread(fd, buf, left)) == 0) {
      return 0;
    } else {
      left -= nread;
      buf += nread;
    }
  }
  return n;
}

/**************************************************************************
 * do_debug / my_err: output helpers (UNCHANGED from original)            *
 **************************************************************************/
void do_debug(char *msg, ...) {
  va_list argp;
  if(debug) {
    va_start(argp, msg);
    vfprintf(stderr, msg, argp);
    va_end(argp);
  }
}

void my_err(char *msg, ...) {
  va_list argp;
  va_start(argp, msg);
  vfprintf(stderr, msg, argp);
  va_end(argp);
}

/**************************************************************************
 * NEW: load_key_file - reads 64-byte key file                            *
 *      First 32 bytes -> AES-256 key                                     *
 *      Last  32 bytes -> HMAC-SHA256 key                                  *
 **************************************************************************/
void load_key_file(const char *keyfile) {
  FILE *f = fopen(keyfile, "rb");
  unsigned char keybuf[KEY_FILE_LEN];

  if (!f) {
    perror("Opening key file");
    exit(1);
  }

  if (fread(keybuf, 1, KEY_FILE_LEN, f) != KEY_FILE_LEN) {
    my_err("Key file must be exactly %d bytes\n", KEY_FILE_LEN);
    fclose(f);
    exit(1);
  }
  fclose(f);

  /* Split the 64 bytes into two 32-byte keys */
  memcpy(aes_key,  keybuf,              AES_KEY_LEN);
  memcpy(hmac_key, keybuf + AES_KEY_LEN, HMAC_KEY_LEN);

  /* Wipe the temporary buffer */
  OPENSSL_cleanse(keybuf, KEY_FILE_LEN);

  do_debug("CRYPTO: Loaded %d-byte key file (%d AES + %d HMAC)\n",
           KEY_FILE_LEN, AES_KEY_LEN, HMAC_KEY_LEN);
}

/**************************************************************************
 * NEW: encrypt_packet                                                     *
 *                                                                         *
 *   plaintext  -->  [ IV (16 bytes) | ciphertext | HMAC (32 bytes) ]      *
 *                                                                         *
 *   Returns total length of the output, or -1 on error.                   *
 **************************************************************************/
int encrypt_packet(unsigned char *plaintext, int plaintext_len,
                   unsigned char *output) {

  unsigned char iv[IV_LEN];
  int ciphertext_len = 0, len = 0;
  unsigned int hmac_len = 0;
  unsigned char *ciphertext_start;
  int total_len;

  /* 1. Generate a random IV for this packet */
  if (RAND_bytes(iv, IV_LEN) != 1) {
    my_err("CRYPTO: RAND_bytes failed\n");
    return -1;
  }

  /* 2. Copy IV to the front of output */
  memcpy(output, iv, IV_LEN);
  ciphertext_start = output + IV_LEN;

  /* 3. Encrypt with AES-256-CBC */
  EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
  if (!ctx) {
    my_err("CRYPTO: EVP_CIPHER_CTX_new failed\n");
    return -1;
  }

  if (EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, aes_key, iv) != 1) {
    my_err("CRYPTO: EncryptInit failed\n");
    EVP_CIPHER_CTX_free(ctx);
    return -1;
  }

  if (EVP_EncryptUpdate(ctx, ciphertext_start, &len,
                        plaintext, plaintext_len) != 1) {
    my_err("CRYPTO: EncryptUpdate failed\n");
    EVP_CIPHER_CTX_free(ctx);
    return -1;
  }
  ciphertext_len = len;

  if (EVP_EncryptFinal_ex(ctx, ciphertext_start + len, &len) != 1) {
    my_err("CRYPTO: EncryptFinal failed\n");
    EVP_CIPHER_CTX_free(ctx);
    return -1;
  }
  ciphertext_len += len;
  EVP_CIPHER_CTX_free(ctx);

  /* 4. Compute HMAC-SHA256 over (IV + ciphertext) -- encrypt-then-MAC */
  total_len = IV_LEN + ciphertext_len;
  if (HMAC(EVP_sha256(), hmac_key, HMAC_KEY_LEN,
           output, total_len,
           output + total_len, &hmac_len) == NULL) {
    my_err("CRYPTO: HMAC computation failed\n");
    return -1;
  }

  total_len += HMAC_LEN;

  do_debug("CRYPTO: Encrypted %d -> %d bytes (IV:%d + cipher:%d + HMAC:%d)\n",
           plaintext_len, total_len, IV_LEN, ciphertext_len, HMAC_LEN);

  return total_len;
}

/**************************************************************************
 * NEW: decrypt_packet                                                     *
 *                                                                         *
 *   [ IV (16 bytes) | ciphertext | HMAC (32 bytes) ]  -->  plaintext      *
 *                                                                         *
 *   Returns plaintext length, or -1 on error (including HMAC mismatch).   *
 **************************************************************************/
int decrypt_packet(unsigned char *input, int input_len,
                   unsigned char *plaintext) {

  unsigned char iv[IV_LEN];
  unsigned char received_hmac[HMAC_LEN];
  unsigned char computed_hmac[HMAC_LEN];
  unsigned int hmac_len = 0;
  int ciphertext_len, plaintext_len = 0, len = 0;

  /* Sanity check: minimum size = IV + 1 block + HMAC */
  if (input_len < IV_LEN + 16 + HMAC_LEN) {
    my_err("CRYPTO: Packet too short to decrypt (%d bytes)\n", input_len);
    return -1;
  }

  /* 1. Extract IV from front */
  memcpy(iv, input, IV_LEN);

  /* 2. Extract HMAC from end */
  memcpy(received_hmac, input + input_len - HMAC_LEN, HMAC_LEN);

  /* 3. Verify HMAC over (IV + ciphertext) */
  ciphertext_len = input_len - IV_LEN - HMAC_LEN;
  if (HMAC(EVP_sha256(), hmac_key, HMAC_KEY_LEN,
           input, IV_LEN + ciphertext_len,
           computed_hmac, &hmac_len) == NULL) {
    my_err("CRYPTO: HMAC computation failed\n");
    return -1;
  }

  if (CRYPTO_memcmp(received_hmac, computed_hmac, HMAC_LEN) != 0) {
    my_err("CRYPTO: HMAC verification FAILED - packet tampered or wrong key!\n");
    return -1;
  }

  do_debug("CRYPTO: HMAC verification OK\n");

  /* 4. Decrypt with AES-256-CBC */
  EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
  if (!ctx) {
    my_err("CRYPTO: EVP_CIPHER_CTX_new failed\n");
    return -1;
  }

  if (EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, aes_key, iv) != 1) {
    my_err("CRYPTO: DecryptInit failed\n");
    EVP_CIPHER_CTX_free(ctx);
    return -1;
  }

  if (EVP_DecryptUpdate(ctx, plaintext, &len,
                        input + IV_LEN, ciphertext_len) != 1) {
    my_err("CRYPTO: DecryptUpdate failed\n");
    EVP_CIPHER_CTX_free(ctx);
    return -1;
  }
  plaintext_len = len;

  if (EVP_DecryptFinal_ex(ctx, plaintext + len, &len) != 1) {
    my_err("CRYPTO: DecryptFinal failed (bad padding / corrupted)\n");
    EVP_CIPHER_CTX_free(ctx);
    return -1;
  }
  plaintext_len += len;
  EVP_CIPHER_CTX_free(ctx);

  do_debug("CRYPTO: Decrypted %d -> %d bytes\n", input_len, plaintext_len);

  return plaintext_len;
}

/**************************************************************************
 * usage: prints usage and exits. (UPDATED: added -k flag)                *
 **************************************************************************/
void usage(void) {
  fprintf(stderr, "Usage:\n");
  fprintf(stderr, "%s -i <ifacename> [-s|-c <serverIP>] [-p <port>] [-u|-a] [-d] -k <keyfile>\n", progname);
  fprintf(stderr, "%s -h\n", progname);
  fprintf(stderr, "\n");
  fprintf(stderr, "-i <ifacename>: Name of interface to use (mandatory)\n");
  fprintf(stderr, "-s|-c <serverIP>: run in server mode (-s), or specify server address (-c <serverIP>) (mandatory)\n");
  fprintf(stderr, "-p <port>: port to listen on (if run in server mode) or to connect to (in client mode), default 55555\n");
  fprintf(stderr, "-u|-a: use TUN (-u, default) or TAP (-a)\n");
  fprintf(stderr, "-k <keyfile>: path to 64-byte key file (mandatory). Generate with: openssl rand -out keyfile 64\n");
  fprintf(stderr, "-d: outputs debug information while running\n");
  fprintf(stderr, "-h: prints this help text\n");
  exit(1);
}

int main(int argc, char *argv[]) {

  int tap_fd, option;
  int flags = IFF_TUN;
  char if_name[IFNAMSIZ] = "";
  int maxfd;
  uint16_t nread, nwrite, plength;
  char buffer[BUFSIZE];
  struct sockaddr_in local, remote;
  char remote_ip[16] = "";
  unsigned short int port = PORT;
  int sock_fd, net_fd, optval = 1;
  socklen_t remotelen;
  int cliserv = -1;
  unsigned long int tap2net = 0, net2tap = 0;

  /* -------- NEW: encryption buffers and key file path -------- */
  unsigned char crypt_buf[CRYPT_BUFSIZE];
  unsigned char decrypt_buf[BUFSIZE];
  char keyfile[256] = "";
  /* ----------------------------------------------------------- */

  progname = argv[0];

  /* Check command line options -- UPDATED: added 'k:' */
  while((option = getopt(argc, argv, "i:sc:p:uahdk:")) > 0) {
    switch(option) {
      case 'd':
        debug = 1;
        break;
      case 'h':
        usage();
        break;
      case 'i':
        strncpy(if_name, optarg, IFNAMSIZ-1);
        break;
      case 's':
        cliserv = SERVER;
        break;
      case 'c':
        cliserv = CLIENT;
        strncpy(remote_ip, optarg, 15);
        break;
      case 'p':
        port = atoi(optarg);
        break;
      case 'u':
        flags = IFF_TUN;
        break;
      case 'a':
        flags = IFF_TAP;
        break;
      /* -------- NEW: key file option -------- */
      case 'k':
        strncpy(keyfile, optarg, sizeof(keyfile) - 1);
        break;
      /* -------------------------------------- */
      default:
        my_err("Unknown option %c\n", option);
        usage();
    }
  }

  argv += optind;
  argc -= optind;

  if(argc > 0) {
    my_err("Too many options!\n");
    usage();
  }

  if(*if_name == '\0') {
    my_err("Must specify interface name!\n");
    usage();
  } else if(cliserv < 0) {
    my_err("Must specify client or server mode!\n");
    usage();
  } else if((cliserv == CLIENT) && (*remote_ip == '\0')) {
    my_err("Must specify server address!\n");
    usage();
  }

  /* -------- NEW: key file is mandatory -------- */
  if(*keyfile == '\0') {
    my_err("Must specify key file with -k!\n");
    usage();
  }

  /* Load encryption keys from file */
  load_key_file(keyfile);
  /* -------------------------------------------- */

  /* initialize tun/tap interface (UNCHANGED) */
  if ( (tap_fd = tun_alloc(if_name, flags | IFF_NO_PI)) < 0 ) {
    my_err("Error connecting to tun/tap interface %s!\n", if_name);
    exit(1);
  }

  do_debug("Successfully connected to interface %s\n", if_name);

  if ( (sock_fd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
    perror("socket()");
    exit(1);
  }

  /* Client/Server connection setup (UNCHANGED) */
  if(cliserv == CLIENT) {
    memset(&remote, 0, sizeof(remote));
    remote.sin_family = AF_INET;
    remote.sin_addr.s_addr = inet_addr(remote_ip);
    remote.sin_port = htons(port);

    if (connect(sock_fd, (struct sockaddr*) &remote, sizeof(remote)) < 0) {
      perror("connect()");
      exit(1);
    }

    net_fd = sock_fd;
    do_debug("CLIENT: Connected to server %s\n", inet_ntoa(remote.sin_addr));

  } else {
    if(setsockopt(sock_fd, SOL_SOCKET, SO_REUSEADDR, (char *)&optval, sizeof(optval)) < 0) {
      perror("setsockopt()");
      exit(1);
    }

    memset(&local, 0, sizeof(local));
    local.sin_family = AF_INET;
    local.sin_addr.s_addr = htonl(INADDR_ANY);
    local.sin_port = htons(port);
    if (bind(sock_fd, (struct sockaddr*) &local, sizeof(local)) < 0) {
      perror("bind()");
      exit(1);
    }

    if (listen(sock_fd, 5) < 0) {
      perror("listen()");
      exit(1);
    }

    remotelen = sizeof(remote);
    memset(&remote, 0, remotelen);
    if ((net_fd = accept(sock_fd, (struct sockaddr*)&remote, &remotelen)) < 0) {
      perror("accept()");
      exit(1);
    }

    do_debug("SERVER: Client connected from %s\n", inet_ntoa(remote.sin_addr));
  }

  /* Main loop with select() */
  maxfd = (tap_fd > net_fd) ? tap_fd : net_fd;

  while(1) {
    int ret;
    fd_set rd_set;

    FD_ZERO(&rd_set);
    FD_SET(tap_fd, &rd_set);
    FD_SET(net_fd, &rd_set);

    ret = select(maxfd + 1, &rd_set, NULL, NULL, NULL);

    if (ret < 0 && errno == EINTR) {
      continue;
    }

    if (ret < 0) {
      perror("select()");
      exit(1);
    }

    if(FD_ISSET(tap_fd, &rd_set)) {
      /*
       * ============================================================
       * TAP -> NET: Read plaintext from TUN, ENCRYPT, send to network
       * ============================================================
       * ORIGINAL: just sent buffer directly
       * NOW:      encrypt buffer, then send encrypted data
       */

      nread = cread(tap_fd, buffer, BUFSIZE);

      tap2net++;
      do_debug("TAP2NET %lu: Read %d bytes from the tap interface\n", tap2net, nread);

      /* NEW: Encrypt the packet */
      int encrypted_len = encrypt_packet((unsigned char *)buffer, nread, crypt_buf);
      if (encrypted_len < 0) {
        my_err("Encryption failed, dropping packet\n");
        continue;
      }

      /* Send length + encrypted packet (same framing as original) */
      plength = htons(encrypted_len);
      nwrite = cwrite(net_fd, (char *)&plength, sizeof(plength));
      nwrite = cwrite(net_fd, (char *)crypt_buf, encrypted_len);

      do_debug("TAP2NET %lu: Written %d encrypted bytes to the network\n", tap2net, encrypted_len);
    }

    if(FD_ISSET(net_fd, &rd_set)) {
      /*
       * ============================================================
       * NET -> TAP: Read encrypted data from network, DECRYPT, write to TUN
       * ============================================================
       * ORIGINAL: just wrote buffer directly to tun
       * NOW:      decrypt first, verify HMAC, then write plaintext to tun
       */

      /* Read length (same framing as original) */
      nread = read_n(net_fd, (char *)&plength, sizeof(plength));
      if(nread == 0) {
        break;
      }

      net2tap++;

      /* Read encrypted packet */
      int enc_len = ntohs(plength);
      nread = read_n(net_fd, (char *)crypt_buf, enc_len);
      do_debug("NET2TAP %lu: Read %d encrypted bytes from the network\n", net2tap, nread);

      /* NEW: Decrypt the packet */
      int decrypted_len = decrypt_packet(crypt_buf, enc_len, decrypt_buf);
      if (decrypted_len < 0) {
        my_err("Decryption failed, dropping packet\n");
        continue;  /* drop tampered/bad packets instead of crashing */
      }

      /* Write decrypted plaintext to tun/tap */
      nwrite = cwrite(tap_fd, (char *)decrypt_buf, decrypted_len);
      do_debug("NET2TAP %lu: Written %d decrypted bytes to the tap interface\n", net2tap, decrypted_len);
    }
  }

  return(0);
}
