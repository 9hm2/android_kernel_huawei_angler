// ucmread.c -- read BCM4358 d11 UCM (microcode memory) bytes via the nexmon
// UCM read-back ioctl (cmd 0x600). Proves whether a byte-patched ucode.bin
// actually reached the live d11 core.  UCM[off] == ucode.bin[off] (no swizzle).
//
// Build (Kali chroot or any Linux with the right libc for the shell you run in):
//     gcc -O2 -o ucmread ucmread.c
// Run as root, wlan0 up:
//     ./ucmread wlan0 0x000 8     # anchor; MUST read 4e1000036 0bc0100 -> 4e 10 00 03 60 bc 01 00
//     ./ucmread wlan0 0xE40 8     # spr223 site: 23 12 00 03 61 b0 00 00 = patch live;
//                                 #              23 92 00 47 48 e8 00 00 = patch NOT loaded
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <errno.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <netinet/in.h>

#define WLC_IOCTL_MAGIC   0x14e46c77u
#define CMD_READ_UCM      0x600

struct nex_ioctl {
    unsigned int cmd;
    void        *buf;
    unsigned int len;
    bool         set;
    unsigned int used;
    unsigned int needed;
    unsigned int driver;
};

int main(int argc, char **argv)
{
    if (argc != 4 && argc != 5) {
        fprintf(stderr, "usage: %s <ifname> <hex_offset> <len(1..256)> [cmd=0x600]\n"
                        "  cmd 0x600 = read live d11 UCM at offset (UCM[x]==ucode.bin[x])\n"
                        "  cmd 0x601 = read EAPOL RX diag bucket A; 0x602 = full-DATA diag bucket B\n"
                        "      bucket layout: [0..1]count [2..3]p->len [4..35]rxhdr[0..31] [36..255]frame\n"
                        "  cmd 0x603 = read d11 SHM: <hex_offset>=SHM word*2 byte addr, <len>=#words\n"
                        "      e.g. read 8 SHM words from word 0x880:  %s wlan0 0x1100 8 0x603\n",
                argv[0], argv[0]);
        return 2;
    }
    const char  *ifname = argv[1];
    unsigned int offset = (unsigned int) strtoul(argv[2], NULL, 0);
    unsigned int length = (unsigned int) strtoul(argv[3], NULL, 0);
    unsigned int cmd    = (argc == 5) ? (unsigned int) strtoul(argv[4], NULL, 0) : CMD_READ_UCM;
    if (length == 0 || length > 256) { fprintf(stderr, "len must be 1..256\n"); return 2; }

    unsigned int buflen = length < 8 ? 8 : length;
    unsigned char *buf = calloc(1, buflen);
    if (!buf) { perror("calloc"); return 1; }
    memcpy(buf + 0, &offset, 4);
    memcpy(buf + 4, &length, 4);

    struct nex_ioctl ioc;
    memset(&ioc, 0, sizeof(ioc));
    ioc.cmd    = cmd;
    ioc.buf    = buf;
    ioc.len    = buflen;
    ioc.set    = false;
    ioc.driver = WLC_IOCTL_MAGIC;

    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    snprintf(ifr.ifr_name, sizeof(ifr.ifr_name), "%s", ifname);
    ifr.ifr_data = (void *) &ioc;

    int s = socket(AF_INET, SOCK_DGRAM, 0);
    if (s < 0) { perror("socket"); free(buf); return 1; }
    int ret = ioctl(s, SIOCDEVPRIVATE, &ifr);
    if (ret < 0 && errno != EAGAIN) {
        fprintf(stderr, "ioctl SIOCDEVPRIVATE failed: ret=%d errno=%d (%s)\n",
                ret, errno, strerror(errno));
        close(s); free(buf); return 1;
    }
    close(s);

    printf("UCM[0x%X..0x%X]: ", offset, offset + length - 1);
    for (unsigned int i = 0; i < length; i++) printf("%02x", buf[i]);
    printf("\n");
    free(buf);
    return 0;
}
