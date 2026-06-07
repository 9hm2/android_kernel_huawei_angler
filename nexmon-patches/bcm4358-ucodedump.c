/*
 * bcm4358-ucodedump.c — dump the live d11 PSM microcode from the BCM4358 via the
 * bcmdhd "membytes" iovar. The ucode runs (decompressed) in dongle RAM at
 * UCODESTART; it is NOT present in the downloaded fw_bcmdhd.bin (that copy is
 * compressed/zero there), so we read it straight off the chip to disassemble it
 * offline (b43-dasm) and find the RX-length decision that truncates unprotected
 * EAPOL frames in monitor mode.
 *
 * Build in the chroot:   gcc -O2 -o ucodedump bcm4358-ucodedump.c
 * Run as root, wlan0 up: ./ucodedump wlan0 ucode.bin
 *
 * Mechanism identical to bcm4358-romdump.c (membytes GET_VAR over
 * SIOCDEVPRIVATE), only the address range differs.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <linux/sockios.h>

#define DHD_IOCTL_MAGIC   0x00444944
#define DHD_GET_VAR       2
#define UCODE_START       0x0020c9c0u   /* UCODESTART (dongle RAM) */
#define UCODE_SIZE        0x0000e000u   /* >= UCODESIZE 0xd518, rounded up */
#define CHUNK             0x1000u

typedef struct dhd_ioctl {
	unsigned int cmd;
	void *buf;
	unsigned int len;
	unsigned char set;
	unsigned int used;
	unsigned int needed;
	unsigned int driver;
} dhd_ioctl_t;

static int dhd_get(int s, const char *ifname, void *buf, unsigned int len)
{
	struct ifreq ifr;
	dhd_ioctl_t ioc;
	memset(&ifr, 0, sizeof(ifr));
	memset(&ioc, 0, sizeof(ioc));
	strncpy(ifr.ifr_name, ifname, IFNAMSIZ - 1);
	ioc.cmd    = DHD_GET_VAR;
	ioc.buf    = buf;
	ioc.len    = len;
	ioc.driver = DHD_IOCTL_MAGIC;
	ifr.ifr_data = (void *)&ioc;
	return ioctl(s, SIOCDEVPRIVATE, &ifr);
}

int main(int argc, char **argv)
{
	const char *ifname = (argc > 1) ? argv[1] : "wlan0";
	const char *outf   = (argc > 2) ? argv[2] : "ucode.bin";
	int s, rc, off;
	unsigned int addr;
	FILE *f;
	unsigned char buf[64 + CHUNK];

	s = socket(AF_INET, SOCK_DGRAM, 0);
	if (s < 0) { perror("socket"); return 1; }
	f = fopen(outf, "wb");
	if (!f) { perror("fopen"); return 1; }

	printf("Dumping ucode 0x%06x..0x%06x from %s -> %s\n",
	       UCODE_START, UCODE_START + UCODE_SIZE, ifname, outf);

	for (addr = UCODE_START; addr < UCODE_START + UCODE_SIZE; addr += CHUNK) {
		unsigned int size = CHUNK;
		if (addr + size > UCODE_START + UCODE_SIZE)
			size = UCODE_START + UCODE_SIZE - addr;
		memset(buf, 0, sizeof(buf));
		strcpy((char *)buf, "membytes");
		off = (int)strlen("membytes") + 1;
		memcpy(buf + off, &addr, sizeof(int));
		memcpy(buf + off + sizeof(int), &size, sizeof(int));
		rc = dhd_get(s, ifname, buf, off + 2 * sizeof(int) + size);
		if (rc < 0) {
			fprintf(stderr, "\nioctl failed at 0x%06x: %s\n",
			        addr, strerror(errno));
			fclose(f); close(s); return 1;
		}
		if (fwrite(buf, 1, size, f) != size) {
			perror("fwrite"); fclose(f); close(s); return 1;
		}
		if ((addr & 0x3FFF) == 0) { printf("."); fflush(stdout); }
	}
	printf("\nDone: %u bytes -> %s\n", UCODE_SIZE, outf);
	fclose(f); close(s);
	return 0;
}
