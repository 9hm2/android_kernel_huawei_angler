/*
 * bcm4358-romdump.c — dump the BCM4358 ROM (0x0..0xA0000) from the device
 * using the bcmdhd "membytes" iovar over SIOCDEVPRIVATE. No kernel rebuild.
 *
 * The on-board firmware's ROM (where the monitor/EAPOL truncation lives) is
 * not in the downloaded fw_bcmdhd.bin. This reads it straight off the chip so
 * it can be disassembled offline.
 *
 * Build on the device / in the chroot:
 *     gcc -O2 -o romdump bcm4358-romdump.c
 * Run as root with wlan0 up:
 *     ./romdump wlan0 rom.bin
 *
 * Mechanism (matches dhd_pcie.c IOV_GVAL(IOV_MEMBYTES)):
 *   - dhd ioctl via SIOCDEVPRIVATE, ifr_data -> dhd_ioctl_t
 *   - cmd = DHD_GET_VAR (2), driver = DHD_IOCTL_MAGIC (0x00444944)
 *   - buf = "membytes\0" + <int address> + <int size>; result returned in buf
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <linux/sockios.h>      /* SIOCDEVPRIVATE */

#define DHD_IOCTL_MAGIC   0x00444944
#define DHD_GET_VAR       2
#define ROM_START         0x00000000u
#define ROM_SIZE          0x000A0000u   /* 640 KiB */
#define CHUNK             0x1000u       /* 4 KiB per read (safe) */

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
	ioc.set    = 0;
	ioc.driver = DHD_IOCTL_MAGIC;
	ifr.ifr_data = (void *)&ioc;
	return ioctl(s, SIOCDEVPRIVATE, &ifr);
}

int main(int argc, char **argv)
{
	const char *ifname = (argc > 1) ? argv[1] : "wlan0";
	const char *outf   = (argc > 2) ? argv[2] : "rom.bin";
	int s, rc;
	unsigned int addr;
	FILE *f;
	/* buffer: "membytes\0" + int addr + int size, reused for the returned data */
	unsigned char buf[64 + CHUNK];

	s = socket(AF_INET, SOCK_DGRAM, 0);
	if (s < 0) { perror("socket"); return 1; }

	f = fopen(outf, "wb");
	if (!f) { perror("fopen"); return 1; }

	printf("Dumping ROM 0x%06x..0x%06x from %s -> %s\n",
	       ROM_START, ROM_START + ROM_SIZE, ifname, outf);

	for (addr = ROM_START; addr < ROM_START + ROM_SIZE; addr += CHUNK) {
		unsigned int size = CHUNK;
		int off = 0;
		if (addr + size > ROM_START + ROM_SIZE)
			size = ROM_START + ROM_SIZE - addr;

		memset(buf, 0, sizeof(buf));
		/* iovar name */
		strcpy((char *)buf, "membytes");
		off = (int)strlen("membytes") + 1;          /* include NUL */
		/* params: address, size (little-endian ints) */
		memcpy(buf + off, &addr, sizeof(int));
		memcpy(buf + off + sizeof(int), &size, sizeof(int));

		rc = dhd_get(s, ifname, buf, off + 2 * sizeof(int) + size);
		if (rc < 0) {
			fprintf(stderr, "\nioctl failed at 0x%06x: %s\n",
			        addr, strerror(errno));
			fprintf(stderr, "(is wlan0 up? are you root? try the iface "
			        "name shown by `ip link`)\n");
			fclose(f); close(s); return 1;
		}
		/* The returned data lands at the start of buf */
		if (fwrite(buf, 1, size, f) != size) {
			perror("fwrite"); fclose(f); close(s); return 1;
		}
		if ((addr & 0xFFFF) == 0) { printf("."); fflush(stdout); }
	}
	printf("\nDone: %u bytes written to %s\n", ROM_SIZE, outf);
	fclose(f);
	close(s);
	return 0;
}
