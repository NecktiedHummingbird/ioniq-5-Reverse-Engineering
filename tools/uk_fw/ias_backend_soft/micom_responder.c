/* micom-responder — minimal /dev/ttyS1 peer for the Gen5W research VM.
 *
 * Framing, measured from 103 real frames emitted by micommanager_userspace:
 *   AA id_hi id_lo L payload[L] CS      (CS = XOR of every preceding byte)
 *   reply: id | 0x8000, same framing
 *
 * Answers every request with a valid frame; boot-info candidates get a 35-byte
 * payload (the launcher's decoder reads bytes 0..34). This is a research stand-in
 * for the MICOM board, not vendor behaviour.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <termios.h>
#include <time.h>

#define BOOTINFO_LEN 35

static unsigned char xor_sum(const unsigned char *p, size_t n)
{
	unsigned char x = 0;
	for (size_t i = 0; i < n; i++)
		x ^= p[i];
	return x;
}

static int read_exact(int fd, unsigned char *buf, size_t n)
{
	size_t got = 0;
	while (got < n) {
		ssize_t r = read(fd, buf + got, n - got);
		if (r <= 0)
			return -1;
		got += (size_t) r;
	}
	return 0;
}

/* Answer the two ids the launcher's static call order makes the boot-info
 * candidates (0x01aa then the first 0x02c3) with a 35-byte payload. */
static int wants_bootinfo(unsigned int id)
{
	return id == 0x01aa || id == 0x02c3;
}

int main(int argc, char **argv)
{
	const char *dev = argc > 1 ? argv[1] : "/dev/ttyS1";
	int fd = open(dev, O_RDWR | O_NOCTTY);
	struct termios tio;
	unsigned int answered = 0, bootinfo = 0;

	if (fd < 0) {
		perror("open");
		return 1;
	}
	if (tcgetattr(fd, &tio) == 0) {
		cfmakeraw(&tio);
		cfsetispeed(&tio, B115200);
		cfsetospeed(&tio, B115200);
		tcsetattr(fd, TCSANOW, &tio);
	}
	fprintf(stderr, "micom-responder: listening on %s\n", dev);

	for (;;) {
		unsigned char hdr[4], pay[256], cs;
		unsigned int id, len, rid;
		unsigned char out[300];
		size_t o = 0;

		if (read_exact(fd, hdr, 1) < 0)
			continue;
		if (hdr[0] != 0xAA)
			continue;
		if (read_exact(fd, hdr + 1, 3) < 0)
			continue;
		id = ((unsigned int) hdr[1] << 8) | hdr[2];
		len = hdr[3];
		if (len > sizeof pay)
			continue;
		if (len && read_exact(fd, pay, len) < 0)
			continue;
		if (read_exact(fd, &cs, 1) < 0)
			continue;

		{
			unsigned char chk[4 + 256];
			memcpy(chk, hdr, 4);
			if (len)
				memcpy(chk + 4, pay, len);
			if (xor_sum(chk, 4 + len) != cs) {
				fprintf(stderr, "micom-responder: bad checksum id=0x%04x\n", id);
				continue;
			}
		}

		rid = id | 0x8000u;
		if (wants_bootinfo(id)) {
			unsigned int n = BOOTINFO_LEN;
			out[o++] = 0xAA;
			out[o++] = (unsigned char) (rid >> 8);
			out[o++] = (unsigned char) (rid & 0xff);
			out[o++] = (unsigned char) n;
			memset(out + o, 0, n);	/* plausible, all-zero boot info */
			o += n;
			bootinfo++;
			fprintf(stderr, "micom-responder: bootinfo reply to 0x%04x (%u bytes)\n",
				id, n);
		} else {
			out[o++] = 0xAA;
			out[o++] = (unsigned char) (rid >> 8);
			out[o++] = (unsigned char) (rid & 0xff);
			out[o++] = 0;
		}
		out[o] = xor_sum(out, o);
		o++;
		if (write(fd, out, o) != (ssize_t) o)
			fprintf(stderr, "micom-responder: short write\n");
		answered++;
		if ((answered % 32) == 0)
			fprintf(stderr, "micom-responder: %u answered, %u bootinfo\n",
				answered, bootinfo);
	}
}
