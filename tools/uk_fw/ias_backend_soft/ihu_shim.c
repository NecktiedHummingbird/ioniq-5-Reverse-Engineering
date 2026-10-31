/* ihu_shim — research stand-in for the component that publishes the vehicle
 * interface shared memory. Qt names each segment qipc_sharedmemory_<key><sha1(key)>
 * (derived empirically from two vendor-created segments), and looks it up with
 * ftok()/shmget(). This creates those segments, zero-filled, so the UI's
 * QSharedMemory::attach() succeeds instead of failing with "key file doesn't exist". */
#define _GNU_SOURCE
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/ipc.h>
#include <sys/shm.h>

#define SEG_SIZE (64 * 1024)
#define LOG "/dev/ttyS0"

static const char *names[] = {
	"qipc_sharedmemory_Ihuafa1c800e2cb4324051d4a6c30bf03eefaa4c234",
	"qipc_sharedmemory__Ihu020b5f4fae836a0e9a31f05c6d749665ac17c380",
	"qipc_sharedmemory_Inform9249a9ea618eadddc5f50ec3bcef3020f3363eaf",
	"qipc_sharedmemory__Informa0189e498cc73ecec9ea792ca1a0c0cc8736a632",
	"qipc_sharedmemory_Information0eb5ed506e4923c28d7f4a8aa69efe99b3ad75d1",
	"qipc_sharedmemory__Informationb1579cb6c837abf773557ea8d39ba66de574dd34",
	"qipc_sharedmemory__Canda432d766b5e1c87c5292122b5df6771e198c0c7",
	"qipc_sharedmemory_Can88e288f3e3ca8d1137556d908dcb9f355209464b",
	"qipc_sharedmemory_PhevInterfacec18480c98979dd199078c72d2c4bf6aeb6caccd4",
	"qipc_sharedmemory__PhevInterface05f27930f3fd33faa4a5680c7a26723610fd5657",
	"qipc_sharedmemory__CryptoService8c82990da17a066a0c6296cda841f64c25b82604",
	"qipc_sharedmemory_CryptoService8c5d64483b27fd0cb238e691513c1c008718633e",
};

int main(void)
{
	int log = open(LOG, O_WRONLY);
	int i, made = 0;

	for (i = 0; i < (int)(sizeof names / sizeof names[0]); i++) {
		char path[256];
		int fd;
		key_t k;
		int id;

		snprintf(path, sizeof path, "/tmp/%s", names[i]);
		fd = open(path, O_CREAT | O_RDWR, 0666);
		if (fd < 0) {
			dprintf(log, "ihu-shim: cannot create %s: %s\n", path, strerror(errno));
			continue;
		}
		close(fd);
		k = ftok(path, 'Q');
		if (k == -1) {
			dprintf(log, "ihu-shim: ftok failed for %s\n", path);
			continue;
		}
		id = shmget(k, SEG_SIZE, IPC_CREAT | 0666);
		if (id < 0) {
			dprintf(log, "ihu-shim: shmget failed for %s: %s\n", path, strerror(errno));
			continue;
		}
		{
			void *p = shmat(id, NULL, 0);
			if (p != (void *)-1) {
				memset(p, 0, SEG_SIZE);
				shmdt(p);
			}
		}
		made++;
		dprintf(log, "ihu-shim: created %s (id=%d)\n", names[i], id);
	}
	dprintf(log, "ihu-shim: %d segment(s) created\n", made);
	return made ? 0 : 1;
}
