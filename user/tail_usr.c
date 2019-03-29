/* Copyright(c) 2017 Jesper Dangaard Brouer, Red Hat, Inc.
 */
static const char *__doc__= " Test of bpf_tail_call from XDP program\n\n"
	"Notice: This is a non-functional test program\n"
	"        for exercising different bpf code paths in the kernel\n";

#include <fcntl.h>
#include <libelf.h>
#include <net/if.h>
#include <unistd.h>
#include <stdbool.h>
#include <linux/if_link.h>

#include "bpf/libbpf.h"
#include "bpf_load.h"
#include "bpf_util.h"

static int ifindex = -1;
static char ifname_buf[IF_NAMESIZE];
static char *ifname = NULL;
static __u32 xdp_flags = 0;
static bool debug = false;

/* Exit return codes */
#define EXIT_OK                 0
#define EXIT_FAIL               1
#define EXIT_FAIL_OPTION        2
#define EXIT_FAIL_XDP           3
#define EXIT_FAIL_MAP		20

static void int_exit(int sig)
{
	printf("Interrupted: Removing XDP program on ifindex:%d device:%s\n",
		ifindex, ifname);
	if (ifindex > -1)
		bpf_set_link_xdp_fd(ifindex, -1, xdp_flags);
	exit(EXIT_OK);
}

/* Helper for adding prog to prog_map */
void jmp_table_add_prog(int map_jmp_table_idx, int idx, int prog_idx)
{

	printf("\n checking map_fd");
	int i;
	for(i=0;i<10;i++)
		printf("\n %d -> %d", i, map_fd[i]);
	int jmp_table_fd = map_fd[map_jmp_table_idx];
	int prog = prog_fd[prog_idx];
	int err;

	printf("\nINFO: jm_table_fd = %d prog_fd = %d", jmp_table_fd, prog);

	if (prog == 0) {
		printf("ERR: Invalid zero-FD prog_fd[%d]=%d,"
		       " did bpf_load.c fail loading program?!?\n",
		       prog_idx, prog);
		exit(EXIT_FAIL_MAP);
	}
        printf("\n putting to %d key = %d val = %d", jmp_table_fd, idx, prog);
	err = bpf_map_update_elem(jmp_table_fd, &idx, &prog, 0);
	if (err) {
		printf("ERR(%d/%d): Fail add prog_fd[%d]=%d to jmp_table%d i:%d\n",
		       err, errno, prog_idx, prog, map_jmp_table_idx+1, idx);
		exit(EXIT_FAIL_MAP);
	}
	int ans, key=78, value = 99;
	ans = bpf_map_lookup_elem(jmp_table_fd, &key, &value);
	printf("\n lookup key = %d val = %d and = %d", key, value, ans);
}

int main(int argc, char **argv)
{
	char filename[256];
	char inner[256];
	int longindex = 0;
	int opt, i;

	/* Corresponding map_fd[index] for jump tables aka tail calls */
	int jmp_table1 = 0;
	int prog_xdp_1 = 1;
	int bpf_code;

	snprintf(filename, sizeof(filename), "/users/pinkasel/tail/kern/tail_kern.o");
	snprintf(inner, sizeof(inner), "ens1f1");
	printf("\n filename is %s", filename);
	printf("\n interface is %s", argv[1]);
			ifindex = if_nametoindex(inner);
			if (ifindex == 0) {
				printf(
					"ERR: --dev name unknown err(%d):%s\n",
					errno, strerror(errno));
				return EXIT_FAIL_OPTION;
			}
	printf("\n ifindex is %d", ifindex);
	
	//debugging
	/*
	int fd;
	fd = open(filename, O_RDONLY, 0);
	printf("\n opening file %d", fd);

	Elf *elf;
	elf = elf_begin(fd, ELF_C_READ, NULL);
	if(!elf)
	{
		printf("\n problem in elf reading");
		return 1;
	}
*/


	/* Required options */
	if (ifindex == -1) {
		fprintf(stderr, "ERR: required option --dev missing");
		//usage(argv);
		return EXIT_FAIL_OPTION;
	}

	if (bpf_code = load_bpf_file(filename)) {
		printf("->ERR in load_bpf_file(): %s - %d checking prog_fd %d", bpf_log_buf, bpf_code, prog_fd[0]);
		return EXIT_FAIL;
	}
	if (!prog_fd[0]) {
		fprintf(stderr, "ERR: load_bpf_file: %s\n", strerror(errno));
		return EXIT_FAIL;
	}

	printf("INFO: bpf ELF file(%s) contained %d program(s)\n prog_fd is %d and %d",
	       filename, prog_cnt, prog_fd[0], prog_fd[1]);


	/* For XDP bpf_load.c seems not to implement automatic
	 * populating the prog_array.
	 *
	 * Do this manually.  The prog_array_fd does contain the FD
	 * but it is not default exported.  Thus, instead rely on the
	 * order of SEC map and prog definitions.
	 */
	if (1) {
		jmp_table_add_prog(jmp_table1, 78, prog_xdp_1);
		//jmp_table_add_prog(jmp_table1, 5, prog_xdp_5);
	}
	/* Notice populating jmp_table is done _before_ attaching the
	 * main XDP program to a specific device.
	 *
	 * DEVEL: As I'm working on locking down prog_array features
	 * changes after a XDP program have been associated with a
	 * device.
	 */
	//if (1) { /* Notice jmp_table2 (number 2) */
	//	for (i = 40; i < 50; i++)
	//		jmp_table_add_prog(jmp_table2, i, prog_xdp_unrelated);
	//}

	//if (debug) {
	//	printf("map_fd[] jmp_table file descriptor mapping:\n");
	//	for (i = 0; i < 3; i++)
	//		printf(" jmp_table map_fd[%d]=fd:%d\n", i, map_fd[i]);
	//}

	/* Attach XDP program */
	if (bpf_set_link_xdp_fd(ifindex, prog_fd[0], xdp_flags) < 0) {
		fprintf(stderr, "ERR: link set xdp fd failed\n");
		return EXIT_FAIL_XDP;
	}

	/* Remove XDP program when program is interrupted or killed */

	/* Notice, after XDP prog have been attached, the features
	 * have been "locked down" (in RFC patch).  Adding something
	 * to a jmp_table will result in runtime validation.
	 */


	printf("Goodbye\n");
}
