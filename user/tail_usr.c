#include <net/if.h>
#include <unistd.h>
#include <stdbool.h>
#include <linux/if_link.h>

#include "bpf/libbpf.h"
#include "bpf_load.h"
#include "bpf_util.h"

#include<assert.h>


void jmp_table_add_prog(int map_fd_id, int key, int prog_fd_id)
{
	int jmp_fd = map_fd[map_fd_id];
	int tail_fd = prog_fd[prog_fd_id];

	if(tail_fd == 0)
	{
		printf("\n invalid program - not loaded ?");
		return;
	}

	int err;

	err = bpf_map_update_elem(jmp_fd, &key, &tail_fd, 0);
	if(err)
	{
		printf("\n could not update element");
		return;
	}

	struct bpf_prog_info info = {};
	uint32_t info_len = sizeof(info);
	int value;

	err = bpf_obj_get_info_by_fd(tail_fd, &info, &info_len);
	assert(!err);
	err = bpf_map_lookup_elem(jmp_fd, &key, &value);
	assert(!err);
	assert(value == info.id);

	return;
}

int main(int argc, char **argv)
{
	char filename[256];
	char iface[256];

	snprintf(filename, sizeof(filename), "/users/pinkasel/start/kern/tail_kern.o");
	snprintf(iface, sizeof(iface), "ens1f1");

	int ifindex;
	ifindex = if_nametoindex(iface);
	if(ifindex == 0)
	{
		printf("\n interface name unknown");
		return 1;
	}

	int bpf_code;
	if(bpf_code = load_bpf_file(filename))
	{
		printf("\n error in bpf load");
		return 1;
	}

	if(!prog_fd[0])
	{
		printf("\n error after bpf load");
		return 1;
	}


	jmp_table_add_prog(0, 78, 1);

	if(bpf_set_link_xdp_fd(ifindex, prog_fd[0], 0) < 0)
	{
		printf("\n link set failed");
		return 1;
	}

        sleep(50);
        printf("\nprogram loaded to interface");
	return 0;
}
