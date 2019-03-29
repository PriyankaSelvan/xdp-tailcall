/* Copyright(c) 2017 Jesper Dangaard Brouer, Red Hat, Inc.
 */
static const char *__doc__= " Test of bpf_tail_call from XDP program\n\n"
	"Notice: This is a non-functional test program\n"
	"        for exercising different bpf code paths in the kernel\n";

#include <signal.h>
#include <net/if.h>
#include <unistd.h>
#include <stdbool.h>
#include <linux/if_link.h>

#include "bpf/libbpf.h"
#include "bpf_load.h"
#include "bpf_util.h"


void jmp_table_add_prog(int jmp_table_fd, int idx, int prog)
{
	int err;
	int value;


	err = bpf_map_update_elem(jmp_table_fd, &idx, &prog, 0);
	if (err) {
		printf("ERR(%d/%d): Fail add prog_fd =%d to jmp_table %d i:%d\n",
		       err, errno, prog, jmp_table_fd, idx);
	}
	if(bpf_map_lookup_elem(jmp_table_fd, &idx, &value)){
			printf("\nlookup failed");
			}
			else
			{
                          printf("\n looked up in %d with key %d got %d",jmp_table_fd, idx,  value);
			}
}

int main(int argc, char **argv)
{
	int map_f;
	int prog_main, prog_tail1;
	struct bpf_object *main, *tail1;
        
	struct bpf_prog_load_attr prog_attr_main = {
		.prog_type = BPF_PROG_TYPE_XDP,
		.file = "../kern/tail_kern.o",
	};
	
	struct bpf_prog_load_attr prog_attr_tail1 = {
		.prog_type = BPF_PROG_TYPE_XDP,
		.file = "../kern/tail1.o",
	};
        
	if(bpf_prog_load_xattr(&prog_attr_main, &main, &prog_main))
	{
		printf("\nCould not load main program");
		return 1;
	}
	printf("\n main prof id %d", prog_main);
	
	if(bpf_prog_load_xattr(&prog_attr_tail1, &tail1, &prog_tail1))
	{
		printf("\nCould not load tail1 program");
		return 1;
	}
	printf("\n tail1 prog id %d", prog_tail1);
       
	struct bpf_map *map = bpf_object__find_map_by_name(main, "jmp_table1");
	if(!map){
		printf("\n finding map failed");
		return 1;
	}
	
	map_f = bpf_map__fd(map);
        
	jmp_table_add_prog(map_f, 1, prog_tail1);
        
	static __u32 xdp_flags = XDP_FLAGS_DRV_MODE;
	int ifindex = if_nametoindex(argv[1]);

	if(bpf_set_link_xdp_fd(ifindex, prog_main, xdp_flags) < 0) {
                printf("\nlink set xdp fd failed");
                return 1;
        }
	/*
	struct bpf_map *map = bpf_object__find_map_by_name(main, "jmp_table1");
        if(!map){
                printf("\n finding map failed");
                return 1;
        }

	map_f = bpf_map__fd(map);

        jmp_table_add_prog(map_f, 1, prog_tail1);
	*/
	return 0;
}
