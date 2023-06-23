// go:build ignore

#include "vmlinux.h"
#include <bpf_endian.h>
#include <bpf_helpers.h>
#include <bpf_tracing.h>
#include <bpf_core_read.h>

#define LOW_32_BITS(x) x & 0xFFFFFFFF
#define HIGH_32_BITS(x) x >> 32

char __license[] SEC("license") = "Dual MIT/GPL";

/*
name: cgroup_attach_task
ID: 418
format:
	field:unsigned short common_type;	offset:0;	size:2;	signed:0;
	field:unsigned char common_flags;	offset:2;	size:1;	signed:0;
	field:unsigned char common_preempt_count;	offset:3;	size:1;	signed:0;
	field:int common_pid;	offset:4;	size:4;	signed:1;

	field:int dst_root;	offset:8;	size:4;	signed:1;
	field:int dst_level;	offset:12;	size:4;	signed:1;
	field:u64 dst_id;	offset:16;	size:8;	signed:0;
	field:int pid;	offset:24;	size:4;	signed:1;
	field:__data_loc char[] dst_path;	offset:28;	size:4;	signed:1;
	field:__data_loc char[] comm;	offset:32;	size:4;	signed:1;
*/

struct cgroup_attach_task {
  /* The first 8 bytes is not allowed to read */
  unsigned long pad;

  unsigned int dst_root;
  unsigned int dst_level;
  u64 dst_id;
  int pid;
  u32 __data_loc_path;
  u32 __data_loc_comm;
};

struct event {
  u64 dst_id;
	int pid;
  u32 current_pid;
  // path is bytes in go side
	u8 path[512];
  u8 comm[128];
};

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1<<24);
} events SEC(".maps");

// Force emitting struct event into the ELF.
const struct event *unused __attribute__((unused));

SEC("tracepoint/cgroup/cgroup_attach_task")
int cgroup_finder(struct cgroup_attach_task *ctx) {
  unsigned short path_offset = ctx->__data_loc_path & 0xFFFF;
  char *path_ptr=(char *)ctx + path_offset;

  unsigned short comm_offset = ctx->__data_loc_comm & 0xFFFF;
  char *comm_ptr=(char *)ctx + comm_offset;

  struct event *task_info;
  task_info = bpf_ringbuf_reserve(&events, sizeof(struct event), 0);
  if (!task_info) {
    return 0;
  }
  u64 id = bpf_get_current_pid_tgid();
  task_info->current_pid = id >> 32;
  task_info->dst_id = ctx->dst_id;
  task_info->pid = ctx->pid;
  bpf_core_read_str(task_info->path, sizeof(task_info->path), path_ptr);
  bpf_core_read_str(task_info->comm, sizeof(task_info->comm), comm_ptr);
  // bpf_printk("cgroup info, dst_id: %d, pid: %d, path: %s\n", ctx->dst_id, ctx->pid, path_str);
  bpf_ringbuf_submit(task_info, 0);
  return 0;
}
