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
name: cgroup_mkdir
ID: 424
format:
	field:unsigned short common_type;	offset:0;	size:2;	signed:0;
	field:unsigned char common_flags;	offset:2;	size:1;	signed:0;
	field:unsigned char common_preempt_count;	offset:3;	size:1;	signed:0;
	field:int common_pid;	offset:4;	size:4;	signed:1;

	field:int root;	offset:8;	size:4;	signed:1;
	field:int level;	offset:12;	size:4;	signed:1;
	field:u64 id;	offset:16;	size:8;	signed:0;
	field:__data_loc char[] path;	offset:24;	size:4;	signed:1;
*/

struct cgroup_mkdir {
  /* The first 8 bytes is not allowed to read */
  unsigned long pad;

  int root;
  int level;
  u64 id;
  u32 __data_loc_path;
};

struct cgroup_mkdir_event {
  u32 root;
  u32 level;
  u64 id;
  // path is bytes in go side
	u8 path[512];
};


// https://stackoverflow.com/questions/63415220/bpf-ring-buffer-invalid-argument-22
struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1 << 12);
} events SEC(".maps");

// Force emitting struct event into the ELF.
const struct cgroup_mkdir_event *unused __attribute__((unused));

SEC("tracepoint/cgroup/cgroup_mkdir")
int cgroup_finder(struct cgroup_mkdir *ctx) {
  unsigned short path_offset = ctx->__data_loc_path & 0xFFFF;
  char *path_ptr=(char *)ctx + path_offset;

  struct cgroup_mkdir_event *event_info;
  event_info = bpf_ringbuf_reserve(&events, sizeof(struct cgroup_mkdir_event), 0);
  if (!event_info) {
    return 0;
  }
  event_info->root = ctx->root;
  event_info->level = ctx->level;
  event_info->id = ctx->id;
  bpf_core_read_str(event_info->path, sizeof(event_info->path), path_ptr);
  // TODO: filter by perfix
  bpf_ringbuf_submit(event_info, 0);
  return 0;
}
