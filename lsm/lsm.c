// +build ignore

#include <string.h>

#include "vmlinux.h"
#include <errno.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include "bpf_misc.h"

#define TASK_COMM_SIZE 100
#define MAX_FILE_NAME_LENGTH 128
#define LOG_DIR "/etc/passwd"
#define LEN_LOG_DIR sizeof(LOG_DIR)
#define COMM "cat"
#define LEN_COMM sizeof(COMM)

char __license[] SEC("license") = "Dual MIT/GPL";

struct event
{
  u32 pid;
  u8 comm[TASK_COMM_SIZE];
  u8 path[MAX_FILE_NAME_LENGTH];
};

struct
{
  __uint(type, BPF_MAP_TYPE_RINGBUF);
  __uint(max_entries, 1 << 24);
} events SEC(".maps");

// Force emitting struct event into the ELF.
const struct event *unused __attribute__((unused));

int mprotect_count = 0;

// SEC("lsm/file_mprotect")
// int BPF_PROG(mprotect_audit, struct vm_area_struct *vma,
// 	     unsigned long reqprot, unsigned long prot, int ret)
// {
// 	if (ret != 0)
// 		return ret;

// 	__s32 pid = bpf_get_current_pid_tgid() >> 32;
// 	int is_stack = 0;

// 	struct event *e;

// 	e = bpf_ringbuf_reserve(&events, sizeof(struct event), 0);
// 	if (!e) {
// 		return 0;
// 	}

// 	e->pid = pid;
// 	bpf_get_current_comm(&e->comm, TASK_COMM_SIZE);

// 	bpf_ringbuf_submit(e, 0);

// 	// return (mprotect_count > 10) ? -EPERM : 0;
// 	return 0;
// }

static inline int matchPrefix(char str[MAX_FILE_NAME_LENGTH])
{
  for (int i = 0; i < LEN_LOG_DIR; i++)
  {
    char ch1 = LOG_DIR[i];
    if (ch1 == '\0')
    {
      return 0;
    }
    char ch2 = str[i];
    if (ch2 == '\0')
    {
      return -1;
    }
    if (ch1 != ch2)
    {
      return -2;
    }
  }
  return (-3);
}

static inline int matchPrefix2(char str[TASK_COMM_SIZE])
{
  for (int i = 0; i < LEN_COMM; i++)
  {
    char ch1 = COMM[i];
    if (ch1 == '\0')
    {
      return 0;
    }
    char ch2 = str[i];
    if (ch2 == '\0')
    {
      return -1;
    }
    if (ch1 != ch2)
    {
      return -2;
    }
  }
  return (-3);
}

static inline void copy(u8 *src, u8 *dst, unsigned int len)
{
  for (int i = 0; i < 2; i++)
  {
    dst[i] = src[i];

    if (dst[i] == '\0')
    {
      return;
    }
  }
}

SEC("lsm/file_open")
int BPF_PROG(mprotect_audit, struct file *file, int ret)
{
  if (ret != 0)
    return ret;

  __s32 pid = bpf_get_current_pid_tgid() >> 32;

  u8 comm[TASK_COMM_SIZE];
  char buf[MAX_FILE_NAME_LENGTH];

  struct event *e;

  e = bpf_ringbuf_reserve(&events, sizeof(struct event), 0);
  if (!e)
  {
    return 0;
  }

  e->pid = pid;

  bpf_get_current_comm(e->comm, TASK_COMM_SIZE);
  bpf_d_path(&file->f_path, (char *)e->path, MAX_FILE_NAME_LENGTH);

  int res = 0;
  res = matchPrefix((char *)e->path);
  int res2 = 0;
  res2 = matchPrefix2((char *)e->comm);

  if (!res)
  {

    bpf_ringbuf_submit(e, 0);
  }
  else
  {
    bpf_ringbuf_discard(e, 0);
  }

  if (!res && !res2)
  {
    return -EPERM;
  }

  return 0;
}
