# LSM eBPF

export PATH="/usr/include/x86_64-linux-gnu:$PATH"
bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h

## Build

```sh
go generate
go build -o lsm
```

## Run

```sh
sudo ./lsm
```

## Issues

Copy strings, maybe replace with

bpf_probe_read_str(e->comm, TASK_COMM_SIZE, comm);
bpf_probe_read_str(e->path, MAX_FILE_NAME_LENGTH, path);