# LSM eBPF

export PATH="/usr/include/x86_64-linux-gnu:$PATH"
bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h

## Build

```sh
go generate
go build -o lsm
```

or

```sh
./build.sh
```

## Run

```sh
sudo ./lsm
```

## Issues

Copy strings, maybe replace with

bpf_probe_read_str(e->comm, TASK_COMM_SIZE, comm);
bpf_probe_read_str(e->path, MAX_FILE_NAME_LENGTH, path);

## Troubleshooting

Checks if lsm is enabled in kernel probes (may not be sufficient, so grub modification needed)

```sh
sudo bpftool feature probe kernel | grep lsm
grep LSM /boot/config-5.15.0-122-generic
```

more generic
```sh
grep LSM /boot/config-$(uname -r)
```

check if bpf lsm is enabled
```sh
cat /sys/kernel/security/lsm
```

if ```bpf``` is not listed, need to add it

### Add bpf lsm into grub configuration
intro

<https://github.com/lockc-project/lockc/issues/159>
<https://gitlab.manjaro.org/packages/core/linux517/-/issues/2>
<https://bugs.launchpad.net/ubuntu/+source/linux/+bug/2054810>

instructions
- <https://tetragon.io/docs/concepts/tracing-policy/hooks/#lsm-bpf>
- <https://aya-rs.dev/book/programs/lsm/#what-is-lsm>

edit to include bpf in LSM congiguration, so it will look something like this (other LSMs included too, can be determined by calling ```grep CONFIG_LSM /boot/config-5.15.0-122-generic```):

```sh
grep GRUB_CMDLINE_LINUX /etc/default/grub
GRUB_CMDLINE_LINUX_DEFAULT="lsm=lockdown,capability,bpf,landlock,yama,integrity,apparmor"
GRUB_CMDLINE_LINUX="lsm=lockdown,capability,bpf,landlock,yama,integrity,apparmor"
```

## References

- <https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git/tree/tools/testing/selftests/bpf/prog_tests/test_lsm.c>
- <https://www.kernel.org/doc/html/v5.9/bpf/bpf_lsm.html>
- <https://www.kernel.org/doc/html/v5.15/admin-guide/kernel-parameters.html>
- <https://docs.ebpf.io/linux/program-type/BPF_PROG_TYPE_LSM/>
- <https://github.com/ShiftLeftSecurity/traceleft/blob/master/documentation/file-tracking.md>
- <https://docs.kernel.org/bpf/prog_lsm.html>