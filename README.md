# ebpf-recipes
Some eBPF recipes for common use cases. Basic stuff.

Based on

- <https://ebpf-go.dev/guides/getting-started/#compile-ebpf-c-and-generate-scaffolding-using-bpf2go>
- <https://github.com/cilium/ebpf/tree/main/examples>
- <https://edgedelta.com/company/blog/applied-introduction-ebpf-go> and <https://github.com/ozansz/intro-ebpf-with-go/tree/main>

Tested on:

```sh
OS: Ubuntu 22.04.5 LTS x86_64 
Kernel: 5.15.0-122-generic
```

## Requirements

# add golang backports to install 2:1.23 version of golang
https://askubuntu.com/questions/513/any-ppas-for-googles-go-language

```sh
sudo add-apt-repository ppa:longsleep/golang-backports
sudo apt update
sudo apt install golang
sudo apt install bpftrace llvm clang gcc-multilib libbpf-dev linux-tools-common linux-tools-5.15.0-122-generic linux-cloud-tools-5.15.0-122-generic
```

## Troubleshooting

Check enabled kernel probes

```sh
sudo bpftool feature probe kernel > kernel_probes.txt
```

Other

<https://github.com/iovisor/bcc/issues/4723>

## References

- <https://ebpf.io/labs/>
- <https://ebpf.io/applications/>
- <https://qmonnet.github.io/whirl-offload/2021/09/23/bpftool-features-thread/>
- <https://www.alibabacloud.com/blog/seven-core-issues-about-ebpf_599668>
- <https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git/tree/tools/testing/selftests/bpf/progs>
- <https://archive.fosdem.org/2020/schedule/event/security_kernel_runtime_security_instrumentation/attachments/slides/3842/export/events/attachments/security_kernel_runtime_security_instrumentation/slides/3842/Kernel_Runtime_Security_Instrumentation.pdf>
- <https://ancat.github.io/kernel/2021/05/20/hooking-processes-and-threads.html> and <https://man7.org/linux/man-pages/man2/execve.2.html>
