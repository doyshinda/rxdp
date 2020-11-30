#!/bin/bash

# eBPF settings
mount bpffs /sys/fs/bpf -t bpf
ulimit -l unlimited

source ~/.bashrc
exec "$@"
