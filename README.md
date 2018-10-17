# Kernel Trace tools Collection (KTC)

KTC is a toolkit for efficient trace various subsystems of the kernel, and
includes several useful tools and examples. It makes use of ftrace + kprobes,
currently only supports the Centos7.5's 3.10.0-862.el7.x86_64.

## Screenshot

This example traces the kernel TCP retransmit function to show details of these
retransmits.

```Shell
# ./tcpretrans
TIME     PID    IP LADDR:LPORT          T> RADDR:RPORT          STATE
01:55:05 0      4  10.153.223.157:22    R> 69.53.245.40:34619   ESTABLISHED
01:55:05 0      4  10.153.223.157:22    R> 69.53.245.40:34619   ESTABLISHED
01:55:17 0      4  10.153.223.157:22    R> 69.53.245.40:22957   ESTABLISHED
```

The above output shows three TCP retransmits, the first two were for an IPv4
connection from 10.153.223.157 port 22 to 69.53.245.40 port 34619. The TCP
state was "ESTABLISHED" at the time of the retransmit. The on-CPU PID at the
time of the retransmit is printed, in this case 0 (the kernel, which will
be the case most of the time).

See the source: [tcpretrans](tools/tcpretrans). What this traces, what this
stores, and how the data is presented, can be entirely customized. This shows
only some of possible capabilities.

## Prerequisites
The intent is as few as possible.

### kernel-devel

We need to compile some kernel modules to generate tracing data. You can install
the kernel-devel package by:

``` Shell
yum install kernel-devel-`uname -r`
```

### ftrace

FTRACE configured in the kernel. You may already have this configured and
available in your kernel. This requires CONFIG_FTRACE and other FTRACE options
depending on the tool.

### debugfs

Requires a kernel with CONFIG_DEBUG_FS option enabled. As with FTRACE, this may
already be enabled (debugfs was added in 2.6.10-rc3). The debugfs also needs to
be mounted:

```
# mount -t debugfs none /sys/kernel/debug
```

### kprobe
KPROBE configured in the kernel. You may already have this configured and
available in your kernel. This requires CONFIG_KPROBES and other KPROBE options
depending on the tool.

### awk

Many of there scripts use awk, and will try to use either mawk or gawk depending
on the desired behavior: mawk for buffered output (because of its speed), and
gawk for synchronous output (as fflush() works, allowing more efficient grouping
of writes).

## Installing

```Shell
wget https://github.com/ethercflow/ktc/archive/v0.1.tar.gz
tar zxf v0.1.tar.gz && cd ktc-0.1/src/modules/tcp
make
insmod tcp_trace.ko
```

### Tracing

#### Tools:
- tools/[tcpaccept](tools/tcpaccept): Trace TCP passive connections (accept()). [Examples](tools/tcpaccept_example.txt).
- tools/[tcpconnect](tools/tcpconnect): Trace TCP active connections (connect()). [Examples](tools/tcpconnect_example.txt).
- tools/[tcpconnlat](tools/tcpconnlat): Trace TCP active connection latency (connect()). [Examples](tools/tcpconnlat_example.txt).
- tools/[tcplife](tools/tcplife): Trace TCP sessions and summarize lifespan. [Examples](tools/tcplife_example.txt).
- tools/[tcpretrans](tools/tcpretrans): Trace TCP retransmits and TLPs. [Examples](tools/tcpretrans_example.txt).
- tools/[tcpstates](tools/tcpstates): Trace TCP session state changes with durations. [Examples](tools/tcpstates_example.txt).

### What's Next
- Add more events and tools for various subsystems of the kernel
- Compatible with all Centos 7.x versions
