#!/usr/bin/python
#
# syscount   Summarize syscall counts and latencies.
#
# USAGE: syscount [-p PID] [-i INTERVAL] [-T TOP] [-x] [-L] [-m] [-P] [-l]
#
# Copyright 2017, Sasha Goldshtein.
# Licensed under the Apache License, Version 2.0 (the "License")
#
# 15-Feb-2017   Sasha Goldshtein    Created this.

from time import sleep, strftime
import argparse
import errno
import itertools
import sys
import signal
import bcc
from bcc import BPF
from bcc.utils import printb
from bcc.syscall import syscall_name, syscalls

if sys.version_info.major < 3:
    izip_longest = itertools.izip_longest
else:
    izip_longest = itertools.zip_longest

# signal handler
def signal_ignore(signal, frame):
    print()

def handle_errno(errstr):
    try:
        return abs(int(errstr))
    except ValueError:
        pass

    try:
        return getattr(errno, errstr)
    except AttributeError:
        raise argparse.ArgumentTypeError("couldn't map %s to an errno" % errstr)


parser = argparse.ArgumentParser(
    description="Summarize syscall counts and latencies.")
parser.add_argument("-p", "--pid", type=int, help="trace only this pid")
parser.add_argument("--child-reaper-pid", type=int, help="trace only processes in the pid namespace whose init process has this pid (in the root pid namespace)")
parser.add_argument("-i", "--interval", type=int,
    help="print summary at this interval (seconds)")
parser.add_argument("-d", "--duration", type=int,
    help="total duration of trace, in seconds")
parser.add_argument("-T", "--top", type=int, default=10,
    help="print only the top syscalls by count or latency")
parser.add_argument("-x", "--failures", action="store_true",
    help="trace only failed syscalls (return < 0)")
parser.add_argument("-e", "--errno", type=handle_errno,
    help="trace only syscalls that return this error (numeric or EPERM, etc.)")
parser.add_argument("-L", "--latency", action="store_true",
    help="collect syscall latency")
parser.add_argument("-m", "--milliseconds", action="store_true",
    help="display latency in milliseconds (default: microseconds)")
parser.add_argument("-P", "--process", action="store_true",
    help="count by process and not by syscall")
parser.add_argument("-l", "--list", action="store_true",
    help="print list of recognized syscalls and exit")
parser.add_argument("--ebpf", action="store_true",
    help=argparse.SUPPRESS)
args = parser.parse_args()
if args.duration and not args.interval:
    args.interval = args.duration
if not args.interval:
    args.interval = 99999999

if args.list:
    for grp in izip_longest(*(iter(sorted(syscalls.values())),) * 4):
        print("   ".join(["%-20s" % s for s in grp if s is not None]))
    sys.exit(0)

text = """
#include <linux/sched.h>
#include <linux/pid_namespace.h>  // task_active_pid_ns, struct pid_namespace
#include <linux/pid.h>

#ifdef LATENCY
struct data_t {
    u64 count;
    u64 total_ns;
};

BPF_HASH(start, u64, u64);
BPF_HASH(data, u32, struct data_t);
#else
BPF_HASH(data, u32, u64);
#endif
BPF_HASH(count_by_ns, u32, u64);

static inline int namespace_error() {
#ifdef FILTER_REAPER_PID
    struct task_struct *curtask =  (struct task_struct *)bpf_get_current_task();

    // struct pid_namespace *ns2 = task_active_pid_ns(curtask); // = ns_of_pid(task_pid(curtask))

    // the following two lines ns_of_pid(task_tgid(curtask)) are equivalent to task_active_pid_ns(curtask) from pid_namespace.h
    struct pid *curtgid = curtask->group_leader->pids[PIDTYPE_PID].pid;  // = task_tgid(curtask) from sched.h
    struct pid_namespace *ns = curtgid->numbers[curtgid->level].ns; // = ns_of_pid(curtid) from pid.h

    // the reaper is the init process
    struct task_struct *child_reaper = ns->child_reaper;
    struct pid *child_reaper_pid = child_reaper->pids[PIDTYPE_PID].pid;  // = get_task_pid(child_reaper, PIDTYPE_PID);
    int child_reaper_pid_nr = child_reaper_pid->numbers[0].nr;  // = pid_nr(child_reaper_pid)  from pid.h
    u64 zero = 0, *val = count_by_ns.lookup_or_try_init(&child_reaper_pid_nr, &zero);
    if (val) {
        ++(*val);
    }
    if (child_reaper_pid_nr == FILTER_REAPER_PID) {
        return 0;
    } else {
        return 1;
    }
#else
    return 0;
#endif
}

#ifdef LATENCY
TRACEPOINT_PROBE(raw_syscalls, sys_enter) {
    u64 pid_tgid = bpf_get_current_pid_tgid();

#ifdef FILTER_PID
    if (pid_tgid >> 32 != FILTER_PID)
        return 0;
#endif

    if (0 != namespace_error()) {
        return 0;
    }

    u64 t = bpf_ktime_get_ns();
    start.update(&pid_tgid, &t);
    return 0;
}
#endif

TRACEPOINT_PROBE(raw_syscalls, sys_exit) {
    u64 pid_tgid = bpf_get_current_pid_tgid();

#ifdef FILTER_PID
    if (pid_tgid >> 32 != FILTER_PID)
        return 0;
#endif

#ifdef FILTER_FAILED
    if (args->ret >= 0)
        return 0;
#endif

#ifdef FILTER_ERRNO
    if (args->ret != -FILTER_ERRNO)
        return 0;
#endif

#ifdef BY_PROCESS
    u32 key = pid_tgid >> 32;
#else
    u32 key = args->id;
#endif

    if (0 != namespace_error()) {
        return 0;
    }

#ifdef LATENCY
    struct data_t *val, zero = {};
    u64 *start_ns = start.lookup(&pid_tgid);
    if (!start_ns)
        return 0;

    val = data.lookup_or_try_init(&key, &zero);
    if (val) {
        val->count++;
        val->total_ns += bpf_ktime_get_ns() - *start_ns;
    }
#else
    u64 *val, zero = 0;
    val = data.lookup_or_try_init(&key, &zero);
    if (val) {
        ++(*val);
    }
#endif
    return 0;
}
"""

if args.pid:
    text = ("#define FILTER_PID %d\n" % args.pid) + text
if args.child_reaper_pid:
    text = ("#define FILTER_REAPER_PID %d\n" % args.child_reaper_pid) + text
if args.failures:
    text = "#define FILTER_FAILED\n" + text
if args.errno:
    text = "#define FILTER_ERRNO %d\n" % abs(args.errno) + text
if args.latency:
    text = "#define LATENCY\n" + text
if args.process:
    text = "#define BY_PROCESS\n" + text
if args.ebpf:
    print(text)
    exit()

#bpf = BPF(text=text, debug=bcc.DEBUG_LLVM_IR | bcc.DEBUG_BPF | bcc.DEBUG_PREPROCESSOR | bcc.DEBUG_SOURCE | bcc.DEBUG_BPF_REGISTER_STATE | bcc.DEBUG_BTF)
bpf = BPF(text=text, debug=bcc.DEBUG_SOURCE)

def print_stats():
    if args.latency:
        print_latency_stats()
    else:
        print_count_stats()
    if args.child_reaper_pid:
        print_reaper_stats()

agg_colname = "PID    COMM" if args.process else "SYSCALL"
time_colname = "TIME (ms)" if args.milliseconds else "TIME (us)"

def comm_for_pid(pid):
    try:
        return open("/proc/%d/comm" % pid, "rb").read().strip()
    except Exception:
        return b"[unknown]"

def agg_colval(key):
    if args.process:
        return b"%-6d %-15s" % (key.value, comm_for_pid(key.value))
    else:
        return syscall_name(key.value)

def print_count_stats():
    data = bpf["data"]
    print("[%s]" % strftime("%H:%M:%S"))
    print("%-22s %8s" % (agg_colname, "COUNT"))
    for k, v in sorted(data.items(), key=lambda kv: -kv[1].value)[:args.top]:
        if k.value == 0xFFFFFFFF:
            continue    # happens occasionally, we don't need it
        printb(b"%-22s %8d" % (agg_colval(k), v.value))
    print("")
    data.clear()

def print_latency_stats():
    data = bpf["data"]
    print("[%s]" % strftime("%H:%M:%S"))
    print("%-22s %8s %16s" % (agg_colname, "COUNT", time_colname))
    for k, v in sorted(data.items(),
                       key=lambda kv: -kv[1].total_ns)[:args.top]:
        if k.value == 0xFFFFFFFF:
            continue    # happens occasionally, we don't need it
        printb((b"%-22s %8d " + (b"%16.6f" if args.milliseconds else b"%16.3f")) %
               (agg_colval(k), v.count,
                v.total_ns / (1e6 if args.milliseconds else 1e3)))
    print("")
    data.clear()

def print_reaper_stats():
    print("Reaper stats:")
    count_by_ns = bpf["count_by_ns"]
    for k, v in sorted(count_by_ns.items(), key=lambda kv: -kv[1].value):
        if k.value == 0xffffffff:
            continue
        printb(b"%-6d %-15s %8d" % (k.value, comm_for_pid(k.value), v.value))
    print("")
    count_by_ns.clear()

print("Tracing %ssyscalls, printing top %d... Ctrl+C to quit." %
      ("failed " if args.failures else "", args.top))
exiting = 0 if args.interval else 1
seconds = 0
while True:
    try:
        sleep(args.interval)
        seconds += args.interval
    except KeyboardInterrupt:
        exiting = 1
        signal.signal(signal.SIGINT, signal_ignore)
    if args.duration and seconds >= args.duration:
        exiting = 1

    print_stats()

    if exiting:
        print("Detaching...")
        exit()
