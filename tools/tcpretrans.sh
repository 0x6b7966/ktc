#!/usr/bin/env bash
#
# tcpretrans    Trace or count TCP retransmits and TLPs.
#               For Linux, uses BCC, eBPF. Embedded C.
#
# USAGE: tcpretrans [-c] [-h] [-l]
#
# This uses dynamic tracing of kernel functions, and will need to be updated
# to match kernel changes.
#
# 17-Sep-2018   Ethercflow   Created this.

### default variables
tracing=/sys/kernel/debug/tracing
flock=/var/tmp/.ftrace-lock
bufsize_kb=4096
opt_tlp=0; opt_stacks=0;
trap ':' INT QUIT TERM PIPE HUP	# sends execution to end tracing section

function usage {
    cat <<-END >&2
    USAGE: tcpretrans [-hlc]
                      -h        # help message
                      -l        # include tail loss probes attempts
                      -s        # print stack traces
                      -c        # count occurred retransmits per flow
    eg,
           tcpretrans           # trace TCP retransmits
           tcpretrans -l        # include TLP attempts
END
    exit
}

function warn {
    if ! eval "$@"; then
        echo >&2 "WARNING: command failed \"$@\""
    fi
}

function end {
    echo 2>/dev/null
    echo "Ending tracing..." 2>/dev/null
    cd $tracing
    warn "echo 0 > events/tcp/tcp_retransmit_skb/enable"
    if (( opt_tlp )); then
        warn "echo 0 > events/tcp/tcp_send_loss_probe/enable"
    fi
    if (( opt_stacks )); then
        warn "echo 0 > options/stacktrace"
    fi
    warn "echo > trace"
    (( wroteflock )) && warn "rm $flock"
}

function die {
    echo >&2 "$@"
    exit 1
}

function edie {
    # die with a quiet end()
    echo >&2 "$@"
    exec >/dev/null 2>&1
    end
    exit 1
}

### process options
while getopts hls opt
do
    case $opt in
    l) opt_tlp=1 ;;
    s) opt_stacks=1 ;;
    h|?) usage ;;
    esac
done
echo "Tracing retransmits ... Hit Ctrl-C to end"

# select awk
awk=gawk
wroteflock=1

### check permissions
cd $tracing || die "ERROR: accessing tracing. Root user? Kernel has FTRACE?
    debugfs mounted? (mount -t debugfs debugfs /sys/kernel/debug)"

### ftrace lock
[[ -e $flock ]] && die "ERROR: ftrace may be in use by PID $(cat $flock) $flock"
echo $$ > $flock || die "ERROR: unable to write $flock."

### setup and begin tracing
echo nop > current_tracer
warn "echo $bufsize_kb > buffer_size_kb"
if ! echo 1 > events/tcp/tcp_retransmit_skb/enable; then
    edie "ERROR: enabling . Exiting."
fi
if (( opt_tlp )); then
    if ! echo 1 > events/tcp/tcp_send_loss_probe/enable; then
        edie "ERROR: enabling . Exiting."
    fi
fi
if (( opt_stacks )); then
    if ! echo 1 > options/stacktrace; then
        warn "unable to enable stacktraces."
    fi
fi
printf "%-8s %-6s" "TIME" "PID"
printf "%-20s" "LADDR:LPORT"
printf " T> "
printf "%-20s" "RADDR:RPORT"
printf "%-12s\n" "STATE"

#
# Determine output format. It may be one of the following (newest first):
#           TASK-PID   CPU#  ||||    TIMESTAMP  FUNCTION
#           TASK-PID    CPU#    TIMESTAMP  FUNCTION
# To differentiate between them, the number of header fields is counted,
# and an offset set, to skip the extra column when needed.
#
offset=$($awk 'BEGIN { o = 0; }
    $1 == "#" && $2 ~ /TASK/ && NF == 6 { o = 1; }
    $2 ~ /TASK/ { print o; exit }' trace)

### print trace buffer
warn "echo > trace"
cat trace_pipe | $awk -v o=$offset -v stacks=$opt_stacks '
    BEGIN {
        m[1]="TCP_ESTABLISHED";
        m[2]="TCP_SYN_SENT";
        m[3]="TCP_SYN_RECV";
        m[4]="TCP_FIN_WAIT1";
        m[5]="TCP_FIN_WAIT2";
        m[6]="TCP_TIME_WAIT";
        m[7]="TCP_CLOSE";
        m[8]="TCP_CLOSE_WAIT";
        m[9]="TCP_LAST_ACK";
        m[10]="TCP_LISTEN";
    }

    $1 != "#" {
	if (stacks) {
	     if ($0 ~ /^ =>/) {
	     	print $0
	     	next
	     }
	     if ($0 ~ /<stack trace>/) {
		next
	     }
	}

        pid = $1
        sub(/.*-/, "", pid)
        time = $(3+o); sub(":", "", time)

        laddr = $(7+o); sub(/.*=/, "", laddr)
        lport = $(5+o); sub(/.*=/, "", lport)
        raddr = $(8+o); sub(/.*=/, "", raddr)
        rport = $(6+o); sub(/.*=/, "", rport)
        state = $(11+o); sub(/.*=/, "", state)

        printf "%-8s %-6s", strftime("%H:%M:%S", time), pid
        printf "%-20s", (laddr":"lport)
        printf " %s> ", ($0 ~ /tcp_send_loss_probe/ ? "L" : "R")
        printf "%-20s", (raddr":"rport)
        printf "%-12s\n", m[state]

        next
    }

    $0 ~ /LOST.*EVENTS/ { print "WARNING: " $0 > "/dev/stderr" }
'

### end tracing
end
