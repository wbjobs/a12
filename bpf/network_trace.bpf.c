#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>

#define TASK_COMM_LEN 16
#define MAX_PAYLOAD_SIZE 1024
#define MAX_PATH_LEN 256

typedef unsigned int __u32;
typedef unsigned long long __u64;

enum event_type {
    EVENT_CONNECT = 0,
    EVENT_ACCEPT = 1,
    EVENT_SENDTO = 2,
    EVENT_RECVFROM = 3,
    EVENT_CLOSE = 4,
};

enum protocol {
    PROTOCOL_HTTP = 0,
    PROTOCOL_GRPC = 1,
    PROTOCOL_REDIS = 2,
    PROTOCOL_UNKNOWN = 3,
};

struct connection_key {
    __u32 pid;
    __u32 fd;
};

struct connection_info {
    __u64 connect_ts;
    __u32 saddr;
    __u32 daddr;
    __u16 sport;
    __u16 dport;
    char comm[TASK_COMM_LEN];
    __u8 protocol;
};

struct socket_key {
    __u32 pid;
    __u64 socket_ptr;
};

struct trace_event {
    __u64 timestamp;
    __u32 pid;
    __u32 tid;
    __u32 uid;
    __u32 gid;
    char comm[TASK_COMM_LEN];
    __u8 event_type;
    __u8 protocol;
    __u32 saddr;
    __u32 daddr;
    __u16 sport;
    __u16 dport;
    __u64 duration_ns;
    __s32 error_code;
    __u32 payload_size;
    char payload[MAX_PAYLOAD_SIZE];
    char trace_id[33];
    char span_id[17];
    char parent_span_id[17];
    char path[MAX_PATH_LEN];
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 65536);
    __type(key, struct connection_key);
    __type(value, struct connection_info);
} connections SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 65536);
    __type(key, struct socket_key);
    __type(value, struct connection_key);
} socket_to_conn SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(__u32));
    __uint(max_entries, 4096);
} events SEC(".maps");

static __always_inline void fill_common_info(struct trace_event *event) {
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    event->timestamp = bpf_ktime_get_ns();
    event->pid = bpf_get_current_pid_tgid() >> 32;
    event->tid = bpf_get_current_pid_tgid() & 0xFFFFFFFF;
    event->uid = bpf_get_current_uid_gid() >> 32;
    event->gid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    bpf_get_current_comm(&event->comm, TASK_COMM_LEN);
    event->error_code = 0;
    event->duration_ns = 0;
    event->payload_size = 0;
    __builtin_memset(event->trace_id, 0, sizeof(event->trace_id));
    __builtin_memset(event->span_id, 0, sizeof(event->span_id));
    __builtin_memset(event->parent_span_id, 0, sizeof(event->parent_span_id));
    __builtin_memset(event->path, 0, sizeof(event->path));
}

static __always_inline __u8 detect_protocol(__u16 dport, __u16 sport) {
    __u16 http_ports[] = {80, 8080, 3000, 8000, 9090};
    __u16 grpc_ports[] = {50051, 9000, 7000};
    __u16 redis_ports[] = {6379};
    
    for (int i = 0; i < sizeof(http_ports)/sizeof(__u16); i++) {
        if (dport == bpf_htons(http_ports[i]) || sport == bpf_htons(http_ports[i])) {
            return PROTOCOL_HTTP;
        }
    }
    for (int i = 0; i < sizeof(grpc_ports)/sizeof(__u16); i++) {
        if (dport == bpf_htons(grpc_ports[i]) || sport == bpf_htons(grpc_ports[i])) {
            return PROTOCOL_GRPC;
        }
    }
    for (int i = 0; i < sizeof(redis_ports)/sizeof(__u16); i++) {
        if (dport == bpf_htons(redis_ports[i]) || sport == bpf_htons(redis_ports[i])) {
            return PROTOCOL_REDIS;
        }
    }
    return PROTOCOL_UNKNOWN;
}

static __always_inline void parse_payload(struct trace_event *event, const char *buf, __u32 size) {
    if (size <= 0) return;
    
    __u32 copy_size = size > MAX_PAYLOAD_SIZE ? MAX_PAYLOAD_SIZE : size;
    bpf_probe_read_user(&event->payload, copy_size, buf);
    event->payload_size = size;
    
    if (event->protocol == PROTOCOL_HTTP && size >= 4) {
        if (event->payload[0] == 'G' && event->payload[1] == 'E' && 
            event->payload[2] == 'T' && event->payload[3] == ' ') {
            int i = 4, j = 0;
            while (i < MAX_PAYLOAD_SIZE && j < MAX_PATH_LEN - 1 && 
                   event->payload[i] != ' ' && event->payload[i] != '\0') {
                event->path[j++] = event->payload[i++];
            }
            event->path[j] = '\0';
        }
    }
}

SEC("kprobe/tcp_connect")
int BPF_KPROBE(tcp_connect, struct sock *sk) {
    struct trace_event event = {};
    fill_common_info(&event);
    event.event_type = EVENT_CONNECT;
    
    struct connection_key conn_key = {
        .pid = event.pid,
        .fd = 0,
    };
    
    struct socket *sock = BPF_CORE_READ(sk, sk_socket);
    if (sock) {
        struct file *file = BPF_CORE_READ(sock, file);
        if (file) {
            conn_key.fd = BPF_CORE_READ(file, f_pos);
        }
    }
    
    struct sockaddr_in *addr = (struct sockaddr_in *)BPF_CORE_READ(sk, sk_v6_daddr);
    event.daddr = BPF_CORE_READ(sk, sk_daddr);
    event.saddr = BPF_CORE_READ(sk, sk_rcv_saddr);
    event.dport = BPF_CORE_READ(sk, sk_dport);
    event.sport = BPF_CORE_READ(sk, sk_num);
    event.protocol = detect_protocol(event.dport, event.sport);
    
    struct connection_info conn_info = {
        .connect_ts = event.timestamp,
        .saddr = event.saddr,
        .daddr = event.daddr,
        .sport = event.sport,
        .dport = event.dport,
        .protocol = event.protocol,
    };
    __builtin_memcpy(&conn_info.comm, &event.comm, TASK_COMM_LEN);
    
    bpf_map_update_elem(&connections, &conn_key, &conn_info, BPF_ANY);
    
    struct socket_key sock_key = {
        .pid = event.pid,
        .socket_ptr = (__u64)sk,
    };
    bpf_map_update_elem(&socket_to_conn, &sock_key, &conn_key, BPF_ANY);
    
    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &event, sizeof(event));
    
    return 0;
}

SEC("kretprobe/tcp_connect")
int BPF_KRETPROBE(tcp_connect_ret, int ret) {
    if (ret < 0) {
        struct trace_event event = {};
        fill_common_info(&event);
        event.event_type = EVENT_CONNECT;
        event.error_code = ret;
        bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &event, sizeof(event));
    }
    return 0;
}

SEC("kprobe/tcp_accept")
int BPF_KPROBE(tcp_accept, struct sock *sk, struct sock *newsk) {
    struct trace_event event = {};
    fill_common_info(&event);
    event.event_type = EVENT_ACCEPT;
    
    event.saddr = BPF_CORE_READ(newsk, sk_daddr);
    event.daddr = BPF_CORE_READ(newsk, sk_rcv_saddr);
    event.sport = BPF_CORE_READ(newsk, sk_dport);
    event.dport = BPF_CORE_READ(newsk, sk_num);
    event.protocol = detect_protocol(event.dport, event.sport);
    
    struct connection_key conn_key = {
        .pid = event.pid,
        .fd = 0,
    };
    
    struct connection_info conn_info = {
        .connect_ts = event.timestamp,
        .saddr = event.saddr,
        .daddr = event.daddr,
        .sport = event.sport,
        .dport = event.dport,
        .protocol = event.protocol,
    };
    __builtin_memcpy(&conn_info.comm, &event.comm, TASK_COMM_LEN);
    
    bpf_map_update_elem(&connections, &conn_key, &conn_info, BPF_ANY);
    
    struct socket_key sock_key = {
        .pid = event.pid,
        .socket_ptr = (__u64)newsk,
    };
    bpf_map_update_elem(&socket_to_conn, &sock_key, &conn_key, BPF_ANY);
    
    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &event, sizeof(event));
    
    return 0;
}

SEC("kprobe/udp_sendmsg")
int BPF_KPROBE(udp_sendmsg, struct sock *sk, struct msghdr *msg, size_t len) {
    struct trace_event event = {};
    fill_common_info(&event);
    event.event_type = EVENT_SENDTO;
    
    event.saddr = BPF_CORE_READ(sk, sk_rcv_saddr);
    event.daddr = BPF_CORE_READ(sk, sk_daddr);
    event.sport = BPF_CORE_READ(sk, sk_num);
    event.dport = BPF_CORE_READ(sk, sk_dport);
    event.protocol = detect_protocol(event.dport, event.sport);
    
    struct iovec *iov = BPF_CORE_READ(msg, msg_iter.iov);
    if (iov) {
        void *buf = BPF_CORE_READ(iov, iov_base);
        __u32 size = BPF_CORE_READ(iov, iov_len);
        if (buf && size > 0) {
            parse_payload(&event, buf, size);
        }
    }
    
    struct socket_key sock_key = {
        .pid = event.pid,
        .socket_ptr = (__u64)sk,
    };
    
    struct connection_key *conn_key = bpf_map_lookup_elem(&socket_to_conn, &sock_key);
    if (conn_key) {
        struct connection_info *conn_info = bpf_map_lookup_elem(&connections, conn_key);
        if (conn_info) {
            event.duration_ns = event.timestamp - conn_info->connect_ts;
        }
    }
    
    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &event, sizeof(event));
    
    return 0;
}

SEC("kprobe/udp_recvmsg")
int BPF_KPROBE(udp_recvmsg, struct sock *sk, struct msghdr *msg, size_t len) {
    struct trace_event event = {};
    fill_common_info(&event);
    event.event_type = EVENT_RECVFROM;
    
    event.saddr = BPF_CORE_READ(sk, sk_daddr);
    event.daddr = BPF_CORE_READ(sk, sk_rcv_saddr);
    event.sport = BPF_CORE_READ(sk, sk_dport);
    event.dport = BPF_CORE_READ(sk, sk_num);
    event.protocol = detect_protocol(event.dport, event.sport);
    
    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &event, sizeof(event));
    
    return 0;
}

SEC("kprobe/tcp_sendmsg")
int BPF_KPROBE(tcp_sendmsg, struct sock *sk, struct msghdr *msg, size_t size) {
    struct trace_event event = {};
    fill_common_info(&event);
    event.event_type = EVENT_SENDTO;
    
    event.saddr = BPF_CORE_READ(sk, sk_rcv_saddr);
    event.daddr = BPF_CORE_READ(sk, sk_daddr);
    event.sport = BPF_CORE_READ(sk, sk_num);
    event.dport = BPF_CORE_READ(sk, sk_dport);
    event.protocol = detect_protocol(event.dport, event.sport);
    
    struct iovec *iov = BPF_CORE_READ(msg, msg_iter.iov);
    if (iov) {
        void *buf = BPF_CORE_READ(iov, iov_base);
        __u32 payload_size = BPF_CORE_READ(iov, iov_len);
        if (buf && payload_size > 0) {
            parse_payload(&event, buf, payload_size);
        }
    }
    
    struct socket_key sock_key = {
        .pid = event.pid,
        .socket_ptr = (__u64)sk,
    };
    
    struct connection_key *conn_key = bpf_map_lookup_elem(&socket_to_conn, &sock_key);
    if (conn_key) {
        struct connection_info *conn_info = bpf_map_lookup_elem(&connections, conn_key);
        if (conn_info) {
            event.duration_ns = event.timestamp - conn_info->connect_ts;
        }
    }
    
    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &event, sizeof(event));
    
    return 0;
}

SEC("kprobe/tcp_cleanup_rbuf")
int BPF_KPROBE(tcp_cleanup_rbuf, struct sock *sk, int copied) {
    if (copied <= 0) return 0;
    
    struct trace_event event = {};
    fill_common_info(&event);
    event.event_type = EVENT_RECVFROM;
    event.payload_size = copied;
    
    event.saddr = BPF_CORE_READ(sk, sk_daddr);
    event.daddr = BPF_CORE_READ(sk, sk_rcv_saddr);
    event.sport = BPF_CORE_READ(sk, sk_dport);
    event.dport = BPF_CORE_READ(sk, sk_num);
    event.protocol = detect_protocol(event.dport, event.sport);
    
    struct socket_key sock_key = {
        .pid = event.pid,
        .socket_ptr = (__u64)sk,
    };
    
    struct connection_key *conn_key = bpf_map_lookup_elem(&socket_to_conn, &sock_key);
    if (conn_key) {
        struct connection_info *conn_info = bpf_map_lookup_elem(&connections, conn_key);
        if (conn_info) {
            event.duration_ns = event.timestamp - conn_info->connect_ts;
        }
    }
    
    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &event, sizeof(event));
    
    return 0;
}

SEC("kprobe/tcp_close")
int BPF_KPROBE(tcp_close, struct sock *sk) {
    struct socket_key sock_key = {
        .pid = bpf_get_current_pid_tgid() >> 32,
        .socket_ptr = (__u64)sk,
    };
    
    struct connection_key *conn_key = bpf_map_lookup_elem(&socket_to_conn, &sock_key);
    if (conn_key) {
        bpf_map_delete_elem(&connections, conn_key);
        bpf_map_delete_elem(&socket_to_conn, &sock_key);
    }
    
    struct trace_event event = {};
    fill_common_info(&event);
    event.event_type = EVENT_CLOSE;
    event.saddr = BPF_CORE_READ(sk, sk_rcv_saddr);
    event.daddr = BPF_CORE_READ(sk, sk_daddr);
    event.sport = BPF_CORE_READ(sk, sk_num);
    event.dport = BPF_CORE_READ(sk, sk_dport);
    
    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &event, sizeof(event));
    
    return 0;
}

char _license[] SEC("license") = "GPL";
