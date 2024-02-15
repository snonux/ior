//+build ignore

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24);
} event_map SEC(".maps");

struct {
   __uint(type, BPF_MAP_TYPE_HASH);
   __type(key, u32);
   __type(value, struct flags);
   __uint(max_entries, 1 << 24);
} flags_map SEC(".maps");
