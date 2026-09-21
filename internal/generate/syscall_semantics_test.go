package generate

import (
	"fmt"
	"maps"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"slices"
	"sort"
	"strconv"
	"strings"
	"testing"

	iortypes "ior/internal/types"
)

type syscallSemantics struct {
	kind   string
	args   map[string]int
	ret    string
	family string
}

type syscallSemanticExpectation struct {
	kind      string
	args      map[string]int
	ret       string
	family    string
	temporary *temporarySyscallSemantics
}

type temporarySyscallSemantics struct {
	task    string
	current syscallSemantics
}

var (
	handlerRE         = regexp.MustCompile(`(?ms)^int handle_sys_(enter|exit)_([a-z0-9_]+)\([^)]*\) \{\n(.*?)^\}\n`)
	eventStructRE     = regexp.MustCompile(`struct ([a-z0-9_]+_event) \*ev = bpf_ringbuf_reserve`)
	kindCommentRE     = regexp.MustCompile(`(?m)^/// sys_enter_([a-z0-9_]+) is a struct [^\n]+ \(kind=([a-z0-9-]+)\)$`)
	resultEnterRE     = regexp.MustCompile(`(?m)^sys_enter_([a-z0-9_]+) is a struct `)
	directEventArgRE  = regexp.MustCompile(`(?m)^\s*ev->([a-z0-9_]+)\s*=.*ctx->args\[([0-9]+)\]`)
	pendingArgRE      = regexp.MustCompile(`(?m)^\s*pending\.([a-z0-9_]+)\s*=.*ctx->args\[([0-9]+)\]`)
	pendingFieldRE    = regexp.MustCompile(`(?m)^\s*pending\.([a-z0-9_]+)\s*=`)
	pendingRefRE      = regexp.MustCompile(`\bpending->([a-z0-9_]+)\b`)
	pendingUpdateRE   = regexp.MustCompile(`(?m)^\s*bpf_map_update_elem\(&([a-z0-9_]+),\s*&tid,\s*&pending,\s*BPF_ANY\);`)
	pendingLookupRE   = regexp.MustCompile(`(?m)^\s*struct [a-z0-9_]+ \*pending\s*=\s*bpf_map_lookup_elem\(&([a-z0-9_]+),\s*&tid\);`)
	stringReadArgRE   = regexp.MustCompile(`(?m)^\s*(?:if\s*\(\s*)?bpf_probe_read_user_str\(ev->([a-z0-9_]+),[^\n]*ctx->args\[([0-9]+)\]`)
	localArgRE        = regexp.MustCompile(`(?m)^\s*(?:[a-z_][a-z0-9_ ]+\s+)?([a-z_][a-z0-9_]*)\s*=.*ctx->args\[([0-9]+)\]`)
	localReadArgRE    = regexp.MustCompile(`(?m)^\s*(?:if\s*\(\s*)?bpf_probe_read_user\(&([a-z_][a-z0-9_]*),[^\n]*ctx->args\[([0-9]+)\]`)
	eventAssignmentRE = regexp.MustCompile(`(?m)^\s*ev->([a-z0-9_]+)\s*=([^;]+);`)
	timerAbstimeArgRE = regexp.MustCompile(`(?m)^\s*if\s*\(\s*\(\s*ctx->args\[([0-9]+)\]\s*&\s*1\s*\)\s*==\s*0\s*\)\s*\{\s*$`)
	retClassRE        = regexp.MustCompile(`(?m)^\s*ev->ret_type\s*=\s*([A-Z_]+);`)
	ringbufSubmitRE   = regexp.MustCompile(`(?m)^\s*bpf_ringbuf_submit\(ev,\s*0\);`)
	disabledIfZeroRE  = regexp.MustCompile(`(?ms)^\s*#if\s+0\s*$.*?^\s*#endif\s*$`)
)

// syscallSemanticExpectations is reviewed data from Linux syscall signatures.
// The ordinary fields describe the correct target semantics. A temporary value
// describes only what the committed artifact emits today; the named task must
// delete that override when it lands, making the already-recorded target live.
// Findings outside these four dimensions (for example, how raw flags render in
// userspace) do not need an override here.
var syscallSemanticExpectations = map[string]syscallSemanticExpectation{
	"accept": {kind: "accept", args: map[string]int{"fd": 0}, ret: "UNCLASSIFIED", family: "Network"},
	"accept4": {
		kind: "accept", args: map[string]int{"fd": 0, "flags": 3}, ret: "UNCLASSIFIED", family: "Network",
	},
	"access":          {kind: "pathname", args: map[string]int{"pathname": 0}, ret: "UNCLASSIFIED", family: "FS"},
	"acct":            {kind: "pathname", args: map[string]int{"pathname": 0}, ret: "UNCLASSIFIED", family: "Misc"},
	"add_key":         {kind: "keyctl", args: map[string]int{"key_serial": 4, "value": 3}, ret: "UNCLASSIFIED", family: "Security"},
	"adjtimex":        {kind: "null", args: map[string]int{}, ret: "UNCLASSIFIED", family: "Time"},
	"alarm":           {kind: "null", args: map[string]int{}, ret: "UNCLASSIFIED", family: "Time"},
	"arch_prctl":      {kind: "null", args: map[string]int{}, ret: "UNCLASSIFIED", family: "Process"},
	"bind":            {kind: "fd", args: map[string]int{"fd": 0}, ret: "UNCLASSIFIED", family: "Network"},
	"bpf":             {kind: "bpf", args: map[string]int{"cmd": 0}, ret: "UNCLASSIFIED", family: "Security"},
	"brk":             {kind: "mem", args: map[string]int{"addr": 0}, ret: "UNCLASSIFIED", family: "Memory"},
	"cachestat":       {kind: "fd", args: map[string]int{"fd": 0}, ret: "UNCLASSIFIED", family: "FS"},
	"capget":          {kind: "null", args: map[string]int{}, ret: "UNCLASSIFIED", family: "Security"},
	"capset":          {kind: "null", args: map[string]int{}, ret: "UNCLASSIFIED", family: "Security"},
	"chdir":           {kind: "pathname", args: map[string]int{"pathname": 0}, ret: "UNCLASSIFIED", family: "FS"},
	"chmod":           {kind: "pathname", args: map[string]int{"pathname": 0}, ret: "UNCLASSIFIED", family: "FS"},
	"chown":           {kind: "pathname", args: map[string]int{"pathname": 0}, ret: "UNCLASSIFIED", family: "FS"},
	"chroot":          {kind: "pathname", args: map[string]int{"pathname": 0}, ret: "UNCLASSIFIED", family: "FS"},
	"clock_adjtime":   {kind: "null", args: map[string]int{}, ret: "UNCLASSIFIED", family: "Time"},
	"clock_getres":    {kind: "null", args: map[string]int{}, ret: "UNCLASSIFIED", family: "Time"},
	"clock_gettime":   {kind: "null", args: map[string]int{}, ret: "UNCLASSIFIED", family: "Time"},
	"clock_nanosleep": {kind: "sleep", args: map[string]int{"flags": 1, "requested_ns": 2}, ret: "UNCLASSIFIED", family: "Time"},
	"clock_settime":   {kind: "null", args: map[string]int{}, ret: "UNCLASSIFIED", family: "Time"},
	"clone":           {kind: "proc", args: map[string]int{}, ret: "UNCLASSIFIED", family: "Process"},
	"clone3":          {kind: "proc", args: map[string]int{}, ret: "UNCLASSIFIED", family: "Process"},
	"close":           {kind: "fd", args: map[string]int{"fd": 0}, ret: "UNCLASSIFIED", family: "FS"},
	"close_range":     {kind: "two-fd", args: map[string]int{"extra": 2, "fd_a": 0, "fd_b": 1}, ret: "UNCLASSIFIED", family: "FS"},
	"connect":         {kind: "fd", args: map[string]int{"fd": 0}, ret: "UNCLASSIFIED", family: "Network"},
	// TODO(q4): delete temporary when transfer attribution consistently uses the destination fd.
	"copy_file_range": {kind: "fd", args: map[string]int{"fd": 2}, ret: "TRANSFER_CLASSIFIED", family: "FS", temporary: temporaryArgs("q4", map[string]int{"fd": 0})},
	"creat":           {kind: "pathname", args: map[string]int{"pathname": 0}, ret: "UNCLASSIFIED", family: "FS"},
	"delete_module":   {kind: "module", args: map[string]int{}, ret: "UNCLASSIFIED", family: "Security"},
	"dup":             {kind: "fd", args: map[string]int{"fd": 0}, ret: "UNCLASSIFIED", family: "FS"},
	"dup2":            {kind: "fd", args: map[string]int{"fd": 0}, ret: "UNCLASSIFIED", family: "FS"},
	"dup3":            {kind: "dup3", args: map[string]int{"fd": 0, "flags": 2}, ret: "UNCLASSIFIED", family: "FS"},
	"epoll_create":    {kind: "eventfd", args: map[string]int{}, ret: "UNCLASSIFIED", family: "Polling"},
	"epoll_create1":   {kind: "eventfd", args: map[string]int{"flags": 0}, ret: "UNCLASSIFIED", family: "Polling"},
	"epoll_ctl":       {kind: "epoll-ctl", args: map[string]int{"epfd": 0, "events": 3, "fd": 2, "op": 1}, ret: "UNCLASSIFIED", family: "Polling"},
	// TODO(t4): delete the epoll temporary overrides when fd/maxevents/timeout are captured together.
	"epoll_pwait": {
		kind: "poll", args: map[string]int{"fd": 0, "nfds": 2, "timeout_ns": 3}, ret: "UNCLASSIFIED", family: "Polling",
		temporary: &temporarySyscallSemantics{task: "t4", current: syscallSemantics{
			kind: "fd", args: map[string]int{"fd": 0},
		}},
	},
	"epoll_pwait2": {
		kind: "poll", args: map[string]int{"fd": 0, "nfds": 2, "timeout_ns": 3}, ret: "UNCLASSIFIED", family: "Polling",
		temporary: &temporarySyscallSemantics{task: "t4", current: syscallSemantics{
			kind: "fd", args: map[string]int{"fd": 0},
		}},
	},
	"epoll_wait": {
		kind: "poll", args: map[string]int{"fd": 0, "nfds": 2, "timeout_ns": 3}, ret: "UNCLASSIFIED", family: "Polling",
		temporary: &temporarySyscallSemantics{task: "t4", current: syscallSemantics{
			kind: "fd", args: map[string]int{"fd": 0},
		}},
	},
	"eventfd":       {kind: "eventfd", args: map[string]int{}, ret: "UNCLASSIFIED", family: "IPC"},
	"eventfd2":      {kind: "eventfd", args: map[string]int{"flags": 1}, ret: "UNCLASSIFIED", family: "IPC"},
	"execve":        {kind: "exec", args: map[string]int{"filename": 0}, ret: "UNCLASSIFIED", family: "Process"},
	"execveat":      {kind: "exec", args: map[string]int{"dirfd": 0, "filename": 1, "flags": 4}, ret: "UNCLASSIFIED", family: "Process"},
	"exit":          {kind: "null", args: map[string]int{}, ret: "NORETURN", family: "Process"},
	"exit_group":    {kind: "null", args: map[string]int{}, ret: "NORETURN", family: "Process"},
	"faccessat":     {kind: "pathname", args: map[string]int{"dirfd": 0, "pathname": 1}, ret: "UNCLASSIFIED", family: "FS"},
	"faccessat2":    {kind: "pathname", args: map[string]int{"dirfd": 0, "flags": 3, "pathname": 1}, ret: "UNCLASSIFIED", family: "FS"},
	"fadvise64":     {kind: "fd", args: map[string]int{"fd": 0}, ret: "UNCLASSIFIED", family: "FS"},
	"fallocate":     {kind: "fd", args: map[string]int{"fd": 0}, ret: "UNCLASSIFIED", family: "FS"},
	"fanotify_init": {kind: "eventfd", args: map[string]int{"flags": 0}, ret: "UNCLASSIFIED", family: "IPC"},
	"fanotify_mark": {
		kind: "fd-pathname", args: map[string]int{"dirfd": 3, "fd": 0, "flags": 1, "pathname": 4}, ret: "UNCLASSIFIED", family: "IPC",
	},
	"fchdir":    {kind: "fd", args: map[string]int{"fd": 0}, ret: "UNCLASSIFIED", family: "FS"},
	"fchmod":    {kind: "fd", args: map[string]int{"fd": 0}, ret: "UNCLASSIFIED", family: "FS"},
	"fchmodat":  {kind: "pathname", args: map[string]int{"dirfd": 0, "pathname": 1}, ret: "UNCLASSIFIED", family: "FS"},
	"fchmodat2": {kind: "pathname", args: map[string]int{"dirfd": 0, "flags": 3, "pathname": 1}, ret: "UNCLASSIFIED", family: "FS"},
	"fchown":    {kind: "fd", args: map[string]int{"fd": 0}, ret: "UNCLASSIFIED", family: "FS"},
	"fchownat":  {kind: "pathname", args: map[string]int{"dirfd": 0, "flags": 4, "pathname": 1}, ret: "UNCLASSIFIED", family: "FS"},
	"fcntl":     {kind: "fcntl", args: map[string]int{"arg": 2, "cmd": 1, "fd": 0}, ret: "UNCLASSIFIED", family: "FS"},
	"fdatasync": {kind: "fd", args: map[string]int{"fd": 0}, ret: "UNCLASSIFIED", family: "FS"},
	// TODO(q4): delete the xattr temporaryArgs overrides when size-probe inputs are captured.
	"fgetxattr":       {kind: "fd", args: map[string]int{"fd": 0, "size": 3}, ret: "READ_CLASSIFIED", family: "FS", temporary: temporaryArgs("q4", map[string]int{"fd": 0})},
	"file_getattr":    {kind: "pathname", args: map[string]int{"dirfd": 0, "flags": 4, "pathname": 1}, ret: "UNCLASSIFIED", family: "FS"},
	"file_setattr":    {kind: "pathname", args: map[string]int{"dirfd": 0, "flags": 4, "pathname": 1}, ret: "UNCLASSIFIED", family: "FS"},
	"finit_module":    {kind: "fd", args: map[string]int{"fd": 0}, ret: "UNCLASSIFIED", family: "Security"},
	"flistxattr":      {kind: "fd", args: map[string]int{"fd": 0, "size": 2}, ret: "READ_CLASSIFIED", family: "FS", temporary: temporaryArgs("q4", map[string]int{"fd": 0})},
	"flock":           {kind: "fd", args: map[string]int{"fd": 0}, ret: "UNCLASSIFIED", family: "FS"},
	"fork":            {kind: "proc", args: map[string]int{}, ret: "UNCLASSIFIED", family: "Process"},
	"fremovexattr":    {kind: "fd", args: map[string]int{"fd": 0}, ret: "UNCLASSIFIED", family: "FS"},
	"fsconfig":        {kind: "fd", args: map[string]int{"fd": 0}, ret: "UNCLASSIFIED", family: "FS"},
	"fsetxattr":       {kind: "fd", args: map[string]int{"fd": 0}, ret: "UNCLASSIFIED", family: "FS"},
	"fsmount":         {kind: "eventfd", args: map[string]int{"fd": 0, "flags": 1}, ret: "UNCLASSIFIED", family: "FS"},
	"fsopen":          {kind: "eventfd", args: map[string]int{"filename": 0, "flags": 1}, ret: "UNCLASSIFIED", family: "FS"},
	"fspick":          {kind: "pathname", args: map[string]int{"dirfd": 0, "flags": 2, "pathname": 1}, ret: "UNCLASSIFIED", family: "FS"},
	"fstatfs":         {kind: "fd", args: map[string]int{"fd": 0}, ret: "UNCLASSIFIED", family: "FS"},
	"fsync":           {kind: "fd", args: map[string]int{"fd": 0}, ret: "UNCLASSIFIED", family: "FS"},
	"ftruncate":       {kind: "fd", args: map[string]int{"fd": 0}, ret: "UNCLASSIFIED", family: "FS"},
	"futex":           {kind: "futex", args: map[string]int{}, ret: "UNCLASSIFIED", family: "IPC"},
	"futex_requeue":   {kind: "futex", args: map[string]int{}, ret: "UNCLASSIFIED", family: "IPC"},
	"futex_wait":      {kind: "futex", args: map[string]int{}, ret: "UNCLASSIFIED", family: "IPC"},
	"futex_waitv":     {kind: "futex", args: map[string]int{}, ret: "UNCLASSIFIED", family: "IPC"},
	"futex_wake":      {kind: "futex", args: map[string]int{}, ret: "UNCLASSIFIED", family: "IPC"},
	"futimesat":       {kind: "pathname", args: map[string]int{"dirfd": 0, "pathname": 1}, ret: "UNCLASSIFIED", family: "FS"},
	"get_mempolicy":   {kind: "null", args: map[string]int{}, ret: "UNCLASSIFIED", family: "Memory"},
	"get_robust_list": {kind: "null", args: map[string]int{}, ret: "UNCLASSIFIED", family: "Misc"},
	"getcpu":          {kind: "null", args: map[string]int{}, ret: "UNCLASSIFIED", family: "Misc"},
	// Raw getcwd returns the copied pathname byte count including its NUL.
	"getcwd":       {kind: "null", args: map[string]int{}, ret: "READ_CLASSIFIED", family: "FS"},
	"getdents":     {kind: "fd", args: map[string]int{"fd": 0}, ret: "READ_CLASSIFIED", family: "FS"},
	"getdents64":   {kind: "fd", args: map[string]int{"fd": 0}, ret: "READ_CLASSIFIED", family: "FS"},
	"getegid":      {kind: "null", args: map[string]int{}, ret: "UNCLASSIFIED", family: "Process"},
	"geteuid":      {kind: "null", args: map[string]int{}, ret: "UNCLASSIFIED", family: "Process"},
	"getgid":       {kind: "null", args: map[string]int{}, ret: "UNCLASSIFIED", family: "Process"},
	"getgroups":    {kind: "null", args: map[string]int{}, ret: "UNCLASSIFIED", family: "Process"},
	"getitimer":    {kind: "null", args: map[string]int{}, ret: "UNCLASSIFIED", family: "Time"},
	"getpeername":  {kind: "fd", args: map[string]int{"fd": 0}, ret: "UNCLASSIFIED", family: "Network"},
	"getpgid":      {kind: "null", args: map[string]int{}, ret: "UNCLASSIFIED", family: "Process"},
	"getpgrp":      {kind: "null", args: map[string]int{}, ret: "UNCLASSIFIED", family: "Process"},
	"getpid":       {kind: "null", args: map[string]int{}, ret: "UNCLASSIFIED", family: "Process"},
	"getppid":      {kind: "null", args: map[string]int{}, ret: "UNCLASSIFIED", family: "Process"},
	"getpriority":  {kind: "null", args: map[string]int{}, ret: "UNCLASSIFIED", family: "Process"},
	"getrandom":    {kind: "null", args: map[string]int{}, ret: "READ_CLASSIFIED", family: "Security"},
	"getresgid":    {kind: "null", args: map[string]int{}, ret: "UNCLASSIFIED", family: "Process"},
	"getresuid":    {kind: "null", args: map[string]int{}, ret: "UNCLASSIFIED", family: "Process"},
	"getrlimit":    {kind: "null", args: map[string]int{}, ret: "UNCLASSIFIED", family: "Process"},
	"getrusage":    {kind: "null", args: map[string]int{}, ret: "UNCLASSIFIED", family: "Process"},
	"getsid":       {kind: "null", args: map[string]int{}, ret: "UNCLASSIFIED", family: "Process"},
	"getsockname":  {kind: "fd", args: map[string]int{"fd": 0}, ret: "UNCLASSIFIED", family: "Network"},
	"getsockopt":   {kind: "fd", args: map[string]int{"fd": 0}, ret: "UNCLASSIFIED", family: "Network"},
	"gettid":       {kind: "null", args: map[string]int{}, ret: "UNCLASSIFIED", family: "Process"},
	"gettimeofday": {kind: "null", args: map[string]int{}, ret: "UNCLASSIFIED", family: "Time"},
	"getuid":       {kind: "null", args: map[string]int{}, ret: "UNCLASSIFIED", family: "Process"},
	"getxattr":     {kind: "pathname", args: map[string]int{"pathname": 0, "size": 3}, ret: "READ_CLASSIFIED", family: "FS", temporary: temporaryArgs("q4", map[string]int{"pathname": 0})},
	"getxattrat": {
		kind: "pathname", args: map[string]int{"dirfd": 0, "flags": 2, "pathname": 1, "size": 4}, ret: "READ_CLASSIFIED", family: "FS",
		temporary: &temporarySyscallSemantics{task: "q4", current: syscallSemantics{
			args: map[string]int{"dirfd": 0, "flags": 2, "pathname": 1},
		}},
	},
	"init_module": {kind: "module", args: map[string]int{}, ret: "UNCLASSIFIED", family: "Security"},
	"inotify_add_watch": {
		kind: "fd-pathname", args: map[string]int{"fd": 0, "pathname": 1}, ret: "UNCLASSIFIED", family: "IPC",
	},
	"inotify_init":            {kind: "eventfd", args: map[string]int{}, ret: "UNCLASSIFIED", family: "IPC"},
	"inotify_init1":           {kind: "eventfd", args: map[string]int{"flags": 0}, ret: "UNCLASSIFIED", family: "IPC"},
	"inotify_rm_watch":        {kind: "fd", args: map[string]int{"fd": 0}, ret: "UNCLASSIFIED", family: "IPC"},
	"io_cancel":               {kind: "null", args: map[string]int{}, ret: "UNCLASSIFIED", family: "AIO"},
	"io_destroy":              {kind: "null", args: map[string]int{}, ret: "UNCLASSIFIED", family: "AIO"},
	"io_getevents":            {kind: "null", args: map[string]int{}, ret: "UNCLASSIFIED", family: "AIO"},
	"io_pgetevents":           {kind: "null", args: map[string]int{}, ret: "UNCLASSIFIED", family: "AIO"},
	"io_setup":                {kind: "null", args: map[string]int{}, ret: "UNCLASSIFIED", family: "AIO"},
	"io_submit":               {kind: "null", args: map[string]int{}, ret: "UNCLASSIFIED", family: "AIO"},
	"io_uring_enter":          {kind: "fd", args: map[string]int{"fd": 0}, ret: "UNCLASSIFIED", family: "AIO"},
	"io_uring_register":       {kind: "fd", args: map[string]int{"fd": 0}, ret: "UNCLASSIFIED", family: "AIO"},
	"io_uring_setup":          {kind: "null", args: map[string]int{}, ret: "UNCLASSIFIED", family: "AIO"},
	"ioctl":                   {kind: "fd", args: map[string]int{"fd": 0}, ret: "UNCLASSIFIED", family: "FS"},
	"ioperm":                  {kind: "null", args: map[string]int{}, ret: "UNCLASSIFIED", family: "Misc"},
	"iopl":                    {kind: "null", args: map[string]int{}, ret: "UNCLASSIFIED", family: "Misc"},
	"ioprio_get":              {kind: "null", args: map[string]int{}, ret: "UNCLASSIFIED", family: "Process"},
	"ioprio_set":              {kind: "null", args: map[string]int{}, ret: "UNCLASSIFIED", family: "Process"},
	"kcmp":                    {kind: "two-fd", args: map[string]int{"extra": 2, "fd_a": 3, "fd_b": 4}, ret: "UNCLASSIFIED", family: "Process"},
	"kexec_file_load":         {kind: "fd", args: map[string]int{"fd": 0}, ret: "UNCLASSIFIED", family: "Security"},
	"kexec_load":              {kind: "null", args: map[string]int{}, ret: "UNCLASSIFIED", family: "Security"},
	"keyctl":                  {kind: "keyctl", args: map[string]int{"key_serial": 1, "option": 0, "value": 2}, ret: "UNCLASSIFIED", family: "Security"},
	"kill":                    {kind: "null", args: map[string]int{}, ret: "UNCLASSIFIED", family: "Signals"},
	"landlock_add_rule":       {kind: "fd", args: map[string]int{"fd": 0}, ret: "UNCLASSIFIED", family: "Security"},
	"landlock_create_ruleset": {kind: "eventfd", args: map[string]int{"flags": 2}, ret: "UNCLASSIFIED", family: "Security"},
	"landlock_restrict_self":  {kind: "fd", args: map[string]int{"fd": 0}, ret: "UNCLASSIFIED", family: "Security"},
	"lchown":                  {kind: "pathname", args: map[string]int{"pathname": 0}, ret: "UNCLASSIFIED", family: "FS"},
	"lgetxattr":               {kind: "pathname", args: map[string]int{"pathname": 0, "size": 3}, ret: "READ_CLASSIFIED", family: "FS", temporary: temporaryArgs("q4", map[string]int{"pathname": 0})},
	"link":                    {kind: "name", args: map[string]int{"newname": 1, "oldname": 0}, ret: "UNCLASSIFIED", family: "FS"},
	"linkat":                  {kind: "name", args: map[string]int{"flags": 4, "newdirfd": 2, "newname": 3, "olddirfd": 0, "oldname": 1}, ret: "UNCLASSIFIED", family: "FS"},
	"listen":                  {kind: "fd", args: map[string]int{"fd": 0}, ret: "UNCLASSIFIED", family: "Network"},
	"listmount":               {kind: "null", args: map[string]int{}, ret: "UNCLASSIFIED", family: "FS"},
	"listns":                  {kind: "null", args: map[string]int{}, ret: "UNCLASSIFIED", family: "FS"},
	"listxattr":               {kind: "pathname", args: map[string]int{"pathname": 0, "size": 2}, ret: "READ_CLASSIFIED", family: "FS", temporary: temporaryArgs("q4", map[string]int{"pathname": 0})},
	"listxattrat": {
		kind: "pathname", args: map[string]int{"dirfd": 0, "flags": 2, "pathname": 1, "size": 4}, ret: "READ_CLASSIFIED", family: "FS",
		temporary: &temporarySyscallSemantics{task: "q4", current: syscallSemantics{
			args: map[string]int{"dirfd": 0, "flags": 2, "pathname": 1},
		}},
	},
	"llistxattr":        {kind: "pathname", args: map[string]int{"pathname": 0, "size": 2}, ret: "READ_CLASSIFIED", family: "FS", temporary: temporaryArgs("q4", map[string]int{"pathname": 0})},
	"lremovexattr":      {kind: "pathname", args: map[string]int{"pathname": 0}, ret: "UNCLASSIFIED", family: "FS"},
	"lseek":             {kind: "fd", args: map[string]int{"fd": 0}, ret: "UNCLASSIFIED", family: "FS"},
	"lsetxattr":         {kind: "pathname", args: map[string]int{"pathname": 0}, ret: "UNCLASSIFIED", family: "FS"},
	"lsm_get_self_attr": {kind: "null", args: map[string]int{}, ret: "UNCLASSIFIED", family: "Security"},
	"lsm_list_modules":  {kind: "null", args: map[string]int{}, ret: "UNCLASSIFIED", family: "Security"},
	"lsm_set_self_attr": {kind: "null", args: map[string]int{}, ret: "UNCLASSIFIED", family: "Security"},
	"madvise":           {kind: "mem", args: map[string]int{"addr": 0, "flags": 2, "length": 1}, ret: "UNCLASSIFIED", family: "Memory"},
	"map_shadow_stack":  {kind: "mem", args: map[string]int{"addr": 0, "flags": 2, "length": 1}, ret: "UNCLASSIFIED", family: "Memory"},
	"mbind":             {kind: "null", args: map[string]int{}, ret: "UNCLASSIFIED", family: "Memory"},
	"membarrier":        {kind: "null", args: map[string]int{}, ret: "UNCLASSIFIED", family: "Memory"},
	"memfd_create":      {kind: "eventfd", args: map[string]int{"filename": 0, "flags": 1}, ret: "UNCLASSIFIED", family: "IPC"},
	"memfd_secret":      {kind: "eventfd", args: map[string]int{"flags": 0}, ret: "UNCLASSIFIED", family: "IPC"},
	"migrate_pages":     {kind: "null", args: map[string]int{}, ret: "UNCLASSIFIED", family: "Memory"},
	"mincore":           {kind: "mem", args: map[string]int{"addr": 0, "length": 1}, ret: "UNCLASSIFIED", family: "Memory"},
	"mkdir":             {kind: "pathname", args: map[string]int{"pathname": 0}, ret: "UNCLASSIFIED", family: "FS"},
	"mkdirat":           {kind: "pathname", args: map[string]int{"dirfd": 0, "pathname": 1}, ret: "UNCLASSIFIED", family: "FS"},
	"mknod":             {kind: "pathname", args: map[string]int{"pathname": 0}, ret: "UNCLASSIFIED", family: "FS"},
	"mknodat":           {kind: "pathname", args: map[string]int{"dirfd": 0, "pathname": 1}, ret: "UNCLASSIFIED", family: "FS"},
	"mlock":             {kind: "mem", args: map[string]int{"addr": 0, "length": 1}, ret: "UNCLASSIFIED", family: "Memory"},
	"mlock2":            {kind: "mem", args: map[string]int{"addr": 0, "flags": 2, "length": 1}, ret: "UNCLASSIFIED", family: "Memory"},
	"mlockall":          {kind: "null", args: map[string]int{}, ret: "UNCLASSIFIED", family: "Memory"},
	"mmap": {
		kind: "mmap", args: map[string]int{"addr": 0, "fd": 4, "flags": 3, "length": 1, "prot": 2}, ret: "UNCLASSIFIED", family: "Memory",
	},
	"modify_ldt":    {kind: "null", args: map[string]int{}, ret: "UNCLASSIFIED", family: "Misc"},
	"mount":         {kind: "pathname", args: map[string]int{"pathname": 1}, ret: "UNCLASSIFIED", family: "FS"},
	"mount_setattr": {kind: "pathname", args: map[string]int{"dirfd": 0, "flags": 2, "pathname": 1}, ret: "UNCLASSIFIED", family: "FS"},
	"move_mount": {
		kind: "two-fd", args: map[string]int{"extra": 4, "fd_a": 0, "fd_b": 2, "newname": 3, "oldname": 1}, ret: "UNCLASSIFIED", family: "FS",
	},
	"move_pages":      {kind: "null", args: map[string]int{}, ret: "UNCLASSIFIED", family: "Memory"},
	"mprotect":        {kind: "mem", args: map[string]int{"addr": 0, "flags": 2, "length": 1}, ret: "UNCLASSIFIED", family: "Memory"},
	"mq_getsetattr":   {kind: "fd", args: map[string]int{"fd": 0}, ret: "UNCLASSIFIED", family: "IPC"},
	"mq_notify":       {kind: "fd", args: map[string]int{"fd": 0}, ret: "UNCLASSIFIED", family: "IPC"},
	"mq_open":         {kind: "mq-open", args: map[string]int{"filename": 0, "flags": 1}, ret: "UNCLASSIFIED", family: "IPC"},
	"mq_timedreceive": {kind: "fd", args: map[string]int{"fd": 0}, ret: "READ_CLASSIFIED", family: "IPC"},
	"mq_timedsend":    {kind: "fd", args: map[string]int{"fd": 0}, ret: "UNCLASSIFIED", family: "IPC"},
	"mq_unlink":       {kind: "pathname", args: map[string]int{"pathname": 0}, ret: "UNCLASSIFIED", family: "IPC"},
	"mremap":          {kind: "mem", args: map[string]int{"addr": 0, "flags": 3, "length": 1, "length2": 2}, ret: "UNCLASSIFIED", family: "Memory"},
	"mseal":           {kind: "mem", args: map[string]int{"addr": 0, "flags": 2, "length": 1}, ret: "UNCLASSIFIED", family: "Memory"},
	"msgctl":          {kind: "sysv-op", args: map[string]int{}, ret: "UNCLASSIFIED", family: "IPC"},
	"msgget":          {kind: "sysv-id", args: map[string]int{}, ret: "UNCLASSIFIED", family: "IPC"},
	"msgrcv":          {kind: "sysv-op", args: map[string]int{}, ret: "READ_CLASSIFIED", family: "IPC"},
	"msgsnd":          {kind: "sysv-op", args: map[string]int{}, ret: "UNCLASSIFIED", family: "IPC"},
	"msync": {
		kind: "mem", args: map[string]int{"addr": 0, "flags": 2, "length": 1}, ret: "UNCLASSIFIED", family: "FS",
	},
	"munlock":           {kind: "mem", args: map[string]int{"addr": 0, "length": 1}, ret: "UNCLASSIFIED", family: "Memory"},
	"munlockall":        {kind: "null", args: map[string]int{}, ret: "UNCLASSIFIED", family: "Memory"},
	"munmap":            {kind: "mem", args: map[string]int{"addr": 0, "length": 1}, ret: "UNCLASSIFIED", family: "Memory"},
	"name_to_handle_at": {kind: "pathname", args: map[string]int{"dirfd": 0, "flags": 4, "pathname": 1}, ret: "UNCLASSIFIED", family: "FS"},
	"nanosleep":         {kind: "sleep", args: map[string]int{"requested_ns": 0}, ret: "UNCLASSIFIED", family: "Time"},
	"newfstat":          {kind: "fd", args: map[string]int{"fd": 0}, ret: "UNCLASSIFIED", family: "FS"},
	"newfstatat":        {kind: "pathname", args: map[string]int{"dirfd": 0, "flags": 3, "pathname": 1}, ret: "UNCLASSIFIED", family: "FS"},
	"newlstat":          {kind: "pathname", args: map[string]int{"pathname": 0}, ret: "UNCLASSIFIED", family: "FS"},
	"newstat":           {kind: "pathname", args: map[string]int{"pathname": 0}, ret: "UNCLASSIFIED", family: "FS"},
	"newuname":          {kind: "null", args: map[string]int{}, ret: "UNCLASSIFIED", family: "Misc"},
	"open":              {kind: "open", args: map[string]int{"filename": 0, "flags": 1}, ret: "UNCLASSIFIED", family: "FS"},
	"open_by_handle_at": {kind: "open-by-handle-at", args: map[string]int{"flags": 2}, ret: "UNCLASSIFIED", family: "FS"},
	"open_tree":         {kind: "open-tree", args: map[string]int{"dirfd": 0, "filename": 1, "flags": 2}, ret: "UNCLASSIFIED", family: "FS"},
	"open_tree_attr":    {kind: "open-tree", args: map[string]int{"dirfd": 0, "filename": 1, "flags": 2}, ret: "UNCLASSIFIED", family: "FS"},
	"openat":            {kind: "open", args: map[string]int{"dirfd": 0, "filename": 1, "flags": 2}, ret: "UNCLASSIFIED", family: "FS"},
	"openat2": {
		kind: "open", args: map[string]int{"dirfd": 0, "filename": 1, "flags": 2}, ret: "UNCLASSIFIED", family: "FS",
	},
	"pause":                  {kind: "null", args: map[string]int{}, ret: "UNCLASSIFIED", family: "Signals"},
	"perf_event_open":        {kind: "perf-open", args: map[string]int{"attr_size": 0, "attr_type": 0, "config": 0, "cpu": 2, "flags": 4, "group_fd": 3, "target_pid": 1}, ret: "UNCLASSIFIED", family: "Security"},
	"personality":            {kind: "null", args: map[string]int{}, ret: "UNCLASSIFIED", family: "Process"},
	"pidfd_getfd":            {kind: "fd", args: map[string]int{"fd": 0}, ret: "UNCLASSIFIED", family: "IPC"},
	"pidfd_open":             {kind: "pidfd", args: map[string]int{"flags": 1}, ret: "UNCLASSIFIED", family: "IPC"},
	"pidfd_send_signal":      {kind: "fd", args: map[string]int{"fd": 0}, ret: "UNCLASSIFIED", family: "IPC"},
	"pipe":                   {kind: "pipe", args: map[string]int{"upipefd": 0}, ret: "UNCLASSIFIED", family: "IPC"},
	"pipe2":                  {kind: "pipe", args: map[string]int{"flags": 1, "upipefd": 0}, ret: "UNCLASSIFIED", family: "IPC"},
	"pivot_root":             {kind: "pathname", args: map[string]int{"pathname": 0}, ret: "UNCLASSIFIED", family: "Process"},
	"pkey_alloc":             {kind: "null", args: map[string]int{}, ret: "UNCLASSIFIED", family: "Memory"},
	"pkey_free":              {kind: "null", args: map[string]int{}, ret: "UNCLASSIFIED", family: "Memory"},
	"pkey_mprotect":          {kind: "mem", args: map[string]int{"addr": 0, "flags": 2, "length": 1, "length2": 3}, ret: "UNCLASSIFIED", family: "Memory"},
	"poll":                   {kind: "poll", args: map[string]int{"nfds": 1, "timeout_ns": 2}, ret: "UNCLASSIFIED", family: "Polling"},
	"ppoll":                  {kind: "poll", args: map[string]int{"nfds": 1, "timeout_ns": 2}, ret: "UNCLASSIFIED", family: "Polling"},
	"prctl":                  {kind: "prctl", args: map[string]int{}, ret: "UNCLASSIFIED", family: "Process"},
	"pread64":                {kind: "fd", args: map[string]int{"fd": 0}, ret: "READ_CLASSIFIED", family: "FS"},
	"preadv":                 {kind: "fd", args: map[string]int{"fd": 0}, ret: "READ_CLASSIFIED", family: "FS"},
	"preadv2":                {kind: "fd", args: map[string]int{"fd": 0}, ret: "READ_CLASSIFIED", family: "FS"},
	"prlimit64":              {kind: "null", args: map[string]int{}, ret: "UNCLASSIFIED", family: "Process"},
	"process_madvise":        {kind: "fd", args: map[string]int{"fd": 0}, ret: "UNCLASSIFIED", family: "Memory"},
	"process_mrelease":       {kind: "fd", args: map[string]int{"fd": 0}, ret: "UNCLASSIFIED", family: "Memory"},
	"process_vm_readv":       {kind: "null", args: map[string]int{}, ret: "READ_CLASSIFIED", family: "Memory"},
	"process_vm_writev":      {kind: "null", args: map[string]int{}, ret: "WRITE_CLASSIFIED", family: "Memory"},
	"pselect6":               {kind: "poll", args: map[string]int{"nfds": 0, "timeout_ns": 4}, ret: "UNCLASSIFIED", family: "Polling"},
	"ptrace":                 {kind: "ptrace", args: map[string]int{"data": 3, "request": 0, "target_pid": 1}, ret: "UNCLASSIFIED", family: "Security"},
	"pwrite64":               {kind: "fd", args: map[string]int{"fd": 0}, ret: "WRITE_CLASSIFIED", family: "FS"},
	"pwritev":                {kind: "fd", args: map[string]int{"fd": 0}, ret: "WRITE_CLASSIFIED", family: "FS"},
	"pwritev2":               {kind: "fd", args: map[string]int{"fd": 0}, ret: "WRITE_CLASSIFIED", family: "FS"},
	"quotactl":               {kind: "pathname", args: map[string]int{"pathname": 1}, ret: "UNCLASSIFIED", family: "FS"},
	"quotactl_fd":            {kind: "fd", args: map[string]int{"fd": 0}, ret: "UNCLASSIFIED", family: "FS"},
	"read":                   {kind: "fd", args: map[string]int{"fd": 0}, ret: "READ_CLASSIFIED", family: "FS"},
	"readahead":              {kind: "fd", args: map[string]int{"fd": 0}, ret: "UNCLASSIFIED", family: "FS"},
	"readlink":               {kind: "pathname", args: map[string]int{"pathname": 0}, ret: "READ_CLASSIFIED", family: "FS"},
	"readlinkat":             {kind: "pathname", args: map[string]int{"dirfd": 0, "pathname": 1}, ret: "READ_CLASSIFIED", family: "FS"},
	"readv":                  {kind: "fd", args: map[string]int{"fd": 0}, ret: "READ_CLASSIFIED", family: "FS"},
	"reboot":                 {kind: "null", args: map[string]int{}, ret: "UNCLASSIFIED", family: "Process"},
	"recvfrom":               {kind: "fd", args: map[string]int{"fd": 0}, ret: "READ_CLASSIFIED", family: "Network"},
	"recvmmsg":               {kind: "fd", args: map[string]int{"fd": 0}, ret: "UNCLASSIFIED", family: "Network"},
	"recvmsg":                {kind: "fd", args: map[string]int{"fd": 0}, ret: "READ_CLASSIFIED", family: "Network"},
	"remap_file_pages":       {kind: "mem", args: map[string]int{"addr": 0, "flags": 4, "length": 1, "length2": 3}, ret: "UNCLASSIFIED", family: "Memory"},
	"removexattr":            {kind: "pathname", args: map[string]int{"pathname": 0}, ret: "UNCLASSIFIED", family: "FS"},
	"removexattrat":          {kind: "pathname", args: map[string]int{"dirfd": 0, "flags": 2, "pathname": 1}, ret: "UNCLASSIFIED", family: "FS"},
	"rename":                 {kind: "name", args: map[string]int{"newname": 1, "oldname": 0}, ret: "UNCLASSIFIED", family: "FS"},
	"renameat":               {kind: "name", args: map[string]int{"newdirfd": 2, "newname": 3, "olddirfd": 0, "oldname": 1}, ret: "UNCLASSIFIED", family: "FS"},
	"renameat2":              {kind: "name", args: map[string]int{"newdirfd": 2, "newname": 3, "olddirfd": 0, "oldname": 1}, ret: "UNCLASSIFIED", family: "FS"},
	"request_key":            {kind: "keyctl", args: map[string]int{"key_serial": 3}, ret: "UNCLASSIFIED", family: "Security"},
	"restart_syscall":        {kind: "null", args: map[string]int{}, ret: "UNCLASSIFIED", family: "Process"},
	"rmdir":                  {kind: "pathname", args: map[string]int{"pathname": 0}, ret: "UNCLASSIFIED", family: "FS"},
	"rseq":                   {kind: "null", args: map[string]int{}, ret: "UNCLASSIFIED", family: "Misc"},
	"rt_sigaction":           {kind: "null", args: map[string]int{}, ret: "UNCLASSIFIED", family: "Signals"},
	"rt_sigpending":          {kind: "null", args: map[string]int{}, ret: "UNCLASSIFIED", family: "Signals"},
	"rt_sigprocmask":         {kind: "null", args: map[string]int{}, ret: "UNCLASSIFIED", family: "Signals"},
	"rt_sigqueueinfo":        {kind: "null", args: map[string]int{}, ret: "UNCLASSIFIED", family: "Signals"},
	"rt_sigreturn":           {kind: "null", args: map[string]int{}, ret: "NORETURN", family: "Signals"},
	"rt_sigsuspend":          {kind: "null", args: map[string]int{}, ret: "UNCLASSIFIED", family: "Signals"},
	"rt_sigtimedwait":        {kind: "null", args: map[string]int{}, ret: "UNCLASSIFIED", family: "Signals"},
	"rt_tgsigqueueinfo":      {kind: "null", args: map[string]int{}, ret: "UNCLASSIFIED", family: "Signals"},
	"sched_get_priority_max": {kind: "null", args: map[string]int{}, ret: "UNCLASSIFIED", family: "Sched"},
	"sched_get_priority_min": {kind: "null", args: map[string]int{}, ret: "UNCLASSIFIED", family: "Sched"},
	// Raw sched_getaffinity returns the number of mask bytes copied.
	"sched_getaffinity":       {kind: "null", args: map[string]int{}, ret: "READ_CLASSIFIED", family: "Sched"},
	"sched_getattr":           {kind: "null", args: map[string]int{}, ret: "UNCLASSIFIED", family: "Sched"},
	"sched_getparam":          {kind: "null", args: map[string]int{}, ret: "UNCLASSIFIED", family: "Sched"},
	"sched_getscheduler":      {kind: "null", args: map[string]int{}, ret: "UNCLASSIFIED", family: "Sched"},
	"sched_rr_get_interval":   {kind: "null", args: map[string]int{}, ret: "UNCLASSIFIED", family: "Sched"},
	"sched_setaffinity":       {kind: "null", args: map[string]int{}, ret: "UNCLASSIFIED", family: "Sched"},
	"sched_setattr":           {kind: "null", args: map[string]int{}, ret: "UNCLASSIFIED", family: "Sched"},
	"sched_setparam":          {kind: "null", args: map[string]int{}, ret: "UNCLASSIFIED", family: "Sched"},
	"sched_setscheduler":      {kind: "null", args: map[string]int{}, ret: "UNCLASSIFIED", family: "Sched"},
	"sched_yield":             {kind: "null", args: map[string]int{}, ret: "UNCLASSIFIED", family: "Sched"},
	"seccomp":                 {kind: "seccomp", args: map[string]int{}, ret: "UNCLASSIFIED", family: "Security"},
	"select":                  {kind: "poll", args: map[string]int{"nfds": 0, "timeout_ns": 4}, ret: "UNCLASSIFIED", family: "Polling"},
	"semctl":                  {kind: "sysv-op", args: map[string]int{}, ret: "UNCLASSIFIED", family: "IPC"},
	"semget":                  {kind: "sysv-id", args: map[string]int{}, ret: "UNCLASSIFIED", family: "IPC"},
	"semop":                   {kind: "sysv-op", args: map[string]int{}, ret: "UNCLASSIFIED", family: "IPC"},
	"semtimedop":              {kind: "sysv-op", args: map[string]int{}, ret: "UNCLASSIFIED", family: "IPC"},
	"sendfile64":              {kind: "fd", args: map[string]int{"fd": 0}, ret: "TRANSFER_CLASSIFIED", family: "Network"},
	"sendmmsg":                {kind: "fd", args: map[string]int{"fd": 0}, ret: "UNCLASSIFIED", family: "Network"},
	"sendmsg":                 {kind: "fd", args: map[string]int{"fd": 0}, ret: "WRITE_CLASSIFIED", family: "Network"},
	"sendto":                  {kind: "fd", args: map[string]int{"fd": 0}, ret: "WRITE_CLASSIFIED", family: "Network"},
	"set_mempolicy":           {kind: "null", args: map[string]int{}, ret: "UNCLASSIFIED", family: "Memory"},
	"set_mempolicy_home_node": {kind: "null", args: map[string]int{}, ret: "UNCLASSIFIED", family: "Memory"},
	"set_robust_list":         {kind: "null", args: map[string]int{}, ret: "UNCLASSIFIED", family: "Misc"},
	"set_tid_address":         {kind: "null", args: map[string]int{}, ret: "UNCLASSIFIED", family: "Process"},
	"setdomainname":           {kind: "null", args: map[string]int{}, ret: "UNCLASSIFIED", family: "Misc"},
	"setfsgid":                {kind: "null", args: map[string]int{}, ret: "UNCLASSIFIED", family: "Process"},
	"setfsuid":                {kind: "null", args: map[string]int{}, ret: "UNCLASSIFIED", family: "Process"},
	"setgid":                  {kind: "null", args: map[string]int{}, ret: "UNCLASSIFIED", family: "Process"},
	"setgroups":               {kind: "null", args: map[string]int{}, ret: "UNCLASSIFIED", family: "Process"},
	"sethostname":             {kind: "null", args: map[string]int{}, ret: "UNCLASSIFIED", family: "Misc"},
	"setitimer":               {kind: "null", args: map[string]int{}, ret: "UNCLASSIFIED", family: "Time"},
	"setns":                   {kind: "fd", args: map[string]int{"fd": 0}, ret: "UNCLASSIFIED", family: "Process"},
	"setpgid":                 {kind: "null", args: map[string]int{}, ret: "UNCLASSIFIED", family: "Process"},
	"setpriority":             {kind: "null", args: map[string]int{}, ret: "UNCLASSIFIED", family: "Process"},
	"setregid":                {kind: "null", args: map[string]int{}, ret: "UNCLASSIFIED", family: "Process"},
	"setresgid":               {kind: "null", args: map[string]int{}, ret: "UNCLASSIFIED", family: "Process"},
	"setresuid":               {kind: "null", args: map[string]int{}, ret: "UNCLASSIFIED", family: "Process"},
	"setreuid":                {kind: "null", args: map[string]int{}, ret: "UNCLASSIFIED", family: "Process"},
	"setrlimit":               {kind: "null", args: map[string]int{}, ret: "UNCLASSIFIED", family: "Process"},
	"setsid":                  {kind: "null", args: map[string]int{}, ret: "UNCLASSIFIED", family: "Process"},
	"setsockopt":              {kind: "fd", args: map[string]int{"fd": 0}, ret: "UNCLASSIFIED", family: "Network"},
	"settimeofday":            {kind: "null", args: map[string]int{}, ret: "UNCLASSIFIED", family: "Time"},
	"setuid":                  {kind: "null", args: map[string]int{}, ret: "UNCLASSIFIED", family: "Process"},
	"setxattr":                {kind: "pathname", args: map[string]int{"pathname": 0}, ret: "UNCLASSIFIED", family: "FS"},
	"setxattrat":              {kind: "pathname", args: map[string]int{"dirfd": 0, "flags": 2, "pathname": 1}, ret: "UNCLASSIFIED", family: "FS"},
	"shmat":                   {kind: "sysv-op", args: map[string]int{}, ret: "UNCLASSIFIED", family: "IPC"},
	"shmctl":                  {kind: "sysv-op", args: map[string]int{}, ret: "UNCLASSIFIED", family: "IPC"},
	"shmdt":                   {kind: "sysv-op", args: map[string]int{}, ret: "UNCLASSIFIED", family: "IPC"},
	"shmget":                  {kind: "sysv-id", args: map[string]int{}, ret: "UNCLASSIFIED", family: "IPC"},
	"shutdown":                {kind: "fd", args: map[string]int{"fd": 0}, ret: "UNCLASSIFIED", family: "Network"},
	"sigaltstack":             {kind: "null", args: map[string]int{}, ret: "UNCLASSIFIED", family: "Signals"},
	"signalfd":                {kind: "eventfd", args: map[string]int{"fd": 0}, ret: "UNCLASSIFIED", family: "IPC"},
	"signalfd4":               {kind: "eventfd", args: map[string]int{"fd": 0, "flags": 3}, ret: "UNCLASSIFIED", family: "IPC"},
	"socket":                  {kind: "socket", args: map[string]int{"family": 0, "protocol": 2, "type": 1}, ret: "UNCLASSIFIED", family: "Network"},
	"socketpair":              {kind: "socketpair", args: map[string]int{"family": 0, "protocol": 2, "type": 1, "usockvec": 3}, ret: "UNCLASSIFIED", family: "Network"},
	"splice":                  {kind: "fd", args: map[string]int{"fd": 2}, ret: "TRANSFER_CLASSIFIED", family: "Network", temporary: temporaryArgs("q4", map[string]int{"fd": 0})},
	"statfs":                  {kind: "pathname", args: map[string]int{"pathname": 0}, ret: "UNCLASSIFIED", family: "FS"},
	"statmount":               {kind: "null", args: map[string]int{}, ret: "UNCLASSIFIED", family: "FS"},
	"statx":                   {kind: "pathname", args: map[string]int{"dirfd": 0, "flags": 2, "pathname": 1}, ret: "UNCLASSIFIED", family: "FS"},
	"swapoff":                 {kind: "pathname", args: map[string]int{"pathname": 0}, ret: "UNCLASSIFIED", family: "FS"},
	"swapon":                  {kind: "pathname", args: map[string]int{"pathname": 0}, ret: "UNCLASSIFIED", family: "FS"},
	"symlink":                 {kind: "name", args: map[string]int{"newname": 1, "oldname": 0}, ret: "UNCLASSIFIED", family: "FS"},
	"symlinkat":               {kind: "name", args: map[string]int{"newdirfd": 1, "newname": 2, "oldname": 0}, ret: "UNCLASSIFIED", family: "FS"},
	"sync":                    {kind: "null", args: map[string]int{}, ret: "UNCLASSIFIED", family: "FS"},
	"sync_file_range":         {kind: "fd", args: map[string]int{"fd": 0}, ret: "UNCLASSIFIED", family: "FS"},
	"syncfs":                  {kind: "fd", args: map[string]int{"fd": 0}, ret: "UNCLASSIFIED", family: "FS"},
	"sysfs":                   {kind: "null", args: map[string]int{}, ret: "UNCLASSIFIED", family: "Misc"},
	"sysinfo":                 {kind: "null", args: map[string]int{}, ret: "UNCLASSIFIED", family: "Misc"},
	// TODO(q4): delete temporary when syslog stops classifying status/size returns as bytes read.
	"syslog": {
		kind: "null", args: map[string]int{}, ret: "UNCLASSIFIED", family: "Misc",
		temporary: &temporarySyscallSemantics{task: "q4", current: syscallSemantics{
			ret: "READ_CLASSIFIED",
		}},
	},
	"tee":              {kind: "fd", args: map[string]int{"fd": 1}, ret: "TRANSFER_CLASSIFIED", family: "Network", temporary: temporaryArgs("q4", map[string]int{"fd": 0})},
	"tgkill":           {kind: "null", args: map[string]int{}, ret: "UNCLASSIFIED", family: "Signals"},
	"time":             {kind: "null", args: map[string]int{}, ret: "UNCLASSIFIED", family: "Time"},
	"timer_create":     {kind: "timer-obj", args: map[string]int{}, ret: "UNCLASSIFIED", family: "Time"},
	"timer_delete":     {kind: "timer-obj", args: map[string]int{}, ret: "UNCLASSIFIED", family: "Time"},
	"timer_getoverrun": {kind: "timer-obj", args: map[string]int{}, ret: "UNCLASSIFIED", family: "Time"},
	"timer_gettime":    {kind: "timer-obj", args: map[string]int{}, ret: "UNCLASSIFIED", family: "Time"},
	"timer_settime":    {kind: "timer-obj", args: map[string]int{}, ret: "UNCLASSIFIED", family: "Time"},
	"timerfd_create":   {kind: "eventfd", args: map[string]int{"flags": 1}, ret: "UNCLASSIFIED", family: "IPC"},
	"timerfd_gettime":  {kind: "fd", args: map[string]int{"fd": 0}, ret: "UNCLASSIFIED", family: "IPC"},
	"timerfd_settime":  {kind: "fd", args: map[string]int{"fd": 0}, ret: "UNCLASSIFIED", family: "IPC"},
	"times":            {kind: "null", args: map[string]int{}, ret: "UNCLASSIFIED", family: "Time"},
	"tkill":            {kind: "null", args: map[string]int{}, ret: "UNCLASSIFIED", family: "Signals"},
	"truncate":         {kind: "pathname", args: map[string]int{"pathname": 0}, ret: "UNCLASSIFIED", family: "FS"},
	"umask":            {kind: "null", args: map[string]int{}, ret: "UNCLASSIFIED", family: "Process"},
	"umount":           {kind: "pathname", args: map[string]int{"pathname": 0}, ret: "UNCLASSIFIED", family: "FS"},
	"unlink":           {kind: "pathname", args: map[string]int{"pathname": 0}, ret: "UNCLASSIFIED", family: "FS"},
	"unlinkat":         {kind: "pathname", args: map[string]int{"dirfd": 0, "pathname": 1}, ret: "UNCLASSIFIED", family: "FS"},
	"unshare":          {kind: "null", args: map[string]int{}, ret: "UNCLASSIFIED", family: "Process"},
	"uprobe":           {kind: "null", args: map[string]int{}, ret: "UNCLASSIFIED", family: "Misc"},
	"uretprobe":        {kind: "null", args: map[string]int{}, ret: "UNCLASSIFIED", family: "Misc"},
	"userfaultfd":      {kind: "eventfd", args: map[string]int{"flags": 0}, ret: "UNCLASSIFIED", family: "IPC"},
	"ustat":            {kind: "null", args: map[string]int{}, ret: "UNCLASSIFIED", family: "FS"},
	"utime":            {kind: "pathname", args: map[string]int{"pathname": 0}, ret: "UNCLASSIFIED", family: "FS"},
	"utimensat":        {kind: "pathname", args: map[string]int{"dirfd": 0, "flags": 3, "pathname": 1}, ret: "UNCLASSIFIED", family: "FS"},
	"utimes":           {kind: "pathname", args: map[string]int{"pathname": 0}, ret: "UNCLASSIFIED", family: "FS"},
	"vfork":            {kind: "proc", args: map[string]int{}, ret: "UNCLASSIFIED", family: "Process"},
	"vhangup":          {kind: "null", args: map[string]int{}, ret: "UNCLASSIFIED", family: "Process"},
	"vmsplice":         {kind: "fd", args: map[string]int{"fd": 0}, ret: "TRANSFER_CLASSIFIED", family: "Network"},
	"wait4":            {kind: "proc", args: map[string]int{}, ret: "UNCLASSIFIED", family: "Process"},
	"waitid":           {kind: "proc", args: map[string]int{}, ret: "UNCLASSIFIED", family: "Process"},
	"write":            {kind: "fd", args: map[string]int{"fd": 0}, ret: "WRITE_CLASSIFIED", family: "FS"},
	"writev":           {kind: "fd", args: map[string]int{"fd": 0}, ret: "WRITE_CLASSIFIED", family: "FS"},
}

// pendingArrayOutputExpectations independently pins output arrays whose source
// pointer must produce multiple event fields. Do not derive these destinations
// or their arity from the generated C array declarations.
var pendingArrayOutputExpectations = map[string]map[string][]string{
	"pipe":       {"upipefd": {"fd0", "fd1"}},
	"pipe2":      {"upipefd": {"fd0", "fd1"}},
	"socketpair": {"usockvec": {"sv0", "sv1"}},
}

var filenameFallbackSyscalls = map[string]struct{}{
	"fsopen":         {},
	"memfd_create":   {},
	"mq_open":        {},
	"open":           {},
	"open_tree":      {},
	"open_tree_attr": {},
	"openat":         {},
	"openat2":        {},
}

func TestGeneratedSyscallSemanticsMatchReviewedExpectations(t *testing.T) {
	source, err := readGeneratedTracepointsC()
	if err != nil {
		t.Fatalf("read generated tracepoints C: %v", err)
	}
	actual, err := parseGeneratedSyscallSemantics(source)
	if err != nil {
		t.Fatalf("parse generated tracepoints C: %v", err)
	}

	resultSource, err := readGeneratedTracepointsResult()
	if err != nil {
		t.Fatalf("read generated tracepoint result: %v", err)
	}
	resultNames, err := parseResultEnterNames(resultSource)
	if err != nil {
		t.Fatalf("parse generated tracepoint result: %v", err)
	}

	issues := compareNameSets("generated C", mapKeysOf(actual), "generated result", resultNames)
	runtimeNames, err := generatedRuntimeEnterNames()
	if err != nil {
		t.Fatalf("read generated runtime trace IDs: %v", err)
	}
	issues = append(issues, compareNameSets("generated C", mapKeysOf(actual), "generated runtime types", runtimeNames)...)
	issues = append(issues, compareSyscallSemantics(syscallSemanticExpectations, actual)...)
	if len(issues) != 0 {
		sort.Strings(issues)
		t.Fatalf("generated syscall semantics drifted from the reviewed Linux signatures:\n%s", strings.Join(issues, "\n"))
	}
}

func TestSyscallSemanticsOracleRejectsMissingRows(t *testing.T) {
	source, err := readGeneratedTracepointsC()
	if err != nil {
		t.Fatalf("read generated tracepoints C: %v", err)
	}
	actual, err := parseGeneratedSyscallSemantics(source)
	if err != nil {
		t.Fatalf("parse generated tracepoints C: %v", err)
	}

	expected := maps.Clone(syscallSemanticExpectations)
	delete(expected, "read")
	if issues := compareSyscallSemantics(expected, actual); len(issues) == 0 {
		t.Fatal("removing an expectation did not fail the semantics comparison")
	}
}

func TestSyscallSemanticsOracleRejectsIncompleteRows(t *testing.T) {
	actual := map[string]syscallSemantics{
		"read": {kind: "fd", args: map[string]int{}, ret: "READ_CLASSIFIED", family: "FS"},
	}
	expected := map[string]syscallSemanticExpectation{
		"read": {kind: "fd", ret: "READ_CLASSIFIED", family: "FS"},
	}
	if issues := compareSyscallSemantics(expected, actual); len(issues) == 0 {
		t.Fatal("omitting the explicit args map did not fail the semantics comparison")
	}
}

func TestSyscallSemanticsParserRejectsMissingHandler(t *testing.T) {
	source, err := readGeneratedTracepointsC()
	if err != nil {
		t.Fatalf("read generated tracepoints C: %v", err)
	}
	source = removeHandler(t, source, "enter", "read")
	actual, err := parseGeneratedSyscallSemantics(source)
	if err == nil {
		if issues := compareSyscallSemantics(syscallSemanticExpectations, actual); len(issues) == 0 {
			t.Fatal("removing sys_enter_read did not fail parsing or comparison")
		}
	}
}

func TestSyscallSemanticsOracleRejectsSemanticMutations(t *testing.T) {
	source, err := readGeneratedTracepointsC()
	if err != nil {
		t.Fatalf("read generated tracepoints C: %v", err)
	}

	tests := []struct {
		name   string
		mutate func(*testing.T, string) string
	}{
		{
			name: "arg",
			mutate: func(t *testing.T, source string) string {
				return replaceInHandler(t, source, "enter", "read", "ev->fd = (__s32)ctx->args[0];", "ev->fd = (__s32)ctx->args[1];")
			},
		},
		{
			name: "duplicate captured field",
			mutate: func(t *testing.T, source string) string {
				return replaceInHandler(t, source, "enter", "read",
					"    ev->fd = (__s32)ctx->args[0];",
					"    ev->fd = (__s32)ctx->args[1];\n    ev->fd = (__s32)ctx->args[0];")
			},
		},
		{
			name: "captured field overwritten",
			mutate: func(t *testing.T, source string) string {
				return replaceInHandler(t, source, "enter", "read",
					"    ev->fd = (__s32)ctx->args[0];",
					"    ev->fd = (__s32)ctx->args[0];\n    ev->fd = -1;")
			},
		},
		{
			name: "captured event field incremented",
			mutate: func(t *testing.T, source string) string {
				return replaceInHandler(t, source, "enter", "read",
					"    ev->fd = (__s32)ctx->args[0];",
					"    ev->fd = (__s32)ctx->args[0];\n    ev->fd++;")
			},
		},
		{
			name: "captured event field cleared by function",
			mutate: func(t *testing.T, source string) string {
				return replaceInHandler(t, source, "enter", "read",
					"    ev->fd = (__s32)ctx->args[0];",
					"    ev->fd = (__s32)ctx->args[0];\n    __builtin_memset(&(ev->fd), 0, sizeof(ev->fd));")
			},
		},
		{
			name: "direct capture after submission",
			mutate: func(t *testing.T, source string) string {
				return replaceInHandler(t, source, "enter", "read",
					"    ev->fd = (__s32)ctx->args[0];\n\n    bpf_ringbuf_submit(ev, 0);",
					"    bpf_ringbuf_submit(ev, 0);\n\n    ev->fd = (__s32)ctx->args[0];")
			},
		},
		{
			name: "string-captured event field element overwritten",
			mutate: func(t *testing.T, source string) string {
				return replaceInHandler(t, source, "enter", "mq_unlink",
					"            ev->pathname_status = PATH_READ_FAILED;",
					"            ev->pathname_status = PATH_READ_FAILED;\n    ev->pathname[0] = '\\0';")
			},
		},
		{
			name: "string capture cleared after probe",
			mutate: func(t *testing.T, source string) string {
				return replaceInHandler(t, source, "enter", "mq_unlink",
					"            ev->pathname_status = PATH_READ_FAILED;",
					"            ev->pathname_status = PATH_READ_FAILED;\n        __builtin_memset(&(ev->pathname), 0, sizeof(ev->pathname));")
			},
		},
		{
			name: "string capture initialized at wrong destination",
			mutate: func(t *testing.T, source string) string {
				return replaceInHandler(t, source, "enter", "mq_unlink",
					"__builtin_memset(&(ev->pathname), 0, sizeof(ev->pathname));",
					"__builtin_memset(&(ev->event_type), 0, sizeof(ev->pathname));")
			},
		},
		{
			name: "string capture initialized with nonzero fill",
			mutate: func(t *testing.T, source string) string {
				return replaceInHandler(t, source, "enter", "mq_unlink",
					"__builtin_memset(&(ev->pathname), 0, sizeof(ev->pathname));",
					"__builtin_memset(&(ev->pathname), 1, sizeof(ev->pathname));")
			},
		},
		{
			name: "string capture initialized with short length",
			mutate: func(t *testing.T, source string) string {
				return replaceInHandler(t, source, "enter", "mq_unlink",
					"__builtin_memset(&(ev->pathname), 0, sizeof(ev->pathname));",
					"__builtin_memset(&(ev->pathname), 0, sizeof(ev->pathname) - 1);")
			},
		},
		{
			name: "short string probe read",
			mutate: func(t *testing.T, source string) string {
				return replaceInHandler(t, source, "enter", "mq_unlink",
					"bpf_probe_read_user_str(ev->pathname, sizeof(ev->pathname), (void*)ctx->args[0])",
					"bpf_probe_read_user_str(ev->pathname, 1, (void*)ctx->args[0])")
			},
		},
		{
			name: "shifted string probe source",
			mutate: func(t *testing.T, source string) string {
				return replaceInHandler(t, source, "enter", "mq_unlink",
					"(void*)ctx->args[0])",
					"(void*)ctx->args[0] + 1)")
			},
		},
		{
			name: "pathname NULL guard removed",
			mutate: func(t *testing.T, source string) string {
				return replaceInHandler(t, source, "enter", "mq_unlink",
					"if (ctx->args[0] == 0) {",
					"if (false) {")
			},
		},
		{
			name: "newer open schema write missing",
			mutate: func(t *testing.T, source string) string {
				return replaceInHandler(t, source, "enter", "open_tree_attr",
					"    ev->schema_version = OPEN_EVENT_SCHEMA_VERSION;", "")
			},
		},
		{
			name: "newer open schema write wrong",
			mutate: func(t *testing.T, source string) string {
				return replaceInHandler(t, source, "enter", "open_tree_attr",
					"ev->schema_version = OPEN_EVENT_SCHEMA_VERSION;",
					"ev->schema_version = PATH_EVENT_SCHEMA_VERSION;")
			},
		},
		{
			name: "newer path schema write missing",
			mutate: func(t *testing.T, source string) string {
				return replaceInHandler(t, source, "enter", "file_getattr",
					"    ev->schema_version = PATH_EVENT_SCHEMA_VERSION;", "")
			},
		},
		{
			name: "newer path schema write wrong",
			mutate: func(t *testing.T, source string) string {
				return replaceInHandler(t, source, "enter", "file_getattr",
					"ev->schema_version = PATH_EVENT_SCHEMA_VERSION;",
					"ev->schema_version = NAME_EVENT_SCHEMA_VERSION;")
			},
		},
		{
			name: "path target default missing",
			mutate: func(t *testing.T, source string) string {
				return replaceInHandler(t, source, "enter", "file_getattr",
					"    ev->target_status = PATH_TARGET_REQUIRED;", "")
			},
		},
		{
			name: "utimensat skipped target status missing",
			mutate: func(t *testing.T, source string) string {
				return replaceInHandler(t, source, "enter", "utimensat",
					"ev->target_status = PATH_TARGET_SKIPPED;",
					"ev->target_status = PATH_TARGET_REQUIRED;")
			},
		},
		{
			name: "utimensat skips when either timestamp is omitted",
			mutate: func(t *testing.T, source string) string {
				return replaceInHandler(t, source, "enter", "utimensat",
					"IOR_UTIME_OMIT == ior_times[0].tv_nsec &&",
					"IOR_UTIME_OMIT == ior_times[0].tv_nsec ||")
			},
		},
		{
			name: "name schema write missing",
			mutate: func(t *testing.T, source string) string {
				return replaceInHandler(t, source, "enter", "renameat2",
					"    ev->schema_version = NAME_EVENT_SCHEMA_VERSION;", "")
			},
		},
		{
			name: "name schema write wrong",
			mutate: func(t *testing.T, source string) string {
				return replaceInHandler(t, source, "enter", "renameat2",
					"ev->schema_version = NAME_EVENT_SCHEMA_VERSION;",
					"ev->schema_version = OPEN_EVENT_SCHEMA_VERSION;")
			},
		},
		{
			name: "pathname NULL status wrong",
			mutate: func(t *testing.T, source string) string {
				return replaceInHandler(t, source, "enter", "mq_unlink",
					"ev->pathname_status = PATH_READ_NULL;",
					"ev->pathname_status = PATH_READ_OK;")
			},
		},
		{
			name: "pathname OK status removed",
			mutate: func(t *testing.T, source string) string {
				return replaceInHandler(t, source, "enter", "mq_unlink",
					"ev->pathname_status = PATH_READ_OK;",
					"ev->pathname_status = PATH_READ_NULL;")
			},
		},
		{
			name: "pathname FAILED status removed",
			mutate: func(t *testing.T, source string) string {
				return replaceInHandler(t, source, "enter", "mq_unlink",
					"ev->pathname_status = PATH_READ_FAILED;",
					"ev->pathname_status = PATH_READ_OK;")
			},
		},
		{
			name: "name old side borrows new NULL guard",
			mutate: func(t *testing.T, source string) string {
				return replaceInHandler(t, source, "enter", "symlinkat",
					"if (ctx->args[0] == 0) {",
					"if (ctx->args[2] == 0) {")
			},
		},
		{
			name: "name new side borrows old failed status",
			mutate: func(t *testing.T, source string) string {
				return replaceInHandler(t, source, "enter", "symlinkat",
					"ev->newname_status = PATH_READ_FAILED;",
					"ev->oldname_status = PATH_READ_FAILED;")
			},
		},
		{
			name: "open NULL guard removed",
			mutate: func(t *testing.T, source string) string {
				return replaceInHandler(t, source, "enter", "openat",
					"if (ctx->args[1] == 0) {",
					"if (false) {")
			},
		},
		{
			name: "filename fallback wrong argument",
			mutate: func(t *testing.T, source string) string {
				return replaceInHandler(t, source, "enter", "openat",
					"ior_stash_pending_filename(tid, ctx->args[1]);",
					"ior_stash_pending_filename(tid, ctx->args[0]);")
			},
		},
		{
			name: "filename fallback removed",
			mutate: func(t *testing.T, source string) string {
				return replaceInHandler(t, source, "enter", "openat",
					"        ior_stash_pending_filename(tid, ctx->args[1]);",
					"        // ior_stash_pending_filename(tid, ctx->args[1]);")
			},
		},
		{
			name: "filename fallback guard inverted",
			mutate: func(t *testing.T, source string) string {
				return replaceInHandler(t, source, "enter", "openat",
					"if (bpf_probe_read_user_str(ev->filename, sizeof(ev->filename), (void *)ctx->args[1]) < 0)",
					"if (bpf_probe_read_user_str(ev->filename, sizeof(ev->filename), (void *)ctx->args[1]) >= 0)")
			},
		},
		{
			name: "additional inline filename fallback",
			mutate: func(t *testing.T, source string) string {
				return replaceInHandler(t, source, "enter", "openat",
					"        ior_stash_pending_filename(tid, ctx->args[1]);",
					"        ior_stash_pending_filename(tid, ctx->args[1]); if (1) ior_stash_pending_filename(tid, ctx->args[1]);")
			},
		},
		{
			name: "unexpected exec filename fallback",
			mutate: func(t *testing.T, source string) string {
				return replaceInHandler(t, source, "enter", "execve",
					"    bpf_probe_read_user_str(ev->filename, sizeof(ev->filename), (void *)ctx->args[0]);",
					"    if (bpf_probe_read_user_str(ev->filename, sizeof(ev->filename), (void *)ctx->args[0]) < 0) ior_stash_pending_filename(tid, ctx->args[0]);")
			},
		},
		{
			name: "string capture after submission",
			mutate: func(t *testing.T, source string) string {
				return replaceInHandler(t, source, "enter", "mq_unlink",
					"    bpf_ringbuf_submit(ev, 0);",
					"    bpf_ringbuf_submit(ev, 0);\n    if (bpf_probe_read_user_str(ev->pathname, sizeof(ev->pathname), (void*)ctx->args[0]) < 0)\n        ev->pathname_status = PATH_READ_FAILED;")
			},
		},
		{
			name: "additional malformed combined string initialization",
			mutate: func(t *testing.T, source string) string {
				return replaceInHandler(t, source, "enter", "symlinkat",
					"            ev->newname_status = PATH_READ_FAILED;",
					"            ev->newname_status = PATH_READ_FAILED;\n    __builtin_memset(&(ev->newname), 0, sizeof(ev->newname) - 1);")
			},
		},
		{
			name: "additional memset of combined comm storage",
			mutate: func(t *testing.T, source string) string {
				return replaceInHandler(t, source, "enter", "execve",
					"    bpf_get_current_comm(&ev->comm, sizeof(ev->comm));",
					"    bpf_get_current_comm(&ev->comm, sizeof(ev->comm));\n    __builtin_memset(&(ev->comm), 0, sizeof(ev->comm));")
			},
		},
		{
			name: "captured local overwritten",
			mutate: func(t *testing.T, source string) string {
				return replaceInHandler(t, source, "enter", "epoll_ctl",
					"        if (bpf_probe_read_user(&user_events, sizeof(user_events), (void *)ctx->args[3]) == 0) {",
					"        if (bpf_probe_read_user(&user_events, sizeof(user_events), (void *)ctx->args[3]) == 0) {\n            user_events = 0;")
			},
		},
		{
			name: "captured local compound-overwritten",
			mutate: func(t *testing.T, source string) string {
				return replaceInHandler(t, source, "enter", "epoll_ctl",
					"        if (bpf_probe_read_user(&user_events, sizeof(user_events), (void *)ctx->args[3]) == 0) {",
					"        if (bpf_probe_read_user(&user_events, sizeof(user_events), (void *)ctx->args[3]) == 0) {\n            user_events &= 0;")
			},
		},
		{
			name: "captured struct local member overwritten",
			mutate: func(t *testing.T, source string) string {
				return replaceInHandler(t, source, "enter", "clock_nanosleep",
					"        if (bpf_probe_read_user(&ts, sizeof(ts), (void *)ctx->args[2]) == 0) {",
					"        if (bpf_probe_read_user(&ts, sizeof(ts), (void *)ctx->args[2]) == 0) {\n            ts.tv_sec = 0;")
			},
		},
		{
			name: "captured struct local cleared",
			mutate: func(t *testing.T, source string) string {
				return replaceInHandler(t, source, "enter", "clock_nanosleep",
					"        if (bpf_probe_read_user(&ts, sizeof(ts), (void *)ctx->args[2]) == 0) {",
					"        if (bpf_probe_read_user(&ts, sizeof(ts), (void *)ctx->args[2]) == 0) {\n            __builtin_memset(&ts, 0, sizeof(ts));")
			},
		},
		{
			name: "captured local consumed before production",
			mutate: func(t *testing.T, source string) string {
				source = replaceInHandler(t, source, "enter", "epoll_ctl", "            ev->events = user_events;\n", "")
				return replaceInHandler(t, source, "enter", "epoll_ctl",
					"        if (bpf_probe_read_user(&user_events, sizeof(user_events), (void *)ctx->args[3]) == 0) {",
					"        ev->events = user_events;\n        if (bpf_probe_read_user(&user_events, sizeof(user_events), (void *)ctx->args[3]) == 0) {")
			},
		},
		{
			name: "probe-read arg",
			mutate: func(t *testing.T, source string) string {
				return replaceInHandler(t, source, "enter", "epoll_ctl",
					"bpf_probe_read_user(&user_events, sizeof(user_events), (void *)ctx->args[3])",
					"bpf_probe_read_user(&user_events, sizeof(user_events), (void *)ctx->args[4])")
			},
		},
		{
			name: "duplicate local probe-read source",
			mutate: func(t *testing.T, source string) string {
				return replaceInHandler(t, source, "enter", "epoll_ctl",
					"        if (bpf_probe_read_user(&user_events, sizeof(user_events), (void *)ctx->args[3]) == 0) {",
					"        bpf_probe_read_user(&user_events, sizeof(user_events), (void *)ctx->args[4]);\n        if (bpf_probe_read_user(&user_events, sizeof(user_events), (void *)ctx->args[3]) == 0) {")
			},
		},
		{
			name: "missing pending map update",
			mutate: func(t *testing.T, source string) string {
				return replaceInHandler(t, source, "enter", "socketpair",
					"    bpf_map_update_elem(&socketpair_ctx_map, &tid, &pending, BPF_ANY);",
					"    // bpf_map_update_elem(&socketpair_ctx_map, &tid, &pending, BPF_ANY);")
			},
		},
		{
			name: "missing pending exit transport",
			mutate: func(t *testing.T, source string) string {
				return replaceInHandler(t, source, "exit", "socketpair",
					"        family = pending->family;",
					"        family = -1;")
			},
		},
		{
			name: "missing pending output read",
			mutate: func(t *testing.T, source string) string {
				return replaceInHandler(t, source, "exit", "socketpair",
					"            if (bpf_probe_read_user(&sv, sizeof(sv), (void *)pending->usockvec) == 0) {",
					"            if (0) {")
			},
		},
		{
			name: "short pending output read",
			mutate: func(t *testing.T, source string) string {
				return replaceInHandler(t, source, "exit", "socketpair",
					"bpf_probe_read_user(&sv, sizeof(sv), (void *)pending->usockvec)",
					"bpf_probe_read_user(&sv, sizeof(sv[0]), (void *)pending->usockvec)")
			},
		},
		{
			name: "inverted pending output read result",
			mutate: func(t *testing.T, source string) string {
				return replaceInHandler(t, source, "exit", "socketpair",
					"if (bpf_probe_read_user(&sv, sizeof(sv), (void *)pending->usockvec) == 0)",
					"if (bpf_probe_read_user(&sv, sizeof(sv), (void *)pending->usockvec) != 0)")
			},
		},
		{
			name: "inverted pending output syscall guard",
			mutate: func(t *testing.T, source string) string {
				return replaceInHandler(t, source, "exit", "socketpair",
					"if (ctx->ret == 0 && pending->usockvec != 0)",
					"if (ctx->ret != 0 && pending->usockvec != 0)")
			},
		},
		{
			name: "pending output read outside syscall guard",
			mutate: func(t *testing.T, source string) string {
				return replaceInHandler(t, source, "exit", "socketpair",
					"        if (ctx->ret == 0 && pending->usockvec != 0) {\n            int sv[2];",
					"        if (ctx->ret == 0 && pending->usockvec != 0) {\n        }\n            int sv[2];")
			},
		},
		{
			name: "pending output not emitted",
			mutate: func(t *testing.T, source string) string {
				return replaceInHandler(t, source, "exit", "socketpair",
					"    ev->sv0 = sv0;",
					"    ev->sv0 = -1;")
			},
		},
		{
			name: "pending output element omitted",
			mutate: func(t *testing.T, source string) string {
				source = replaceInHandler(t, source, "exit", "socketpair", "                sv1 = (__s32)sv[1];\n", "")
				return replaceInHandler(t, source, "exit", "socketpair", "    ev->sv1 = sv1;\n", "")
			},
		},
		{
			name: "pending output array shrunk",
			mutate: func(t *testing.T, source string) string {
				source = replaceInHandler(t, source, "exit", "socketpair", "            int sv[2];", "            int sv[1];")
				source = replaceInHandler(t, source, "exit", "socketpair", "                sv1 = (__s32)sv[1];\n", "")
				return replaceInHandler(t, source, "exit", "socketpair", "    ev->sv1 = sv1;\n", "")
			},
		},
		{
			name: "pending output derived before read",
			mutate: func(t *testing.T, source string) string {
				source = replaceInHandler(t, source, "exit", "socketpair", "                sv0 = (__s32)sv[0];\n", "")
				return replaceInHandler(t, source, "exit", "socketpair",
					"            if (bpf_probe_read_user(&sv, sizeof(sv), (void *)pending->usockvec) == 0) {",
					"            sv0 = (__s32)sv[0];\n            if (bpf_probe_read_user(&sv, sizeof(sv), (void *)pending->usockvec) == 0) {")
			},
		},
		{
			name: "pending output derived outside successful read",
			mutate: func(t *testing.T, source string) string {
				source = replaceInHandler(t, source, "exit", "socketpair", "                sv0 = (__s32)sv[0];\n", "")
				return replaceInHandler(t, source, "exit", "socketpair",
					"            }\n        }\n        bpf_map_delete_elem(&socketpair_ctx_map, &tid);",
					"            }\n            sv0 = (__s32)sv[0];\n        }\n        bpf_map_delete_elem(&socketpair_ctx_map, &tid);")
			},
		},
		{
			name: "pending output buffer overwritten",
			mutate: func(t *testing.T, source string) string {
				return replaceInHandler(t, source, "exit", "socketpair",
					"            if (bpf_probe_read_user(&sv, sizeof(sv), (void *)pending->usockvec) == 0) {",
					"            if (bpf_probe_read_user(&sv, sizeof(sv), (void *)pending->usockvec) == 0) {\n                sv[0] = -1;")
			},
		},
		{
			name: "pending output destinations swapped",
			mutate: func(t *testing.T, source string) string {
				return replaceInHandler(t, source, "exit", "socketpair",
					"    ev->sv0 = sv0;\n    ev->sv1 = sv1;",
					"    ev->sv0 = sv1;\n    ev->sv1 = sv0;")
			},
		},
		{
			name: "pending output emitted after submission",
			mutate: func(t *testing.T, source string) string {
				return replaceInHandler(t, source, "exit", "socketpair",
					"    ev->sv0 = sv0;\n    ev->sv1 = sv1;\n    ev->ret = ctx->ret;\n\n    bpf_ringbuf_submit(ev, 0);",
					"    ev->sv1 = sv1;\n    ev->ret = ctx->ret;\n\n    bpf_ringbuf_submit(ev, 0);\n    ev->sv0 = sv0;")
			},
		},
		{
			name: "pending scalar destinations swapped",
			mutate: func(t *testing.T, source string) string {
				return replaceInHandler(t, source, "exit", "socketpair",
					"    ev->family = family;\n    ev->type = type;",
					"    ev->family = type;\n    ev->type = family;")
			},
		},
		{
			name: "pending destination overwritten",
			mutate: func(t *testing.T, source string) string {
				return replaceInHandler(t, source, "exit", "socketpair",
					"    ev->family = family;",
					"    ev->family = family;\n    ev->family = -1;")
			},
		},
		{
			name: "transported destination incremented",
			mutate: func(t *testing.T, source string) string {
				return replaceInHandler(t, source, "exit", "socketpair",
					"    ev->family = family;",
					"    ev->family = family;\n    ev->family++;")
			},
		},
		{
			name: "pending map update before capture",
			mutate: func(t *testing.T, source string) string {
				return replaceInHandler(t, source, "enter", "socketpair",
					"    pending.usockvec = ctx->args[3];\n    pending.family = (__s32)ctx->args[0];\n    pending.type = (__s32)ctx->args[1];\n    pending.protocol = (__s32)ctx->args[2];\n    bpf_map_update_elem(&socketpair_ctx_map, &tid, &pending, BPF_ANY);",
					"    bpf_map_update_elem(&socketpair_ctx_map, &tid, &pending, BPF_ANY);\n    pending.usockvec = ctx->args[3];\n    pending.family = (__s32)ctx->args[0];\n    pending.type = (__s32)ctx->args[1];\n    pending.protocol = (__s32)ctx->args[2];")
			},
		},
		{
			name: "pending field overwritten before update",
			mutate: func(t *testing.T, source string) string {
				return replaceInHandler(t, source, "enter", "socketpair",
					"    pending.family = (__s32)ctx->args[0];",
					"    pending.family = (__s32)ctx->args[0];\n    pending.family = -1;")
			},
		},
		{
			name: "pending field overwritten after update",
			mutate: func(t *testing.T, source string) string {
				return replaceInHandler(t, source, "enter", "socketpair",
					"    bpf_map_update_elem(&socketpair_ctx_map, &tid, &pending, BPF_ANY);",
					"    bpf_map_update_elem(&socketpair_ctx_map, &tid, &pending, BPF_ANY);\n    pending.family = -1;")
			},
		},
		{
			name: "pending field compound-overwritten",
			mutate: func(t *testing.T, source string) string {
				return replaceInHandler(t, source, "enter", "socketpair",
					"    pending.family = (__s32)ctx->args[0];",
					"    pending.family = (__s32)ctx->args[0];\n    pending.family += 1;")
			},
		},
		{
			name: "pending enter emission removed",
			mutate: func(t *testing.T, source string) string {
				return replaceInHandler(t, source, "enter", "socketpair",
					"    ev->family = pending.family;",
					"    ev->family = -1;")
			},
		},
		{
			name: "pending capture route bypassed",
			mutate: func(t *testing.T, source string) string {
				source = replaceInHandler(t, source, "enter", "socketpair",
					"    pending.family = (__s32)ctx->args[0];",
					"    pending.family = 0;")
				return replaceInHandler(t, source, "enter", "socketpair",
					"    ev->family = pending.family;",
					"    ev->family = (__s32)ctx->args[0];")
			},
		},
		{
			name: "pending capture cleared by function",
			mutate: func(t *testing.T, source string) string {
				return replaceInHandler(t, source, "enter", "socketpair",
					"    pending.family = (__s32)ctx->args[0];",
					"    pending.family = (__s32)ctx->args[0];\n    __builtin_memset(&(pending.family), 0, sizeof(pending.family));")
			},
		},
		{
			name: "missing pending map lookup",
			mutate: func(t *testing.T, source string) string {
				return replaceInHandler(t, source, "exit", "socketpair",
					"    struct socketpair_ctx *pending = bpf_map_lookup_elem(&socketpair_ctx_map, &tid);",
					"    // struct socketpair_ctx *pending = bpf_map_lookup_elem(&socketpair_ctx_map, &tid);")
			},
		},
		{
			name: "structured pending read outside null guard",
			mutate: func(t *testing.T, source string) string {
				source = replaceInHandler(t, source, "exit", "socketpair", "        family = pending->family;\n", "")
				return replaceInHandler(t, source, "exit", "socketpair",
					"    }\n    ev->family = family;",
					"    }\n    family = pending->family;\n    ev->family = family;")
			},
		},
		{
			name: "structured pending read before null guard",
			mutate: func(t *testing.T, source string) string {
				source = replaceInHandler(t, source, "exit", "socketpair", "        family = pending->family;\n", "")
				return replaceInHandler(t, source, "exit", "socketpair",
					"    if (pending) {",
					"    family = pending->family;\n    if (pending) {")
			},
		},
		{
			name: "structured pending delete removed",
			mutate: func(t *testing.T, source string) string {
				return replaceInHandler(t, source, "exit", "socketpair",
					"        bpf_map_delete_elem(&socketpair_ctx_map, &tid);",
					"        // bpf_map_delete_elem(&socketpair_ctx_map, &tid);")
			},
		},
		{
			name: "structured pending delete before reads",
			mutate: func(t *testing.T, source string) string {
				source = replaceInHandler(t, source, "exit", "socketpair", "        bpf_map_delete_elem(&socketpair_ctx_map, &tid);\n", "")
				return replaceInHandler(t, source, "exit", "socketpair",
					"    if (pending) {",
					"    if (pending) {\n        bpf_map_delete_elem(&socketpair_ctx_map, &tid);")
			},
		},
		{
			name: "structured pending delete before null guard",
			mutate: func(t *testing.T, source string) string {
				source = replaceInHandler(t, source, "exit", "socketpair", "        bpf_map_delete_elem(&socketpair_ctx_map, &tid);\n", "")
				return replaceInHandler(t, source, "exit", "socketpair",
					"    if (pending) {",
					"    bpf_map_delete_elem(&socketpair_ctx_map, &tid);\n    if (pending) {")
			},
		},
		{
			name: "structured pending delete after null guard",
			mutate: func(t *testing.T, source string) string {
				source = replaceInHandler(t, source, "exit", "socketpair", "        bpf_map_delete_elem(&socketpair_ctx_map, &tid);\n", "")
				return replaceInHandler(t, source, "exit", "socketpair",
					"    }\n    ev->family = family;",
					"    }\n    bpf_map_delete_elem(&socketpair_ctx_map, &tid);\n    ev->family = family;")
			},
		},
		{
			name: "duplicate pending map lookup",
			mutate: func(t *testing.T, source string) string {
				return replaceInHandler(t, source, "exit", "socketpair",
					"    struct socketpair_ctx *pending = bpf_map_lookup_elem(&socketpair_ctx_map, &tid);",
					"    struct socketpair_ctx *pending = bpf_map_lookup_elem(&socketpair_ctx_map, &tid);\n    struct socketpair_ctx *pending = bpf_map_lookup_elem(&socketpair_ctx_map, &tid);")
			},
		},
		{
			name: "pending map mismatch",
			mutate: func(t *testing.T, source string) string {
				return replaceInHandler(t, source, "exit", "socketpair",
					"    struct socketpair_ctx *pending = bpf_map_lookup_elem(&socketpair_ctx_map, &tid);",
					"    struct socketpair_ctx *pending = bpf_map_lookup_elem(&pipe_ctx_map, &tid);")
			},
		},
		{
			name: "pending read before lookup",
			mutate: func(t *testing.T, source string) string {
				source = replaceInHandler(t, source, "exit", "socketpair", "        family = pending->family;\n", "")
				return replaceInHandler(t, source, "exit", "socketpair",
					"    struct socketpair_ctx *pending = bpf_map_lookup_elem(&socketpair_ctx_map, &tid);",
					"    family = pending->family;\n    struct socketpair_ctx *pending = bpf_map_lookup_elem(&socketpair_ctx_map, &tid);")
			},
		},
		{
			name: "missing scalar pending map update",
			mutate: func(t *testing.T, source string) string {
				return replaceInHandler(t, source, "enter", "landlock_create_ruleset",
					"    bpf_map_update_elem(&eventfd_flags_map, &tid, &flags, BPF_ANY);",
					"    // bpf_map_update_elem(&eventfd_flags_map, &tid, &flags, BPF_ANY);")
			},
		},
		{
			name: "scalar pending update before production",
			mutate: func(t *testing.T, source string) string {
				return replaceInHandler(t, source, "enter", "landlock_create_ruleset",
					"    __s32 flags = (__s32)ctx->args[2];\n    bpf_map_update_elem(&eventfd_flags_map, &tid, &flags, BPF_ANY);",
					"    __s32 flags;\n    bpf_map_update_elem(&eventfd_flags_map, &tid, &flags, BPF_ANY);\n    flags = (__s32)ctx->args[2];")
			},
		},
		{
			name: "missing scalar pending map lookup",
			mutate: func(t *testing.T, source string) string {
				return replaceInHandler(t, source, "exit", "landlock_create_ruleset",
					"    __s32 *pending = bpf_map_lookup_elem(&eventfd_flags_map, &tid);",
					"    // __s32 *pending = bpf_map_lookup_elem(&eventfd_flags_map, &tid);")
			},
		},
		{
			name: "scalar pending map mismatch",
			mutate: func(t *testing.T, source string) string {
				return replaceInHandler(t, source, "exit", "landlock_create_ruleset",
					"    __s32 *pending = bpf_map_lookup_elem(&eventfd_flags_map, &tid);",
					"    __s32 *pending = bpf_map_lookup_elem(&pipe_ctx_map, &tid);")
			},
		},
		{
			name: "scalar pending restore removed",
			mutate: func(t *testing.T, source string) string {
				return replaceInHandler(t, source, "exit", "landlock_create_ruleset",
					"        flags = *pending;",
					"        flags = 0;")
			},
		},
		{
			name: "pidfd scalar pending restore removed",
			mutate: func(t *testing.T, source string) string {
				return replaceInHandler(t, source, "exit", "pidfd_open",
					"        flags = *pending;",
					"        flags = 0;")
			},
		},
		{
			name: "pidfd scalar pending restore outside null guard",
			mutate: func(t *testing.T, source string) string {
				source = replaceInHandler(t, source, "exit", "pidfd_open", "        flags = *pending;\n", "")
				return replaceInHandler(t, source, "exit", "pidfd_open",
					"    }\n    ev->flags = flags;",
					"    }\n    flags = *pending;\n    ev->flags = flags;")
			},
		},
		{
			name: "pidfd scalar pending restore before null guard",
			mutate: func(t *testing.T, source string) string {
				source = replaceInHandler(t, source, "exit", "pidfd_open", "        flags = *pending;\n", "")
				return replaceInHandler(t, source, "exit", "pidfd_open",
					"    if (pending) {",
					"    flags = *pending;\n    if (pending) {")
			},
		},
		{
			name: "scalar pending delete removed",
			mutate: func(t *testing.T, source string) string {
				return replaceInHandler(t, source, "exit", "pidfd_open",
					"        bpf_map_delete_elem(&eventfd_flags_map, &tid);",
					"        // bpf_map_delete_elem(&eventfd_flags_map, &tid);")
			},
		},
		{
			name: "scalar pending delete before restore",
			mutate: func(t *testing.T, source string) string {
				return replaceInHandler(t, source, "exit", "pidfd_open",
					"        flags = *pending;\n        bpf_map_delete_elem(&eventfd_flags_map, &tid);",
					"        bpf_map_delete_elem(&eventfd_flags_map, &tid);\n        flags = *pending;")
			},
		},
		{
			name: "scalar pending delete before null guard",
			mutate: func(t *testing.T, source string) string {
				source = replaceInHandler(t, source, "exit", "pidfd_open", "        bpf_map_delete_elem(&eventfd_flags_map, &tid);\n", "")
				return replaceInHandler(t, source, "exit", "pidfd_open",
					"    if (pending) {",
					"    bpf_map_delete_elem(&eventfd_flags_map, &tid);\n    if (pending) {")
			},
		},
		{
			name: "scalar pending delete after null guard",
			mutate: func(t *testing.T, source string) string {
				source = replaceInHandler(t, source, "exit", "pidfd_open", "        bpf_map_delete_elem(&eventfd_flags_map, &tid);\n", "")
				return replaceInHandler(t, source, "exit", "pidfd_open",
					"    }\n    ev->flags = flags;",
					"    }\n    bpf_map_delete_elem(&eventfd_flags_map, &tid);\n    ev->flags = flags;")
			},
		},
		{
			name: "scalar pending exit emission removed",
			mutate: func(t *testing.T, source string) string {
				return replaceInHandler(t, source, "exit", "landlock_create_ruleset",
					"    ev->flags = flags;",
					"    ev->flags = -1;")
			},
		},
		{
			name: "commented string probe read",
			mutate: func(t *testing.T, source string) string {
				return replaceInHandler(t, source, "enter", "mq_unlink",
					"        if (bpf_probe_read_user_str(ev->pathname, sizeof(ev->pathname), (void*)ctx->args[0]) < 0)",
					"        // if (bpf_probe_read_user_str(ev->pathname, sizeof(ev->pathname), (void*)ctx->args[0]) < 0)")
			},
		},
		{
			name: "commented local probe read",
			mutate: func(t *testing.T, source string) string {
				return replaceInHandler(t, source, "enter", "epoll_ctl",
					"        if (bpf_probe_read_user(&user_events, sizeof(user_events), (void *)ctx->args[3]) == 0) {",
					"        /* if (bpf_probe_read_user(&user_events, sizeof(user_events), (void *)ctx->args[3]) == 0) { */")
			},
		},
		{
			name: "commented TIMER_ABSTIME control",
			mutate: func(t *testing.T, source string) string {
				return replaceInHandler(t, source, "enter", "clock_nanosleep",
					"            if ((ctx->args[1] & 1 /* TIMER_ABSTIME */) == 0) {",
					"            /*\n            if ((ctx->args[1] & 1) == 0) {\n            */")
			},
		},
		{
			name: "requested duration outside TIMER_ABSTIME guard",
			mutate: func(t *testing.T, source string) string {
				source = replaceInHandler(t, source, "enter", "clock_nanosleep",
					"                ev->requested_ns = ts.tv_sec * 1000000000LL + ts.tv_nsec;\n", "")
				return replaceInHandler(t, source, "enter", "clock_nanosleep",
					"            }\n        }\n    }\n\n    bpf_ringbuf_submit(ev, 0);",
					"            }\n            ev->requested_ns = ts.tv_sec * 1000000000LL + ts.tv_nsec;\n        }\n    }\n\n    bpf_ringbuf_submit(ev, 0);")
			},
		},
		{
			name: "kind",
			mutate: func(t *testing.T, source string) string {
				return replaceExactlyOnce(t, source,
					"/// sys_enter_clone is a struct null_event (kind=proc)",
					"/// sys_enter_clone is a struct null_event (kind=null)")
			},
		},
		{
			name: "ret",
			mutate: func(t *testing.T, source string) string {
				return replaceInHandler(t, source, "exit", "read", "ev->ret_type = READ_CLASSIFIED;", "ev->ret_type = WRITE_CLASSIFIED;")
			},
		},
		{
			name: "missing unclassified ret assignment",
			mutate: func(t *testing.T, source string) string {
				return replaceInHandler(t, source, "exit", "bind", "    ev->ret_type = UNCLASSIFIED;\n", "")
			},
		},
		{
			name: "duplicate ret assignment",
			mutate: func(t *testing.T, source string) string {
				return replaceInHandler(t, source, "exit", "read",
					"    ev->ret_type = READ_CLASSIFIED;",
					"    ev->ret_type = READ_CLASSIFIED;\n    ev->ret_type = WRITE_CLASSIFIED;")
			},
		},
		{
			name: "numeric ret overwrite",
			mutate: func(t *testing.T, source string) string {
				return replaceInHandler(t, source, "exit", "read",
					"    ev->ret_type = READ_CLASSIFIED;",
					"    ev->ret_type = READ_CLASSIFIED;\n    ev->ret_type = 0;")
			},
		},
		{
			name: "ret classification incremented",
			mutate: func(t *testing.T, source string) string {
				return replaceInHandler(t, source, "exit", "read",
					"    ev->ret_type = READ_CLASSIFIED;",
					"    ev->ret_type = READ_CLASSIFIED;\n    ev->ret_type++;")
			},
		},
		{
			name: "ret classification after submission",
			mutate: func(t *testing.T, source string) string {
				return replaceInHandler(t, source, "exit", "read",
					"    ev->ret_type = READ_CLASSIFIED;\n\n    bpf_ringbuf_submit(ev, 0);",
					"    bpf_ringbuf_submit(ev, 0);\n\n    ev->ret_type = READ_CLASSIFIED;")
			},
		},
		{
			name: "commented ret assignment",
			mutate: func(t *testing.T, source string) string {
				return replaceInHandler(t, source, "exit", "read",
					"    ev->ret_type = READ_CLASSIFIED;",
					"    /* ev->ret_type = READ_CLASSIFIED; */")
			},
		},
		{
			name: "commented event struct",
			mutate: func(t *testing.T, source string) string {
				return replaceInHandler(t, source, "enter", "read",
					"    struct fd_event *ev = bpf_ringbuf_reserve(&event_map, sizeof(struct fd_event), 0);",
					"    /* struct fd_event *ev = bpf_ringbuf_reserve(&event_map, sizeof(struct fd_event), 0); */")
			},
		},
		{
			name: "block-commented enter handler",
			mutate: func(t *testing.T, source string) string {
				return blockCommentHandler(t, source, "enter", "read")
			},
		},
		{
			name: "block-commented exit handler",
			mutate: func(t *testing.T, source string) string {
				return blockCommentHandler(t, source, "exit", "read")
			},
		},
		{
			name: "preprocessor-disabled enter handler",
			mutate: func(t *testing.T, source string) string {
				return disableHandler(t, source, "enter", "read")
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			actual, err := parseGeneratedSyscallSemantics(test.mutate(t, source))
			if err == nil && len(compareSyscallSemantics(syscallSemanticExpectations, actual)) == 0 {
				t.Fatalf("%s mutation did not fail parsing or comparison", test.name)
			}
		})
	}

	t.Run("runtime family value", func(t *testing.T) {
		actual, err := parseGeneratedSyscallSemantics(source)
		if err != nil {
			t.Fatalf("parse generated tracepoints C: %v", err)
		}
		read := actual["read"]
		read.family = "Memory"
		actual["read"] = read
		if issues := compareSyscallSemantics(syscallSemanticExpectations, actual); len(issues) == 0 {
			t.Fatal("mutating the runtime family value did not fail comparison")
		}
	})

	t.Run("classifier and runtime artifact drift", func(t *testing.T) {
		previous, existed := syscallFamilies["read"]
		syscallFamilies["read"] = FamilyMemory
		defer func() {
			if existed {
				syscallFamilies["read"] = previous
				return
			}
			delete(syscallFamilies, "read")
		}()

		if _, err := parseGeneratedSyscallSemantics(source); err == nil {
			t.Fatal("making the classifier stale against generated runtime metadata did not fail parsing")
		}
	})
}

func temporaryArgs(task string, current map[string]int) *temporarySyscallSemantics {
	return &temporarySyscallSemantics{task: task, current: syscallSemantics{args: current}}
}

func (e syscallSemanticExpectation) artifactExpectation() syscallSemantics {
	result := syscallSemantics{kind: e.kind, args: e.args, ret: e.ret, family: e.family}
	if e.temporary == nil {
		return result
	}
	current := e.temporary.current
	if current.kind != "" {
		result.kind = current.kind
	}
	if current.args != nil {
		result.args = current.args
	}
	if current.ret != "" {
		result.ret = current.ret
	}
	if current.family != "" {
		result.family = current.family
	}
	return result
}

func compareSyscallSemantics(expected map[string]syscallSemanticExpectation, actual map[string]syscallSemantics) []string {
	issues := compareNameSets("expectations", mapKeysOf(expected), "generated C", mapKeysOf(actual))
	for name, expectation := range expected {
		issues = append(issues, validateSyscallSemanticExpectation(name, expectation)...)
		got, ok := actual[name]
		if !ok {
			continue
		}
		want := expectation.artifactExpectation()
		if got.kind != want.kind {
			issues = append(issues, fmt.Sprintf("%s: kind=%q want %q", name, got.kind, want.kind))
		}
		if !maps.Equal(got.args, want.args) {
			issues = append(issues, fmt.Sprintf("%s: args=%v want %v", name, got.args, want.args))
		}
		if got.ret != want.ret {
			issues = append(issues, fmt.Sprintf("%s: ret=%q want %q", name, got.ret, want.ret))
		}
		if got.family != want.family {
			issues = append(issues, fmt.Sprintf("%s: family=%q want %q", name, got.family, want.family))
		}
	}
	return issues
}

func validateSyscallSemanticExpectation(name string, expectation syscallSemanticExpectation) []string {
	var issues []string
	if expectation.kind == "" {
		issues = append(issues, fmt.Sprintf("%s: expectation has no kind", name))
	}
	if expectation.args == nil {
		issues = append(issues, fmt.Sprintf("%s: expectation has no explicit args map", name))
	}
	if expectation.ret == "" {
		issues = append(issues, fmt.Sprintf("%s: expectation has no return classification", name))
	}
	if expectation.family == "" {
		issues = append(issues, fmt.Sprintf("%s: expectation has no family", name))
	}
	if expectation.temporary != nil {
		if expectation.temporary.task == "" {
			issues = append(issues, fmt.Sprintf("%s: temporary semantics have no task", name))
		}
		current := expectation.temporary.current
		if current.kind == "" && current.args == nil && current.ret == "" && current.family == "" {
			issues = append(issues, fmt.Sprintf("%s: temporary semantics override nothing", name))
		}
	}
	return issues
}

func compareNameSets(leftLabel string, left map[string]struct{}, rightLabel string, right map[string]struct{}) []string {
	var issues []string
	for name := range left {
		if _, ok := right[name]; !ok {
			issues = append(issues, fmt.Sprintf("%s has %s but %s does not", leftLabel, name, rightLabel))
		}
	}
	for name := range right {
		if _, ok := left[name]; !ok {
			issues = append(issues, fmt.Sprintf("%s has %s but %s does not", rightLabel, name, leftLabel))
		}
	}
	return issues
}

func mapKeysOf[T any](values map[string]T) map[string]struct{} {
	result := make(map[string]struct{}, len(values))
	for name := range values {
		result[name] = struct{}{}
	}
	return result
}

func generatedRuntimeEnterNames() (map[string]struct{}, error) {
	traceIDs := iortypes.EnterTraceIDs()
	result := make(map[string]struct{}, len(traceIDs))
	for _, traceID := range traceIDs {
		name := traceID.Name()
		if _, exists := result[name]; exists {
			return nil, fmt.Errorf("duplicate generated runtime enter trace ID for %s", name)
		}
		result[name] = struct{}{}
	}
	if len(result) == 0 {
		return nil, fmt.Errorf("no generated runtime enter trace IDs")
	}
	return result, nil
}

func parseResultEnterNames(source string) (map[string]struct{}, error) {
	result := map[string]struct{}{}
	for _, match := range resultEnterRE.FindAllStringSubmatch(source, -1) {
		if _, exists := result[match[1]]; exists {
			return nil, fmt.Errorf("duplicate sys_enter_%s result row", match[1])
		}
		result[match[1]] = struct{}{}
	}
	if len(result) == 0 {
		return nil, fmt.Errorf("no enter rows")
	}
	return result, nil
}

func removeHandler(t *testing.T, source, phase, name string) string {
	t.Helper()
	re := regexp.MustCompile(`(?ms)^int handle_sys_` + regexp.QuoteMeta(phase) + `_` + regexp.QuoteMeta(name) + `\([^)]*\) \{\n.*?^\}\n`)
	if matches := re.FindAllStringIndex(source, -1); len(matches) != 1 {
		t.Fatalf("found %d %s handlers for %s, want 1", len(matches), phase, name)
	}
	return re.ReplaceAllString(source, "")
}

func blockCommentHandler(t *testing.T, source, phase, name string) string {
	t.Helper()
	re := regexp.MustCompile(`(?ms)^int handle_sys_` + regexp.QuoteMeta(phase) + `_` + regexp.QuoteMeta(name) + `\([^)]*\) \{\n.*?^\}\n`)
	location := re.FindStringIndex(source)
	if location == nil {
		t.Fatalf("%s handler for %s not found", phase, name)
	}
	return source[:location[0]] + "/*\n" + source[location[0]:location[1]] + "*/\n" + source[location[1]:]
}

func disableHandler(t *testing.T, source, phase, name string) string {
	t.Helper()
	re := regexp.MustCompile(`(?ms)^int handle_sys_` + regexp.QuoteMeta(phase) + `_` + regexp.QuoteMeta(name) + `\([^)]*\) \{\n.*?^\}\n`)
	location := re.FindStringIndex(source)
	if location == nil {
		t.Fatalf("%s handler for %s not found", phase, name)
	}
	return source[:location[0]] + "#if 0\n" + source[location[0]:location[1]] + "#endif\n" + source[location[1]:]
}

func replaceInHandler(t *testing.T, source, phase, name, old, replacement string) string {
	t.Helper()
	re := regexp.MustCompile(`(?ms)^int handle_sys_` + regexp.QuoteMeta(phase) + `_` + regexp.QuoteMeta(name) + `\([^)]*\) \{\n.*?^\}\n`)
	location := re.FindStringIndex(source)
	if location == nil {
		t.Fatalf("%s handler for %s not found", phase, name)
	}
	handler := replaceExactlyOnce(t, source[location[0]:location[1]], old, replacement)
	return source[:location[0]] + handler + source[location[1]:]
}

func replaceExactlyOnce(t *testing.T, source, old, replacement string) string {
	t.Helper()
	if count := strings.Count(source, old); count != 1 {
		t.Fatalf("found %d copies of %q, want 1", count, old)
	}
	return strings.Replace(source, old, replacement, 1)
}

func parseGeneratedSyscallSemantics(source string) (map[string]syscallSemantics, error) {
	source = stripCBlockComments(source)
	source = stripDisabledCPreprocessorBlocks(source)
	type handlerPair struct {
		enter string
		exit  string
	}
	kinds := map[string]string{}
	for _, match := range kindCommentRE.FindAllStringSubmatch(source, -1) {
		if _, exists := kinds[match[1]]; exists {
			return nil, fmt.Errorf("duplicate kind comment for sys_enter_%s", match[1])
		}
		kinds[match[1]] = match[2]
	}

	pairs := map[string]handlerPair{}
	for _, match := range handlerRE.FindAllStringSubmatch(source, -1) {
		pair := pairs[match[2]]
		if match[1] == "enter" {
			if pair.enter != "" {
				return nil, fmt.Errorf("duplicate sys_enter_%s handler", match[2])
			}
			pair.enter = match[3]
		} else {
			if pair.exit != "" {
				return nil, fmt.Errorf("duplicate sys_exit_%s handler", match[2])
			}
			pair.exit = match[3]
		}
		pairs[match[2]] = pair
	}

	result := make(map[string]syscallSemantics, len(pairs))
	for name, pair := range pairs {
		if pair.enter == "" {
			return nil, fmt.Errorf("sys_exit_%s has no enter handler", name)
		}
		kind, ok := kinds[name]
		if !ok {
			return nil, fmt.Errorf("sys_enter_%s has no kind comment", name)
		}
		if err := validateHandlerEventStruct(name, kind, pair.enter); err != nil {
			return nil, err
		}
		if err := validateSchemaVersionWrite(name, pair.enter); err != nil {
			return nil, err
		}
		if err := validatePathTargetStatus(name, pair.enter); err != nil {
			return nil, err
		}
		if kind == "eventfd" || kind == "pidfd" {
			if err := validateScalarPendingTransport(name, "flags", pair.enter, pair.exit); err != nil {
				return nil, err
			}
		}
		ret := "NORETURN"
		if pair.exit != "" {
			parsedRet, err := parseExitRetSemantics(name, pair.exit)
			if err != nil {
				return nil, err
			}
			ret = parsedRet
		}
		traceID, ok := iortypes.EnterTraceIDByName(name)
		if !ok {
			return nil, fmt.Errorf("sys_enter_%s is missing from generated runtime trace IDs", name)
		}
		runtimeFamily := string(traceID.Family())
		classifiedFamily := string(ClassifySyscallFamily("sys_enter_" + name))
		if runtimeFamily != classifiedFamily {
			return nil, fmt.Errorf("sys_enter_%s runtime family=%q differs from classifier=%q", name, runtimeFamily, classifiedFamily)
		}
		args, err := parseEnterArgSources(name, pair.enter, pair.exit)
		if err != nil {
			return nil, err
		}
		result[name] = syscallSemantics{
			kind:   kind,
			args:   args,
			ret:    ret,
			family: runtimeFamily,
		}
	}
	if len(kinds) != len(result) {
		return nil, fmt.Errorf("kind comments=%d enter handlers=%d", len(kinds), len(result))
	}
	return result, nil
}

// validateSchemaVersionWrite pins the ABI discriminator in every committed
// open/path/name/accept handler. This deliberately checks the rendered artifact, not
// only generator snippets, because newer-kernel-only handlers may be preserved
// manually when mage generate is run on an older host.
func validateSchemaVersionWrite(name, body string) error {
	body = stripCComments(body)
	match := eventStructRE.FindStringSubmatch(body)
	if match == nil {
		return fmt.Errorf("sys_enter_%s has no event struct", name)
	}
	want, ok := map[string]string{
		"open_event":   "OPEN_EVENT_SCHEMA_VERSION",
		"path_event":   "PATH_EVENT_SCHEMA_VERSION",
		"name_event":   "NAME_EVENT_SCHEMA_VERSION",
		"accept_event": "ACCEPT_EVENT_SCHEMA_VERSION",
	}[match[1]]
	if !ok {
		return nil
	}
	writes := cLValueWriteLocations(body, "ev->schema_version")
	exactRE := regexp.MustCompile(`(?m)^\s*ev->schema_version\s*=\s*` + want + `\s*;`)
	exact := exactRE.FindAllStringIndex(body, -1)
	if len(writes) != 1 || len(exact) != 1 || writes[0][0] != exact[0][0] {
		return fmt.Errorf("sys_enter_%s %s writes schema_version %d times with %d exact %s assignments, want 1/1", name, match[1], len(writes), len(exact), want)
	}
	return validateBeforeSubmit("sys_enter_"+name, body, exact[0][1])
}

func validatePathTargetStatus(name, body string) error {
	body = stripCComments(body)
	match := eventStructRE.FindStringSubmatch(body)
	if match == nil || match[1] != "path_event" {
		return nil
	}
	requiredRE := regexp.MustCompile(`(?m)^\s*ev->target_status\s*=\s*PATH_TARGET_REQUIRED\s*;`)
	required := requiredRE.FindAllStringIndex(body, -1)
	if len(required) != 1 {
		return fmt.Errorf("sys_enter_%s assigns PATH_TARGET_REQUIRED %d times, want 1", name, len(required))
	}
	writes := cLValueWriteLocations(body, "ev->target_status")
	if name != "utimensat" {
		if len(writes) != 1 {
			return fmt.Errorf("sys_enter_%s writes target_status %d times, want deterministic default only", name, len(writes))
		}
		return validateBeforeSubmit("sys_enter_"+name, body, required[0][1])
	}

	for fragment, description := range map[string]string{
		"struct __kernel_timespec ior_times[2] = {};":                                         "two-element timespec buffer",
		"if (ctx->args[2] != 0) {":                                                            "non-NULL timespec guard",
		"if (bpf_probe_read_user(&ior_times, sizeof(ior_times), (void *)ctx->args[2]) < 0) {": "guarded full-array read",
	} {
		if strings.Count(body, fragment) != 1 {
			return fmt.Errorf("sys_enter_utimensat must contain exactly one %s", description)
		}
	}
	unknownRE := regexp.MustCompile(`(?m)^\s*ev->target_status\s*=\s*PATH_TARGET_UNKNOWN\s*;`)
	skippedRE := regexp.MustCompile(`(?m)^\s*ev->target_status\s*=\s*PATH_TARGET_SKIPPED\s*;`)
	unknown := unknownRE.FindAllStringIndex(body, -1)
	skipped := skippedRE.FindAllStringIndex(body, -1)
	if len(writes) != 3 || len(unknown) != 1 || len(skipped) != 1 {
		return fmt.Errorf("sys_enter_utimensat target-status writes=%d required/unknown/skipped=%d/%d/%d, want 3/1/1/1", len(writes), len(required), len(unknown), len(skipped))
	}
	doubleOmitRE := regexp.MustCompile(`(?s)else\s+if\s*\(\s*IOR_UTIME_OMIT\s*==\s*ior_times\[0\]\.tv_nsec\s*&&\s*IOR_UTIME_OMIT\s*==\s*ior_times\[1\]\.tv_nsec\s*\)\s*\{\s*ev->target_status\s*=\s*PATH_TARGET_SKIPPED\s*;\s*\}`)
	if matches := doubleOmitRE.FindAllStringIndex(body, -1); len(matches) != 1 {
		return fmt.Errorf("sys_enter_utimensat must assign PATH_TARGET_SKIPPED in exactly one both-UTIME_OMIT branch, got %d", len(matches))
	}
	return validateBeforeSubmit("sys_enter_utimensat", body, skipped[0][1])
}

func parseExitRetSemantics(name, body string) (string, error) {
	body = stripCComments(body)
	eventStruct := eventStructRE.FindStringSubmatch(body)
	if eventStruct == nil {
		return "", fmt.Errorf("sys_exit_%s has no event struct", name)
	}
	allAssignments := cLValueWriteLocations(body, "ev->ret_type")
	assignments := retClassRE.FindAllStringSubmatchIndex(body, -1)
	if eventStruct[1] == "ret_event" {
		if len(allAssignments) != 1 || len(assignments) != 1 {
			return "", fmt.Errorf("sys_exit_%s ret_event has %d total/%d symbolic ret_type assignments, want 1/1", name, len(allAssignments), len(assignments))
		}
		if err := validateBeforeSubmit("sys_exit_"+name, body, assignments[0][1]); err != nil {
			return "", err
		}
		return body[assignments[0][2]:assignments[0][3]], nil
	}
	if len(allAssignments) != 0 {
		return "", fmt.Errorf("sys_exit_%s specialized %s has %d ret_type assignments, want 0", name, eventStruct[1], len(allAssignments))
	}
	return string(Unclassified), nil
}

func validateHandlerEventStruct(name, kind, body string) error {
	body = stripCComments(body)
	match := eventStructRE.FindStringSubmatch(body)
	if match == nil {
		return fmt.Errorf("sys_enter_%s has no event struct", name)
	}
	for registeredKind, registered := range kindRegistry {
		if registeredKind.MetadataName() == kind {
			want := registered.structName
			if match[1] != want {
				return fmt.Errorf("sys_enter_%s kind %s reserves %s, want %s", name, kind, match[1], want)
			}
			return nil
		}
	}
	return fmt.Errorf("sys_enter_%s has unknown kind %q", name, kind)
}

func parseEnterArgSources(name, enterBody, exitBody string) (map[string]int, error) {
	enterBody = stripCComments(enterBody)
	exitBody = stripCComments(exitBody)
	result := map[string]int{}
	addMatches := func(matches [][]string) error {
		for _, match := range matches {
			if err := addArgSource(name, result, match[1], mustArgIndex(match[2])); err != nil {
				return err
			}
		}
		return nil
	}
	directMatches := directEventArgRE.FindAllStringSubmatch(enterBody, -1)
	if err := validateDirectCaptureAssignments(name, enterBody, directMatches); err != nil {
		return nil, err
	}
	stringMatches := stringReadArgRE.FindAllStringSubmatch(enterBody, -1)
	if err := validateStringCaptureWrites(name, enterBody, stringMatches); err != nil {
		return nil, err
	}
	for _, matches := range [][][]string{
		directMatches,
		stringMatches,
	} {
		if err := addMatches(matches); err != nil {
			return nil, err
		}
	}
	pendingMatches := pendingArgRE.FindAllStringSubmatch(enterBody, -1)
	if err := validatePendingCaptureTransport(name, enterBody, exitBody); err != nil {
		return nil, err
	}
	if err := addMatches(pendingMatches); err != nil {
		return nil, err
	}

	localSources := map[string]int{}
	localSourceEnds := map[string]int{}
	for _, re := range []*regexp.Regexp{localArgRE, localReadArgRE} {
		for _, match := range re.FindAllStringSubmatchIndex(enterBody, -1) {
			local := enterBody[match[2]:match[3]]
			argIndex := mustArgIndex(enterBody[match[4]:match[5]])
			if err := addLocalArgSource(name, localSources, local, argIndex); err != nil {
				return nil, err
			}
			if err := validateLocalNotWrittenAfter(name, local, enterBody, match[1]); err != nil {
				return nil, err
			}
			localSourceEnds[local] = match[1]
		}
	}
	timerGuardStart := -1
	timerGuardEnd := -1
	timerFlagsArg := -1
	if match := timerAbstimeArgRE.FindStringSubmatchIndex(enterBody); match != nil {
		openingBrace := match[0] + strings.LastIndex(enterBody[match[0]:match[1]], "{")
		var ok bool
		timerGuardEnd, ok = matchingBrace(enterBody, openingBrace)
		if !ok {
			return nil, fmt.Errorf("sys_enter_%s has an unbalanced TIMER_ABSTIME guard", name)
		}
		timerGuardStart = openingBrace
		timerFlagsArg = mustArgIndex(enterBody[match[2]:match[3]])
	}
	eventAssignments := eventAssignmentRE.FindAllStringSubmatchIndex(enterBody, -1)
	for _, match := range eventAssignments {
		field := enterBody[match[2]:match[3]]
		rightHandSide := enterBody[match[4]:match[5]]
		for local, argIndex := range localSources {
			if regexp.MustCompile(`\b` + regexp.QuoteMeta(local) + `\b`).MatchString(rightHandSide) {
				if match[0] < localSourceEnds[local] {
					return nil, fmt.Errorf("sys_enter_%s emits local %s before reading its syscall argument", name, local)
				}
				if err := validateEventAssignmentIsLast(name, field, enterBody, match[0]); err != nil {
					return nil, err
				}
				if field == "requested_ns" && timerGuardStart >= 0 && (match[0] <= timerGuardStart || match[0] >= timerGuardEnd) {
					return nil, fmt.Errorf("sys_enter_%s emits requested_ns outside its TIMER_ABSTIME guard", name)
				}
				if err := addArgSource(name, result, field, argIndex); err != nil {
					return nil, err
				}
			}
		}
	}
	if timerFlagsArg >= 0 {
		if err := addArgSource(name, result, "flags", timerFlagsArg); err != nil {
			return nil, err
		}
	}
	return result, nil
}

func validatePendingCaptureTransport(name, enterBody, exitBody string) error {
	enterFields := map[string]struct{}{}
	for _, match := range pendingFieldRE.FindAllStringSubmatch(enterBody, -1) {
		enterFields[match[1]] = struct{}{}
	}
	exitFields := map[string]struct{}{}
	for _, match := range pendingRefRE.FindAllStringSubmatch(exitBody, -1) {
		exitFields[match[1]] = struct{}{}
	}
	if len(enterFields) == 0 && len(exitFields) == 0 {
		return nil
	}
	if !maps.Equal(enterFields, exitFields) {
		return fmt.Errorf("%s pending fields differ between enter %v and exit %v", name, mapKeysOf(enterFields), mapKeysOf(exitFields))
	}
	updateIndexes := pendingUpdateRE.FindAllStringSubmatchIndex(enterBody, -1)
	if len(updateIndexes) != 1 {
		return fmt.Errorf("sys_enter_%s has %d pending-map updates, want 1", name, len(updateIndexes))
	}
	lookupIndexes := pendingLookupRE.FindAllStringSubmatchIndex(exitBody, -1)
	if len(lookupIndexes) != 1 {
		return fmt.Errorf("sys_exit_%s has %d pending-map lookups, want 1", name, len(lookupIndexes))
	}
	update := updateIndexes[0]
	lookup := lookupIndexes[0]
	updateMap := enterBody[update[2]:update[3]]
	lookupMap := exitBody[lookup[2]:lookup[3]]
	if updateMap != lookupMap {
		return fmt.Errorf("%s pending-map update uses %s but lookup uses %s", name, updateMap, lookupMap)
	}
	pendingGuardRE := regexp.MustCompile(`(?m)^\s*if\s*\(pending\)\s*\{`)
	pendingGuards := pendingGuardRE.FindAllStringIndex(exitBody, -1)
	if len(pendingGuards) != 1 || pendingGuards[0][0] < lookup[1] {
		return fmt.Errorf("sys_exit_%s has %d null-check guards after its pending lookup, want 1", name, len(pendingGuards))
	}
	pendingGuardEnd, ok := matchingBrace(exitBody, pendingGuards[0][1]-1)
	if !ok {
		return fmt.Errorf("sys_exit_%s has an unbalanced pending null-check guard", name)
	}
	pendingReferences := pendingRefRE.FindAllStringIndex(exitBody, -1)
	lastPendingReferenceEnd := -1
	for _, reference := range pendingReferences {
		if reference[0] < pendingGuards[0][1] || reference[0] >= pendingGuardEnd {
			return fmt.Errorf("sys_exit_%s reads structured pending state outside its null-check guard", name)
		}
		lastPendingReferenceEnd = max(lastPendingReferenceEnd, reference[1])
	}
	deleteRE := regexp.MustCompile(`(?m)^\s*bpf_map_delete_elem\(&` + regexp.QuoteMeta(updateMap) + `,\s*&tid\);`)
	deletes := deleteRE.FindAllStringIndex(exitBody, -1)
	if len(deletes) != 1 || deletes[0][0] < pendingGuards[0][1] || deletes[0][0] < lastPendingReferenceEnd || deletes[0][0] >= pendingGuardEnd {
		return fmt.Errorf("sys_exit_%s deletes structured pending state %d times after its final guarded read, want 1", name, len(deletes))
	}
	for field := range enterFields {
		assignments := cLValueWriteLocations(enterBody, "pending."+field)
		if len(assignments) != 1 {
			return fmt.Errorf("sys_enter_%s assigns pending.%s %d times, want 1", name, field, len(assignments))
		}
		if assignments[0][1] > update[0] {
			return fmt.Errorf("sys_enter_%s updates its pending map before pending.%s is captured", name, field)
		}
	}
	seenArrayOutputs := map[string][]string{}
	for field := range enterFields {
		outputs, err := validatePendingFieldEmission(name, field, enterBody, exitBody)
		if err != nil {
			return err
		}
		if outputs != nil {
			seenArrayOutputs[field] = outputs
		}
	}
	expectedArrayOutputs := pendingArrayOutputExpectations[name]
	if !maps.EqualFunc(seenArrayOutputs, expectedArrayOutputs, slices.Equal) {
		return fmt.Errorf("%s pending array outputs=%v want %v", name, seenArrayOutputs, expectedArrayOutputs)
	}
	return nil
}

func validatePendingFieldEmission(name, field, enterBody, exitBody string) ([]string, error) {
	quotedField := regexp.QuoteMeta(field)
	directRE := regexp.MustCompile(`(?m)^\s*ev->` + quotedField + `\s*=\s*pending->` + quotedField + `\s*;`)
	scalarRE := regexp.MustCompile(`(?m)^\s*([a-z_][a-z0-9_]*)\s*=\s*pending->` + quotedField + `\s*;`)
	userReadRE := regexp.MustCompile(`(?m)^\s*(?:if\s*\(\s*)?bpf_probe_read_user\(&([a-z_][a-z0-9_]*),[^\n]*pending->` + quotedField + `\b`)
	direct := directRE.FindAllStringSubmatchIndex(exitBody, -1)
	scalars := scalarRE.FindAllStringSubmatchIndex(exitBody, -1)
	userReads := userReadRE.FindAllStringSubmatchIndex(exitBody, -1)
	if len(direct)+len(scalars)+len(userReads) != 1 {
		return nil, fmt.Errorf("sys_exit_%s has %d emission paths for pending.%s, want 1", name, len(direct)+len(scalars)+len(userReads), field)
	}
	if len(direct) == 1 {
		return nil, validateEventAssignmentIsLast(name, field, exitBody, direct[0][0])
	}
	if len(scalars) == 1 {
		local := exitBody[scalars[0][2]:scalars[0][3]]
		if err := validatePendingEnterFieldEmission(name, field, enterBody); err != nil {
			return nil, err
		}
		return nil, requireLocalEventEmission(name, field, local, field, exitBody, scalars[0][1])
	}

	buffer := exitBody[userReads[0][2]:userReads[0][3]]
	completeReadRE := regexp.MustCompile(`(?m)^\s*if\s*\(bpf_probe_read_user\(&` + regexp.QuoteMeta(buffer) + `,\s*sizeof\(` + regexp.QuoteMeta(buffer) + `\),\s*\(void \*\)pending->` + quotedField + `\)\s*==\s*0\)\s*\{`)
	completeReads := completeReadRE.FindAllStringIndex(exitBody, -1)
	if len(completeReads) != 1 || completeReads[0][0] != userReads[0][0] {
		return nil, fmt.Errorf("sys_exit_%s does not completely read pending.%s into %s under a success predicate", name, field, buffer)
	}
	readBlockEnd, ok := matchingBrace(exitBody, completeReads[0][1]-1)
	if !ok {
		return nil, fmt.Errorf("sys_exit_%s has an unbalanced successful read block for pending.%s", name, field)
	}
	successGuardRE := regexp.MustCompile(`(?m)^\s*if\s*\(ctx->ret\s*==\s*0\s*&&\s*pending->` + quotedField + `\s*!=\s*0\)\s*\{`)
	successGuards := successGuardRE.FindAllStringIndex(exitBody, -1)
	if len(successGuards) != 1 || successGuards[0][0] > userReads[0][0] {
		return nil, fmt.Errorf("sys_exit_%s does not guard pending.%s output read on syscall success and a non-null pointer", name, field)
	}
	guardEnd, ok := matchingBrace(exitBody, successGuards[0][1]-1)
	if !ok || userReads[0][0] >= guardEnd {
		return nil, fmt.Errorf("sys_exit_%s pending.%s output read is outside its success/non-null guard", name, field)
	}
	if err := validateLocalNotWrittenAfter(name, buffer, exitBody, userReads[0][1]); err != nil {
		return nil, err
	}
	arrayRE := regexp.MustCompile(`(?m)^\s*[a-z_][a-z0-9_ ]+\s+` + regexp.QuoteMeta(buffer) + `\[([0-9]+)\];`)
	array := arrayRE.FindAllStringSubmatch(exitBody, -1)
	if len(array) != 1 {
		return nil, fmt.Errorf("sys_exit_%s has %d array declarations for pending.%s buffer %s, want 1", name, len(array), field, buffer)
	}
	arrayLength := mustArgIndex(array[0][1])
	derivedRE := regexp.MustCompile(`(?m)^\s*([a-z_][a-z0-9_]*)\s*=.*\b` + regexp.QuoteMeta(buffer) + `\[([0-9]+)\]\s*;`)
	derived := derivedRE.FindAllStringSubmatchIndex(exitBody, -1)
	if len(derived) != arrayLength {
		return nil, fmt.Errorf("sys_exit_%s derives %d values from pending.%s buffer %s, want %d", name, len(derived), field, buffer, arrayLength)
	}
	seenIndexes := map[int]struct{}{}
	outputs := make([]string, arrayLength)
	for _, match := range derived {
		local := exitBody[match[2]:match[3]]
		index := mustArgIndex(exitBody[match[4]:match[5]])
		if match[0] < userReads[0][1] {
			return nil, fmt.Errorf("sys_exit_%s derives %s from pending.%s before reading buffer %s", name, local, field, buffer)
		}
		if match[0] >= readBlockEnd {
			return nil, fmt.Errorf("sys_exit_%s derives %s from pending.%s outside the successful read block", name, local, field)
		}
		if index < 0 || index >= arrayLength {
			return nil, fmt.Errorf("sys_exit_%s reads out-of-range %s[%d] for pending.%s", name, buffer, index, field)
		}
		if _, exists := seenIndexes[index]; exists {
			return nil, fmt.Errorf("sys_exit_%s reads %s[%d] more than once for pending.%s", name, buffer, index, field)
		}
		seenIndexes[index] = struct{}{}
		outputs[index] = local
		if err := requireLocalEventEmission(name, field, local, local, exitBody, match[1]); err != nil {
			return nil, err
		}
	}
	return outputs, nil
}

func validatePendingEnterFieldEmission(name, field, enterBody string) error {
	assignmentRE := regexp.MustCompile(`(?m)^\s*ev->` + regexp.QuoteMeta(field) + `\s*=\s*pending\.` + regexp.QuoteMeta(field) + `\s*;`)
	assignments := assignmentRE.FindAllStringIndex(enterBody, -1)
	if len(assignments) != 1 {
		return fmt.Errorf("sys_enter_%s emits pending.%s to its matching event field %d times, want 1", name, field, len(assignments))
	}
	return validateEventAssignmentIsLast(name, field, enterBody, assignments[0][0])
}

func validateScalarPendingTransport(name, field, enterBody, exitBody string) error {
	enterBody = stripCComments(enterBody)
	exitBody = stripCComments(exitBody)
	quotedField := regexp.QuoteMeta(field)
	producerRE := regexp.MustCompile(`(?m)^\s*(?:[a-z_][a-z0-9_ ]+\s+)?` + quotedField + `\s*=[^;]+;`)
	producers := producerRE.FindAllStringIndex(enterBody, -1)
	if len(producers) != 1 {
		return fmt.Errorf("sys_enter_%s produces scalar pending field %s %d times, want 1", name, field, len(producers))
	}
	updateRE := regexp.MustCompile(`(?m)^\s*bpf_map_update_elem\(&([a-z0-9_]+),\s*&tid,\s*&` + quotedField + `,\s*BPF_ANY\);`)
	updates := updateRE.FindAllStringSubmatchIndex(enterBody, -1)
	if len(updates) != 1 {
		return fmt.Errorf("sys_enter_%s has %d scalar pending-map updates for %s, want 1", name, len(updates), field)
	}
	if producers[0][1] > updates[0][0] {
		return fmt.Errorf("sys_enter_%s updates its scalar pending map before producing %s", name, field)
	}
	if err := validateLocalNotWrittenAfter(name, field, enterBody, producers[0][1]); err != nil {
		return err
	}
	if err := requireLocalEventEmission(name, field, field, field, enterBody, producers[0][1]); err != nil {
		return err
	}

	lookupRE := regexp.MustCompile(`(?m)^\s*[a-z_][a-z0-9_ ]+\s+\*pending\s*=\s*bpf_map_lookup_elem\(&([a-z0-9_]+),\s*&tid\);`)
	lookups := lookupRE.FindAllStringSubmatchIndex(exitBody, -1)
	if len(lookups) != 1 {
		return fmt.Errorf("sys_exit_%s has %d scalar pending-map lookups for %s, want 1", name, len(lookups), field)
	}
	updateMap := enterBody[updates[0][2]:updates[0][3]]
	lookupMap := exitBody[lookups[0][2]:lookups[0][3]]
	if updateMap != lookupMap {
		return fmt.Errorf("%s scalar pending-map update uses %s but lookup uses %s", name, updateMap, lookupMap)
	}
	restoreRE := regexp.MustCompile(`(?m)^\s*` + quotedField + `\s*=\s*\*pending\s*;`)
	restores := restoreRE.FindAllStringIndex(exitBody, -1)
	if len(restores) != 1 || restores[0][0] < lookups[0][1] {
		return fmt.Errorf("sys_exit_%s restores scalar pending field %s %d times after lookup, want 1", name, field, len(restores))
	}
	pendingGuardRE := regexp.MustCompile(`(?m)^\s*if\s*\(pending\)\s*\{`)
	pendingGuards := pendingGuardRE.FindAllStringIndex(exitBody, -1)
	if len(pendingGuards) != 1 || pendingGuards[0][0] < lookups[0][1] {
		return fmt.Errorf("sys_exit_%s has %d null-check guards for scalar pending field %s after lookup, want 1", name, len(pendingGuards), field)
	}
	pendingGuardEnd, ok := matchingBrace(exitBody, pendingGuards[0][1]-1)
	if !ok || restores[0][0] < pendingGuards[0][1] || restores[0][0] >= pendingGuardEnd {
		return fmt.Errorf("sys_exit_%s restores scalar pending field %s outside its null-check guard", name, field)
	}
	deleteRE := regexp.MustCompile(`(?m)^\s*bpf_map_delete_elem\(&` + regexp.QuoteMeta(updateMap) + `,\s*&tid\);`)
	deletes := deleteRE.FindAllStringIndex(exitBody, -1)
	if len(deletes) != 1 || deletes[0][0] < pendingGuards[0][1] || deletes[0][0] < restores[0][1] || deletes[0][0] >= pendingGuardEnd {
		return fmt.Errorf("sys_exit_%s deletes scalar pending field %s %d times after its guarded restore, want 1", name, field, len(deletes))
	}
	if err := validateLocalNotWrittenAfter(name, field, exitBody, restores[0][1]); err != nil {
		return err
	}
	return requireLocalEventEmission(name, field, field, field, exitBody, restores[0][1])
}

func requireLocalEventEmission(name, pendingField, local, eventField, exitBody string, sourceEnd int) error {
	if err := validateLocalNotWrittenAfter(name, local, exitBody, sourceEnd); err != nil {
		return err
	}
	assignments := eventAssignmentRE.FindAllStringSubmatchIndex(exitBody, -1)
	matching := -1
	for _, match := range assignments {
		field := exitBody[match[2]:match[3]]
		if field != eventField {
			continue
		}
		if matching != -1 {
			return fmt.Errorf("sys_exit_%s assigns event field %s more than once for pending.%s", name, eventField, pendingField)
		}
		if strings.TrimSpace(exitBody[match[4]:match[5]]) != local {
			return fmt.Errorf("sys_exit_%s assigns event field %s from %q, want %s for pending.%s", name, eventField, strings.TrimSpace(exitBody[match[4]:match[5]]), local, pendingField)
		}
		matching = match[0]
	}
	if matching < sourceEnd {
		return fmt.Errorf("sys_exit_%s does not emit local %s to event field %s after deriving it from pending.%s", name, local, eventField, pendingField)
	}
	return validateEventAssignmentIsLast(name, eventField, exitBody, matching)
}

func validateDirectCaptureAssignments(name, enterBody string, directMatches [][]string) error {
	for _, match := range directMatches {
		writes := cLValueWriteLocations(enterBody, "ev->"+match[1])
		if len(writes) != 1 {
			return fmt.Errorf("sys_enter_%s writes captured field %s %d times, want 1", name, match[1], len(writes))
		}
		if err := validateBeforeSubmit("sys_enter_"+name, enterBody, writes[0][1]); err != nil {
			return err
		}
	}
	return nil
}

func validateStringCaptureWrites(name, enterBody string, stringMatches [][]string) error {
	probeIndexes := stringReadArgRE.FindAllStringSubmatchIndex(enterBody, -1)
	for _, match := range stringMatches {
		field := match[1]
		if writes := cLValueAssignmentLocations(enterBody, "ev->"+field); len(writes) != 0 {
			return fmt.Errorf("sys_enter_%s directly writes string-captured field %s %d times, want 0", name, match[1], len(writes))
		}
		probeStart := -1
		probeEnd := -1
		for _, indexes := range probeIndexes {
			if enterBody[indexes[2]:indexes[3]] == field {
				probeStart = indexes[0]
				probeEnd = indexes[1]
				break
			}
		}
		exactProbeRE := regexp.MustCompile(`bpf_probe_read_user_str\(\s*ev->` + regexp.QuoteMeta(field) + `,\s*sizeof\(ev->` + regexp.QuoteMeta(field) + `\),\s*\(void\s*\*\)\s*ctx->args\[` + regexp.QuoteMeta(match[2]) + `\]\s*\)`)
		if exactProbes := exactProbeRE.FindAllStringIndex(enterBody, -1); len(exactProbes) != 1 {
			return fmt.Errorf("sys_enter_%s reads string field %s with its full reviewed size %d times, want 1", name, field, len(exactProbes))
		}
		if field == "pathname" || field == "oldname" || field == "newname" ||
			(field == "filename" && requiresFilenameFallback(name)) {
			if err := validatePathReadProtocol(name, enterBody, field, match[2]); err != nil {
				return err
			}
		}
		if field == "filename" {
			if err := validateFilenameFallback(name, enterBody, match[2]); err != nil {
				return err
			}
		}
		filenameMemset := `__builtin_memset\(&\(ev->filename\),\s*0,\s*sizeof\(ev->filename\)\s*\+\s*sizeof\(ev->comm\)\);`
		filenameStorageFields := []string{"filename", "comm"}
		if name == "fsopen" || name == "memfd_create" {
			filenameMemset = `__builtin_memset\(&\(ev->filename\),\s*0,\s*sizeof\(ev->filename\)\);`
			filenameStorageFields = []string{"filename"}
		}
		memsetPattern, ok := map[string]string{
			"filename": filenameMemset,
			"newname":  `__builtin_memset\(&\(ev->oldname\),\s*0,\s*sizeof\(ev->oldname\)\s*\+\s*sizeof\(ev->newname\)\);`,
			"oldname":  `__builtin_memset\(&\(ev->oldname\),\s*0,\s*sizeof\(ev->oldname\)\s*\+\s*sizeof\(ev->newname\)\);`,
			"pathname": `__builtin_memset\(&\(ev->pathname\),\s*0,\s*sizeof\(ev->pathname\)\);`,
		}[field]
		if !ok {
			return fmt.Errorf("sys_enter_%s has no reviewed initializer shape for string field %s", name, field)
		}
		memsetRE := regexp.MustCompile(`(?m)^\s*` + memsetPattern + `$`)
		memsets := memsetRE.FindAllStringIndex(enterBody, -1)
		storageFields := map[string][]string{
			"filename": filenameStorageFields,
			"newname":  {"oldname", "newname"},
			"oldname":  {"oldname", "newname"},
			"pathname": {"pathname"},
		}[field]
		quotedStorageFields := make([]string, len(storageFields))
		for i, storageField := range storageFields {
			quotedStorageFields[i] = regexp.QuoteMeta(storageField)
		}
		allStorageMemsetRE := regexp.MustCompile(`(?m)^\s*__builtin_memset\(&\(ev->(?:` + strings.Join(quotedStorageFields, `|`) + `)\),[^;]*;\s*$`)
		allStorageMemsets := allStorageMemsetRE.FindAllStringIndex(enterBody, -1)
		if len(memsets) != 1 || len(allStorageMemsets) != 1 || memsets[0][1] > probeStart {
			return fmt.Errorf("sys_enter_%s initializes string-captured field %s %d times before its probe, want 1", name, field, len(memsets))
		}
		if err := validateBeforeSubmit("sys_enter_"+name, enterBody, probeEnd); err != nil {
			return err
		}
	}
	return nil
}

func requiresFilenameFallback(name string) bool {
	_, ok := filenameFallbackSyscalls[name]
	return ok
}

// validatePathReadProtocol independently pins the full three-state capture
// protocol in the committed C artifact. Merely finding the probe is not
// enough: a zero-filled destination means three different things unless the
// handler separately records a NULL pointer, a successful read (including an
// empty string), and a failed non-NULL nofault read. The validation is per
// destination field, which prevents one side of a name_event from borrowing
// the other side's guard or status writes.
func validatePathReadProtocol(name, enterBody, field, argIndex string) error {
	statusField := field + "_status"
	quotedArg := regexp.QuoteMeta(argIndex)
	quotedField := regexp.QuoteMeta(field)
	quotedStatus := regexp.QuoteMeta(statusField)

	nullGuardRE := regexp.MustCompile(`(?m)^\s*if\s*\(ctx->args\[` + quotedArg + `\]\s*==\s*0\)\s*\{`)
	nullGuards := nullGuardRE.FindAllStringIndex(enterBody, -1)
	if len(nullGuards) != 1 {
		return fmt.Errorf("sys_enter_%s field %s has %d NULL-pointer guards for args[%s], want 1", name, field, len(nullGuards), argIndex)
	}
	nullEnd, ok := matchingBrace(enterBody, nullGuards[0][1]-1)
	if !ok {
		return fmt.Errorf("sys_enter_%s field %s has an unterminated NULL-pointer guard", name, field)
	}

	assignment := func(value string) [][]int {
		re := regexp.MustCompile(`(?m)^\s*ev->` + quotedStatus + `\s*=\s*` + value + `\s*;`)
		return re.FindAllStringIndex(enterBody, -1)
	}
	nulls := assignment("PATH_READ_NULL")
	oks := assignment("PATH_READ_OK")
	failures := assignment("PATH_READ_FAILED")
	if len(nulls) != 1 || nulls[0][0] <= nullGuards[0][0] || nulls[0][1] > nullEnd {
		return fmt.Errorf("sys_enter_%s field %s assigns PATH_READ_NULL %d times inside its NULL guard, want 1", name, field, len(nulls))
	}

	elseRE := regexp.MustCompile(`(?m)^\s*\}\s*else\s*\{`)
	elseLocation := elseRE.FindStringIndex(enterBody[nullEnd:])
	if elseLocation == nil || elseLocation[0] != 0 {
		return fmt.Errorf("sys_enter_%s field %s has no else block paired with its NULL guard", name, field)
	}
	elseOpen := nullEnd + elseLocation[1] - 1
	elseEnd, ok := matchingBrace(enterBody, elseOpen)
	if !ok {
		return fmt.Errorf("sys_enter_%s field %s has an unterminated non-NULL block", name, field)
	}
	if len(oks) != 1 || oks[0][0] <= elseOpen || oks[0][1] > elseEnd {
		return fmt.Errorf("sys_enter_%s field %s assigns PATH_READ_OK %d times inside its non-NULL block, want 1", name, field, len(oks))
	}

	probeGuardRE := regexp.MustCompile(`(?m)^\s*if\s*\(bpf_probe_read_user_str\(\s*ev->` + quotedField + `,\s*sizeof\(ev->` + quotedField + `\),\s*\(void\s*\*\)\s*ctx->args\[` + quotedArg + `\]\s*\)\s*<\s*0\)\s*(\{)?\s*$`)
	probeGuards := probeGuardRE.FindAllStringSubmatchIndex(enterBody, -1)
	if len(probeGuards) != 1 || probeGuards[0][0] <= oks[0][1] || probeGuards[0][0] >= elseEnd {
		return fmt.Errorf("sys_enter_%s field %s has %d failed-read guards after PATH_READ_OK, want 1", name, field, len(probeGuards))
	}
	if len(failures) != 1 {
		return fmt.Errorf("sys_enter_%s field %s assigns PATH_READ_FAILED %d times, want 1", name, field, len(failures))
	}
	if probeGuards[0][2] >= 0 {
		probeEnd, matched := matchingBrace(enterBody, probeGuards[0][1]-1)
		if !matched || failures[0][0] <= probeGuards[0][1] || failures[0][1] > probeEnd {
			return fmt.Errorf("sys_enter_%s field %s does not assign PATH_READ_FAILED inside its failed-read block", name, field)
		}
	} else {
		failedStatementRE := regexp.MustCompile(`^\s*ev->` + quotedStatus + `\s*=\s*PATH_READ_FAILED\s*;`)
		if !failedStatementRE.MatchString(enterBody[probeGuards[0][1]:]) {
			return fmt.Errorf("sys_enter_%s field %s does not make PATH_READ_FAILED the guarded failed-read statement", name, field)
		}
	}
	return nil
}

func validateFilenameFallback(name, enterBody, argIndex string) error {
	allStashes := regexp.MustCompile(`\bior_stash_pending_filename\s*\(`).FindAllStringIndex(enterBody, -1)
	requiresFallback := requiresFilenameFallback(name)
	want := 0
	if requiresFallback {
		want = 1
	}
	if len(allStashes) != want {
		return fmt.Errorf("sys_enter_%s has %d pending-filename stashes, want %d", name, len(allStashes), want)
	}
	if !requiresFallback {
		return nil
	}
	quotedArg := regexp.QuoteMeta(argIndex)
	guardedStashRE := regexp.MustCompile(`(?ms)^\s*if\s*\(bpf_probe_read_user_str\(\s*ev->filename,\s*sizeof\(ev->filename\),\s*\(void\s*\*\)\s*ctx->args\[` + quotedArg + `\]\s*\)\s*<\s*0\)\s*\{\s*ev->filename_status\s*=\s*PATH_READ_FAILED\s*;\s*ior_stash_pending_filename\(tid,\s*ctx->args\[` + quotedArg + `\]\);\s*\}`)
	if guarded := guardedStashRE.FindAllStringIndex(enterBody, -1); len(guarded) != 1 {
		return fmt.Errorf("sys_enter_%s does not stash the exact filename argument once after a failed probe", name)
	}
	return nil
}

func validateLocalNotWrittenAfter(name, local, body string, sourceEnd int) error {
	quotedLocal := regexp.QuoteMeta(local)
	lvalueSuffix := `(?:(?:\[[^]]+\])|(?:(?:\.|->)[a-z_][a-z0-9_]*))*`
	assignmentRE := regexp.MustCompile(`(?m)^\s*(?:[a-z_][a-z0-9_ ]+\s+)?` + quotedLocal + lvalueSuffix + `\s*(?:(?:<<|>>|[+\-*/%&|^])?=)`)
	prefixIncrementRE := regexp.MustCompile(`(?m)^\s*(?:\+\+|--)\s*` + quotedLocal + lvalueSuffix + `\s*;`)
	suffixIncrementRE := regexp.MustCompile(`(?m)^\s*` + quotedLocal + lvalueSuffix + `\s*(?:\+\+|--)\s*;`)
	probeReadRE := regexp.MustCompile(`(?m)^\s*(?:if\s*\(\s*)?bpf_probe_read_user\(&` + quotedLocal + `\b`)
	memsetRE := regexp.MustCompile(`(?m)^\s*__builtin_memset\(\s*&\(?\s*` + quotedLocal + `\b`)
	for _, re := range []*regexp.Regexp{assignmentRE, prefixIncrementRE, suffixIncrementRE, probeReadRE, memsetRE} {
		for _, location := range re.FindAllStringIndex(body, -1) {
			if location[0] >= sourceEnd {
				return fmt.Errorf("%s overwrites captured local %s after reading its syscall argument", name, local)
			}
		}
	}
	return nil
}

func validateEventAssignmentIsLast(name, field, body string, assignmentStart int) error {
	writes := cLValueWriteLocations(body, "ev->"+field)
	if len(writes) == 0 || writes[len(writes)-1][0] != assignmentStart {
		return fmt.Errorf("%s overwrites captured event field %s after its argument-derived assignment", name, field)
	}
	return validateBeforeSubmit(name, body, writes[len(writes)-1][1])
}

func validateBeforeSubmit(handler, body string, semanticEnd int) error {
	submissions := ringbufSubmitRE.FindAllStringIndex(body, -1)
	if len(submissions) != 1 {
		return fmt.Errorf("%s has %d ring-buffer submissions, want 1", handler, len(submissions))
	}
	if semanticEnd > submissions[0][0] {
		return fmt.Errorf("%s writes reviewed semantics after its ring-buffer submission", handler)
	}
	return nil
}

func matchingBrace(body string, openingBrace int) (int, bool) {
	if openingBrace < 0 || openingBrace >= len(body) || body[openingBrace] != '{' {
		return 0, false
	}
	depth := 1
	for i := openingBrace + 1; i < len(body); i++ {
		switch body[i] {
		case '{':
			depth++
		case '}':
			depth--
			if depth == 0 {
				return i, true
			}
		}
	}
	return 0, false
}

func cLValueWriteLocations(body, lvalue string) [][]int {
	result := cLValueAssignmentLocations(body, lvalue)
	quoted := regexp.QuoteMeta(lvalue)
	memsetRE := regexp.MustCompile(`(?m)^\s*__builtin_memset\(\s*&\(?\s*` + quoted + `\s*\)?\s*,`)
	result = append(result, memsetRE.FindAllStringIndex(body, -1)...)
	sort.Slice(result, func(i, j int) bool { return result[i][0] < result[j][0] })
	return result
}

func cLValueAssignmentLocations(body, lvalue string) [][]int {
	quoted := regexp.QuoteMeta(lvalue)
	assignmentRE := regexp.MustCompile(`(?m)^\s*` + quoted + `(?:\[[^]]+\])?\s*(?:(?:<<|>>|[+\-*/%&|^])?=)`)
	prefixIncrementRE := regexp.MustCompile(`(?m)^\s*(?:\+\+|--)\s*` + quoted + `(?:\[[^]]+\])?\s*;`)
	suffixIncrementRE := regexp.MustCompile(`(?m)^\s*` + quoted + `(?:\[[^]]+\])?\s*(?:\+\+|--)\s*;`)
	var result [][]int
	for _, re := range []*regexp.Regexp{assignmentRE, prefixIncrementRE, suffixIncrementRE} {
		result = append(result, re.FindAllStringIndex(body, -1)...)
	}
	sort.Slice(result, func(i, j int) bool { return result[i][0] < result[j][0] })
	return result
}

func addArgSource(name string, result map[string]int, field string, argIndex int) error {
	if previous, exists := result[field]; exists {
		return fmt.Errorf("sys_enter_%s captures %s from args[%d] after args[%d]", name, field, argIndex, previous)
	}
	result[field] = argIndex
	return nil
}

func addLocalArgSource(name string, result map[string]int, local string, argIndex int) error {
	if previous, exists := result[local]; exists {
		return fmt.Errorf("sys_enter_%s reads local %s from args[%d] after args[%d]", name, local, argIndex, previous)
	}
	result[local] = argIndex
	return nil
}

func stripCComments(source string) string {
	return stripSelectedCComments(source, true)
}

func stripCBlockComments(source string) string {
	return stripSelectedCComments(source, false)
}

func stripDisabledCPreprocessorBlocks(source string) string {
	return disabledIfZeroRE.ReplaceAllStringFunc(source, func(block string) string {
		result := []byte(block)
		for i := range result {
			if result[i] != '\n' {
				result[i] = ' '
			}
		}
		return string(result)
	})
}

func stripSelectedCComments(source string, stripLineComments bool) string {
	result := []byte(source)
	var quote byte
	for i := 0; i < len(result); {
		if quote != 0 {
			if result[i] == '\\' && i+1 < len(result) {
				i += 2
				continue
			}
			if result[i] == quote {
				quote = 0
			}
			i++
			continue
		}
		if result[i] == '"' || result[i] == '\'' {
			quote = result[i]
			i++
			continue
		}
		if result[i] != '/' || i+1 == len(result) {
			i++
			continue
		}
		switch result[i+1] {
		case '/':
			if !stripLineComments {
				i += 2
				for i < len(result) && result[i] != '\n' {
					i++
				}
				continue
			}
			result[i], result[i+1] = ' ', ' '
			i += 2
			for i < len(result) && result[i] != '\n' {
				result[i] = ' '
				i++
			}
		case '*':
			result[i], result[i+1] = ' ', ' '
			i += 2
			for i < len(result) {
				if i+1 < len(result) && result[i] == '*' && result[i+1] == '/' {
					result[i], result[i+1] = ' ', ' '
					i += 2
					break
				}
				if result[i] != '\n' {
					result[i] = ' '
				}
				i++
			}
		default:
			i++
		}
	}
	return string(result)
}

func mustArgIndex(value string) int {
	index, err := strconv.Atoi(value)
	if err != nil {
		panic(fmt.Sprintf("invalid argument index %q: %v", value, err))
	}
	return index
}

func readGeneratedTracepointsResult() (string, error) {
	_, filename, _, ok := runtime.Caller(0)
	if !ok {
		return "", fmt.Errorf("runtime.Caller failed")
	}
	repoRoot := filepath.Clean(filepath.Join(filepath.Dir(filename), "..", ".."))
	content, err := os.ReadFile(filepath.Join(repoRoot, "internal", "c", "generated_tracepoints_result.txt"))
	if err != nil {
		return "", err
	}
	return string(content), nil
}
