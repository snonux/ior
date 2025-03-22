#!/usr/bin/env raku

use v6.d;

# TODO: Also add sys_enter_open_by_handler_at
 
# Grammar to parse  /sys/kernel/tracing/events/syscalls/sys_{enter,exit}_*/format'
grammar SysTraceFormat {
    rule TOP { <whole-format-section>* }
    rule whole-format-section { <name> <id> <format> <print-fmt> }
    rule name { 'name:' <identifier> }
    rule id { 'ID:' <number> }
    rule format { 'format:' <field>* }

    rule field { 'field:' <field-elements> }
    rule field-elements { <field-declaration> <field-offset> <field-size> <field-signed> }
    rule field-declaration { <field-type>+ <identifier> ';' }

    token field-type { <-[ \t]> }
    token field-offset { 'offset:' <number> ';' }
    token field-size { 'size:' <number> ';' }
    token field-signed { 'signed:' <cbool> ';' }

    token identifier { <[a..zA..Z0..9_]>+ }
    token number { \d+ }
    token cbool { '0' | '1' }
    token print-fmt { 'print fmt' <-[\n]>+ "\n" }
}

class Field {
    has Str $.type is rw;
    has Str $.name is rw;
    has Int $.offset is rw;
    has Int $.size is rw;
    has Bool $.signed is rw;
}

role TracepointTemplate {
    method template(%vals --> Str) {
        my Bool \is-enter = %vals<name>.split('_')[1] eq 'enter';
        my Str \ctx-struct = is-enter ?? 'trace_event_raw_sys_enter' !! 'trace_event_raw_sys_exit';
        my Str @parts;

        @parts.push: qq:to/BPF_C_CODE/;
        SEC("tracepoint/syscalls/{%vals<name>}")
        int handle_{%vals<name>.lc}(struct {ctx-struct} *ctx) \{
            __u32 pid, tid;
            if (filter(&pid, &tid))
                return 0;

            struct {%vals<event-struct>} *ev = bpf_ringbuf_reserve(&event_map, sizeof(struct {%vals<event-struct>}), 0);
            if (!ev)
                return 0;

            ev->event_type = {(is-enter ?? 'ENTER_' !! 'EXIT_') ~ %vals<event-struct>.uc};
            ev->trace_id = {%vals<name>.uc};
            ev->pid = pid;
            ev->tid = tid;
            ev->time = bpf_ktime_get_boot_ns();
        BPF_C_CODE

        @parts.push: %vals<extra> if %vals<extra>:exists;

        @parts.push: qq:to/BPF_C_CODE/;

            bpf_ringbuf_submit(ev, 0);
            return 0;
        \}
        BPF_C_CODE

        [~] @parts;
    }
}

class FdTracepoint does TracepointTemplate {
    method generate-bpf-c-tracepoint(%vals --> Str) {
        my Str $extra = qq:to/BPF_C_CODE/;
            ev->fd = (__s32)ctx->args[0];
        BPF_C_CODE
        self.template: %vals.append( ( event-struct => 'fd_event', :$extra ).hash );
    }
}

class NameTracepoint does TracepointTemplate {
    method generate-bpf-c-tracepoint(%vals --> Str) {
        my Int \oldname-field-number = %vals<format>.field-number('oldname');
        my Int \newname-field-number = %vals<format>.field-number('newname');
        my Str $extra = qq:to/BPF_C_CODE/;
            __builtin_memset(\&(ev->oldname), 0, sizeof(ev->oldname) + sizeof(ev->newname));
            bpf_probe_read_user_str(ev->oldname, sizeof(ev->oldname), (void*)ctx->args[{oldname-field-number}]);
            bpf_probe_read_user_str(ev->newname, sizeof(ev->newname), (void*)ctx->args[{newname-field-number}]);
        BPF_C_CODE
        self.template: %vals.append( ( event-struct => 'name_event', :$extra ).hash );
    }
}

class OpenTracepoint does TracepointTemplate {
    method generate-bpf-c-tracepoint(%vals --> Str) {
        my Int \filename-field-number = %vals<format>.field-number('filename');
        my Int \flags-field-number = %vals<format>.field-number('flags');
        my Str $extra = qq:to/BPF_C_CODE/;
            __builtin_memset(\&(ev->filename), 0, sizeof(ev->filename) + sizeof(ev->comm));
            bpf_probe_read_user_str(ev->filename, sizeof(ev->filename), (void *)ctx->args[{filename-field-number}]);
            bpf_get_current_comm(\&ev->comm, sizeof(ev->comm));
            ev->flags = {flags-field-number > -1 ?? ('ctx->args[' ~ flags-field-number ~ '];') !! '-1; // Probably OK'}
        BPF_C_CODE
        self.template: %vals.append( ( event-struct => 'open_event', :$extra ).hash );
    }
}

class PathnameTracepoint does TracepointTemplate {
    method generate-bpf-c-tracepoint(%vals --> Str) {
        my Int \field-number = %vals<format>.field-number('pathname');
        my Str $extra = qq:to/BPF_C_CODE/;
            __builtin_memset(\&(ev->pathname), 0, sizeof(ev->pathname));
            bpf_probe_read_user_str(ev->pathname, sizeof(ev->pathname), (void*)ctx->args[{field-number}]);
        BPF_C_CODE
        self.template: %vals.append( ( event-struct => 'path_event', :$extra ).hash );
    }
}

class RetTracepoint does TracepointTemplate {
    method generate-bpf-c-tracepoint(%vals --> Str) {
        my Str $extra = q:to/BPF_C_CODE/;
            ev->ret = ctx->ret; 
        BPF_C_CODE
        self.template: %vals.append( ( event-struct => 'ret_event', :$extra ).hash );
    }
}

class NullTracepoint does TracepointTemplate {
    method generate-bpf-c-tracepoint(%vals --> Str) {
        self.template: %vals.append( ( event-struct => 'null_event' ).hash );
    }
}

class FcntlTracepoint does TracepointTemplate {
    method generate-bpf-c-tracepoint(%vals --> Str) {
        my Int \fd-field-number = %vals<format>.field-number('fd');
        my Int \cmd-field-number = %vals<format>.field-number('cmd');
        my Int \arg-field-number = %vals<format>.field-number('arg');
        my Str $extra = qq:to/BPF_C_CODE/;
            ev->fd = {'ctx->args[' ~ fd-field-number ~ ']'};
            ev->cmd = {'ctx->args[' ~ cmd-field-number ~ ']'};
            ev->arg = {'ctx->args[' ~ arg-field-number ~ ']'};
        BPF_C_CODE
        self.template: %vals.append( ( event-struct => 'fcntl_event', :$extra ).hash );
    }
}

class Format {
    has Field @!internal-fields; # Fields not accessible from raw tracepoints.
    has Field @!external-fields; # Fields accessible from raw tracepoints.
    has Bool $!is-external = False; # Track internal/external field sections.
    has Str $.name is rw;
    has Int $.id is rw;
    has $.format-impl;

    method push(Field \field) {
        $!is-external = True if field.name eq '__syscall_nr'; 

        if $!is-external {
            push @!external-fields: field;
        } else {
            push @!internal-fields: field;
            return;
        }

        self.set-format-impl(field.name, field.type);
    }

    # TODO: implement FcntlTracepoint (as it can change open flags)
    # TODO: implement Dup3Tracepoint (as it can change open flags)
    multi method set-format-impl('fd', 'unsigned int') { $!format-impl = FdTracepoint.new }
    multi method set-format-impl('newname', 'const char *') { $!format-impl = NameTracepoint.new }
    multi method set-format-impl('filename', 'const char *') { $!format-impl = OpenTracepoint.new }
    multi method set-format-impl('pathname', 'const char *') { $!format-impl = PathnameTracepoint.new }
    multi method set-format-impl('ret', 'long') { $!format-impl = RetTracepoint.new }
    multi method set-format-impl('cmd', 'unsigned int') { $!format-impl = FcntlTracepoint.new }
    multi method set-format-impl($, $) { }

    method generate-c-constant returns Str { "#define {$!name.uc} {$!id}" }
    method generate-bpf-c-tracepoint returns Str { $!format-impl.generate-bpf-c-tracepoint: (format => self, :$!name).hash }

    method field-number(Str \field-name) { (@!external-fields.first(*.name eq field-name, :k) // 0) - 1 }
    method can-generate returns Bool { so $!format-impl.^can('generate-bpf-c-tracepoint') }

    method enter-reject returns Bool { $!format-impl !~~ any(
        FdTracepoint, NameTracepoint, OpenTracepoint, PathnameTracepoint, FcntlTracepoint
    ) }
}

class SysTraceFormatActions {
    has Hash %!formats;
    has Format $!current-format = Format.new;
    has Field $!current-field = Field.new;

    method TOP($/) { make %!formats }

    method whole-format-section($/) {
        my ($, \enter-exit, \what) = $!current-format.name.split('_', 3);
        %!formats{what}{enter-exit} = $!current-format;
        $!current-format = Format.new;
    }

    method name($/) { $!current-format.name = ~$/<identifier> }
    method id($/) { $!current-format.id = +$/<number> }

    method field-declaration($/) {
        $!current-field.name = ~$/<identifier>;
        $!current-field.type = $/<field-type>.join('').trim-trailing;
        $!current-format.push($!current-field);
        $!current-field = Field.new;
    }

    method field-offset($/) { $!current-field.offset = +$/<number> }
    method field-size($/) { $!current-field.size = +$/<number> }
    method field-signed($/) { $!current-field.signed = +$/<cbool> == 0 ?? False !! True }
}

say qq:to/BPF_C_CODE/;
// Code generated - don't change manually!
BPF_C_CODE

my Format @formats = gather for
    SysTraceFormat.parse($*IN.slurp, actions => SysTraceFormatActions.new).made.values -> %syscall {

    if !all(%syscall.values.map(*.can-generate)) {
        say "// Ignoring {%syscall.values.map(*.name).sort} as possibly not file I/O related";
        next;
    } elsif %syscall<enter>.enter-reject {
        say "// Ignoring {%syscall.values.map(*.name).sort} as enter-rejected";
        next;   
    }
    .take for %syscall.values;
}

@formats .= sort({ $^b.id cmp $^a.id });

say qq:to/BPF_C_CODE/;

{@formats.map(*.generate-c-constant).join("\n")}

{@formats.map(*.generate-bpf-c-tracepoint).join("\n")}
BPF_C_CODE
