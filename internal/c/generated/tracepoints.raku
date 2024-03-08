#!/usr/bin/env raku

use v6.d;
#use Grammar::Debugger;

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

class Format {
    # Fields not accessible from raw tracepoints.
    has Field @!internal-fields;
    # Fields accessible from raw tracepoints.
    has Field @!external-fields;
    # Track internal/external field sections.
    has Bool $!is-external = False;

    has Str $.name is rw;
    has Int $.id is rw;

    # file descriptor passed to syscalls.
    has Bool $.has-fd is rw = False;
    # Tracepoint has oldname/newname
    has Bool $.has-name is rw = False;
    # Tracepoint has pathname
    has Bool $.has-path is rw = False;
    # Syscall returns with a long value (e.g. bytes read/written)
    has Bool $.has-long-ret is rw = False;

    method push(Field \field) {
        # External fields start from this field name.
        $!is-external = True if field.name eq '__syscall_nr'; 

        if $!is-external {
            push @!external-fields: field;
        } else {
            push @!internal-fields: field;
            return;
        }

        if (field.name eq 'fd' && field.type eq 'unsigned int') {
            $!has-fd = True;
        } elsif (field.name eq 'newname' && field.type eq 'const char *') {
            $!has-name = True;
        } elsif (field.name eq 'pathname' && field.type eq 'const char *') {
            $!has-path = True;
        } elsif (field.name eq 'ret' && field.type eq 'long') {
            $.has-long-ret = True;
        }
    }

    method !field-number(Str \field-name) {
        @!external-fields.first(*.name eq field-name, :k) - 1;
    }

    method generate-constant returns Str {
        "#define {$!name.uc} {$!id}";
    }

    method generate-probe returns Str {
        my \is-enter = $!name.split('_')[1] eq 'enter';
        my \ctx-struct = is-enter ?? 'trace_event_raw_sys_enter'
                                  !! 'trace_event_raw_sys_exit';
        my \event-struct = do if $!has-fd { 'fd_event' }
                           elsif $!has-long-ret { 'ret_event' }
                           elsif $!has-name { 'name_event' }
                           elsif $!has-path { 'path_event' }
                           else { 'null_event' };
        my \extra-data = do if $!has-fd { 'ev->fd = (__s32)ctx->args[0];' }
                         elsif $!has-long-ret { 'ev->ret = ctx->ret;' }
                         elsif $!has-name {
                           my Int \oldname-index = self!field-number('oldname');
                           my Int \newname-index = self!field-number('newname');
                           qq:to/END/.trim-trailing;
                           __builtin_memset(\&(ev->oldname), 0, sizeof(ev->oldname) + sizeof(ev->newname));
                               bpf_probe_read_user_str(ev->oldname, sizeof(ev->oldname), (void*)ctx->args[{oldname-index}]);
                               bpf_probe_read_user_str(ev->newname, sizeof(ev->newname), (void*)ctx->args[{newname-index}]);
                           END
                         } elsif $!has-path {
                           my Int \pathname-index = self!field-number('pathname');
                           qq:to/END/.trim-trailing;
                           __builtin_memset(\&(ev->pathname), 0, sizeof(ev->pathname));
                               bpf_probe_read_user_str(ev->pathname, sizeof(ev->pathname), (void*)ctx->args[{pathname-index}]);
                           END
                         }
                         else { '' };
        qq:to/END/;
        SEC("tracepoint/syscalls/{$!name}")
        int handle_{$!name.lc}(struct {ctx-struct} *ctx) \{
            __u32 pid, tid;
            if (filter(&pid, &tid))
                return 0;

            struct {event-struct} *ev = bpf_ringbuf_reserve(&event_map, sizeof(struct {event-struct}), 0);
            if (!ev)
                return 0;

            ev->event_type = {(is-enter ?? 'ENTER_' !! 'EXIT_') ~ event-struct.uc};
            ev->trace_id = {$!name.uc};
            ev->pid = pid;
            ev->tid = tid;
            ev->time = bpf_ktime_get_ns() / 1000;
            {extra-data}

            bpf_ringbuf_submit(ev, 0);
            return 0;
        \}
        END
    }
}

class SysTraceFormatActions {
    has Format @!formats;
    has Format $!current-format = Format.new;
    has Field $!current-field = Field.new;

    method TOP($/) { make @!formats }

    method whole-format-section($/) {
        push @!formats: $!current-format;
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

my Format @formats = gather for SysTraceFormat
    .parse($*IN.slurp,:actions(SysTraceFormatActions.new)).made
    # For each enter there is an exit tracepoint. E.g. sys_enter_open and sys_exit_open
    .classify(*.name.split('_').tail).values
    .grep({ $_.grep(*.has-fd) || $_.grep(*.has-name) || $_.grep(*.has-path) }) -> @_ { .take for @_ }

@formats .= sort(*.id);

say qq:to/END/;
// Code generated - don't change manually!

{@formats.map(*.generate-constant).join("\n")}

{@formats.map(*.generate-probe).join("\n")}
END
