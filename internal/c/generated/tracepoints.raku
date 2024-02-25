#!/usr/bin/env raku

use v6.d;
#use Grammar::Debugger;

grammar SysTraceFormat {
    rule TOP { <wholeformatsection>* }
    rule wholeformatsection { <name> <id> <format> <print-fmt> }
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
    has Str $.name is rw;
    has Int $.id is rw;
    has Field @.fields is rw;
    has Bool $.has-fd is rw = False;

    method push(Field $field) {
        push @!fields: $field;
        $!has-fd = True if ($field.name eq 'fd' && $field.type eq 'unsigned int');
    }

    method generate-constant returns Str {
        "#define {$!name.uc} {$!id}"
    }

    method generate-probe returns Str {
        my \is-enter = $!name.split('_')[1] eq 'enter';
        my \ctx-struct = is-enter ?? 'trace_event_raw_sys_enter' !! 'trace_event_raw_sys_exit';
        my \event-struct = is-enter ?? 'fd_event' !! 'null_event';

        qq:to/END/;
        SEC("tracepoint/syscalls/{$!name}")
        int handle_enter_write(struct {ctx-struct} *ctx) \{
            __u32 pid, tid;
            if (filter(&pid, &tid))
                return 0;

            struct {event-struct} *ev = bpf_ringbuf_reserve(&event_map, sizeof(struct {event-struct}), 0);
            if (!ev)
                return 0;

            ev->op_id = {$!name.uc};
            ev->pid = pid;
            ev->tid = tid;
            ev->time = bpf_ktime_get_ns() / 1000;
            {is-enter ?? 'ev->fd = (int)ctx->args[0];' !! ''}

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

    method wholeformatsection($/) {
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
    # Check whether one of them (enter or exit) has an fd.
    .grep(*.grep(*.has-fd).elems > 0) -> @_ { .take for @_ }

say qq:to/END/;
// Code generated - don't change manually!

{@formats.map(*.generate-constant).join("\n")}

{@formats.map(*.generate-probe).join("\n")}
END
