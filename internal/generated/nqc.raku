#!/usr/bin/env raku
#
# This Raku program takes a list of C struct and constant definitions and converts
# it to valid Go code.

use v6.d;
#use Grammar::Debugger;

# Not quite C
grammar NQC {
    rule TOP { <construct>* }
    rule construct { <constant> | <statement> | <comment> }
    rule constant { '#define' <identifier> <number> }
    rule statement { <struct> ';' }
    rule struct { 'struct' <identifier> '{' <member>+ %% ';' '}' }
    rule member { <type> <identifier> <arraysize>? }
    rule comment { <single-line-comment> | <multi-line-comment> }
    rule single-line-comment { '//' <-[\n]>+ }
    rule multi-line-comment { '/*' .*? '*/' }
    token arraysize { '[' <identifier> ']' }
    token type { 'char' | '__s32' | '__u32' | '__s64' | '__u64' }
    token identifier { <[a..z A..Z 0..9 _]>+ }
    token number { \d+ }
}

class NQCToGoActions {
    has Str @!const-names;
    has Bool $!constant-type-set;

    method TOP($/) {
        make "// This file was generated - don't change manually!\n"
        ~ "package types\n\n"
        ~ self!constant-go-string-method ~ "\n"
        ~ $<construct>.map(*.made).join('');
    }

    method construct($/) {
        make $<constant>.made // $<statement>.made // '';
    }

    method statement($/) {
        make "\n" ~ $<struct>.made;
    }

    method constant($/) {
        push @!const-names: ~$<identifier>;
        my $const-type = $<identifier>.starts-with('SYS_') ?? ' SyscallId ' !! '';

        make qq:to/END/;
        const {$<identifier>}$const-type = {$<number>}
        END
    }

    method !constant-go-string-method returns Str {
        qq:to/END/;
        type EventType uint32
        type SyscallId uint32

        func (s SyscallId) String() string \{
            switch (s) \{
            {@!const-names.grep(/^SYS_/).map({
                "case $_: return \"{$_.subst('SYS_', '').lc}\""
            }).join('; ')}
            default: panic(fmt.Sprintf("Unknown SyscallId: %d", s))
            \}
        \}
        END
    }

    method struct($/) {
        make qq:to/END/;
        type {$<identifier>.made} struct \{
            {$<member>.map(*.made).join('; ')} 
        \}
        
        {self!struct-go-string-method($/)}
        {($<identifier>.made.ends-with('Event') ?? "\n" ~ self!struct-go-sync-pool($/) !! '')}
        END
    }

    # Generate String() method on the Go struct, for pretty printing.
    method !struct-go-string-method($/) returns Str {
        my Str $self-ref = $<identifier>.lc.substr(0,1);
        my Str @format = $<member>.map({ $_.<identifier>.made ~ ':%v' });

        my Str @args = $<member>.map({
            my Str $ref = "$self-ref." ~ $_.<identifier>.made;
            # Need to convert char-arrays into a Go slice, and then convert via string(...) 
            ($_.<type> eq 'char' && $_.<arraysize>) ?? "string({$ref}[:])" !! $ref;
        });

        qq:to/END/;
        func ($self-ref {$<identifier>.made}) String() string \{
            return fmt.Sprintf("{@format.join(' ')}", {@args.join(', ')})
        \}
        END
    }

    method !struct-go-sync-pool($/) returns Str {
        my Str $identifier = $/<identifier>.made;
        my Str $self-ref = $identifier.lc.substr(0,1);

        qq:to/END/;
        var poolOf{$identifier}s = sync.Pool\{
            New: func() interface\{\} \{ return &$identifier\{\} \},
        \}

        func New{$identifier}(raw []byte) *$identifier \{
            $self-ref := poolOf{$identifier}s.Get().(*$identifier);
            if err := binary.Read(bytes.NewReader(raw), binary.LittleEndian, $self-ref); err != nil \{
                fmt.Println($self-ref, raw, len(raw), err)
                panic(raw)
            \}
            return $self-ref
        \}

        func ($self-ref *$identifier) Recycle() \{
            poolOf{$identifier}s.Put($self-ref)
        \}
        END
    }

    method member($/) {
        my Str $type = $<identifier>.made eq 'SyscallId' ?? 'SyscallId' !! $<type>.made;
        $type = 'EventType' if $<identifier>.made eq 'EventType';
        make $<identifier>.made ~ ' ' ~ ($<arraysize> // '') ~ $type;
    }

    method type($/) {
        make do given ~$/ {
            when 'char' { 'byte' }
            when '__s32' { 'int32' }
            when '__u32' { 'uint32' }
            when '__s64' { 'int64' }
            when '__u64' { 'uint64' }
        }
    }

    method identifier($/) {
        # Convert identifier from snake_case (C) to CamelCase (Go)
        make $/.Str.split('_').map(*.tc).join('');
    }
}

say NQC.parse($*IN.slurp, actions => NQCToGoActions.new).made;
