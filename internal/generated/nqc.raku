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
    token type { 'char' | '__s32' | '__u32' | '__u64' }
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
        my $const-type = $<identifier>.ends-with('_OP_ID') ?? ' OpId' !! '';

        make qq:to/END/;
             const {$<identifier>}$const-type = {$<number>}
             END
    }

    method !constant-go-string-method returns Str {
        qq:to/END/;
        type OpId uint32

        func (o OpId) String() string \{
            switch (o) \{
            {@!const-names.grep(/_OP_ID$/).map({
                "case $_: return \"{$_.subst('_OP_ID', '').lc}\""
            }).join('; ')}
            default: panic(fmt.Sprintf("Unknown OpId: %d", o))
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

        qq:to/END/;
        var poolOf{$identifier}s = sync.Pool\{
            New: func() interface\{\} \{ return &$identifier\{\} \},
	\}

        func {$identifier}New() *$identifier \{
            return poolOf{$identifier}s.Get().(*$identifier);
        \}

        func {$identifier}Recycle(elem *$identifier) \{
            poolOf{$identifier}s.Put(elem)
        \}
        END
    }

    method member($/) {
        my Str $type = $<identifier>.made eq 'OpId' ?? 'OpId' !! $<type>.made;
        make $<identifier>.made ~ ' ' ~ ($<arraysize> // '') ~ $type;
    }

    method type($/) {
        make do given ~$/ {
            when 'char' { 'byte' }
            when '__s32' { 'int32' }
            when '__u32' { 'uint32' }
            when '__u64' { 'uint64' }
        }
    }

    method identifier($/) {
        # Convert identifier from snake_case (C) to CamelCase (Go)
        make $/.Str.split('_').map(*.tc).join('');
    }
}

say NQC.parse($*IN.slurp, actions => NQCToGoActions.new).made;
