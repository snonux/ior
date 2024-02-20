#!/usr/bin/env raku
#
# This Raku program takes a list of C struct and constant definitions and converts
# it to valid Go code.

#use Grammar::Debugger;

# Not quite C
grammar NQC {
    rule TOP { <construct>* }
    rule construct { <constant> | <statement> || <comment> }
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
    method TOP($/) {
        make "// This file was generated - don't change manually!\n" ~
             "package types\n\n" ~
             $<construct>.map(*.made).join('')
    }

    method construct($/) { make $<constant>.made // $<statement>.made // '' }
    method statement($/) { make "\n" ~ $<struct>.made ~ "\n"; }
    method constant($/) { make 'const ' ~ $<identifier> ~ ' = ' ~ $<number> ~ "\n" }

    method struct($/) {
        make 'type ' ~ $<identifier>.made ~ " struct \{\n\t" ~
                       $<member>.map(*.made).join("\n\t") ~ "\n\}"
    }

    method member($/) {
        make $<identifier>.made ~ ' ' ~ ($<arraysize> ?? $<arraysize> !! '') ~ $<type>.made
    }

    method type($/) {
        make do given ~$/ {
            when 'char' { 'byte' }
            when '__s32' { 'int32' }
            when '__u32' { 'uint32' }
            when '__u64' { 'uint64' }
        };
    }

    method identifier($/) {
        # Convert identifier from snake_case (C) to CamelCase (Go)
        make $/.Str.split('_').map(*.tc).join('')
    }
}

say NQC.parse($*IN.slurp, :actions(NQCToGoActions)).made;
