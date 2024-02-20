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
    rule constant { '#define' <identifier> <number> <-[\n]>+ }
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
    has Str @.const-types is required;

    method TOP($/) {
        make "// This file was generated - don't change manually!\n"
             ~ "package types\n\n"
             ~ @!const-types.map({ "type {self!const-camel-case($_)} int\n" })
             ~ $<construct>.map(*.made).join('')
    }

    method construct($/) { make $<constant>.made // $<statement>.made // '' }
    method statement($/) { make "\n" ~ $<struct>.made ~ "\n"; }

    method constant($/) {
        make 'const ' ~ $<identifier> ~ "{self!const-type($/)} = " ~ $<number> ~ "\n"
    }

    method !const-type($/) returns Str {
        my $suffix = @!const-types.grep({ $<identifier>.ends-with($_) }).first;
        $suffix ?? ' ' ~ self!const-camel-case($suffix) !! ''
    }

    method !const-camel-case(Str $const-name) returns Str {
        $const-name.lc.split('_').map(*.tc).join('')
    }

    method struct($/) {
        make 'type ' ~ $<identifier>.made ~ " struct \{\n\t" 
            ~ $<member>.map(*.made).join("\n\t") 
            ~ "\n\}\n\n"
            ~ self!struct-go-string-method($/);
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

        return qq:to/END/;
               func ({$self-ref} {$<identifier>.made}) String() string \{
               \treturn fmt.Sprintf("{@format.join(' ')}", {@args.join(', ')})
               \}
               END
    }

    method member($/) { make $<identifier>.made ~ ' ' ~ ($<arraysize> // '') ~ $<type>.made }

    method type($/) {
        make do given ~$/ {
            when 'char' { 'byte' }
            when '__s32' { 'int32' }
            when '__u32' { 'uint32' }
            when '__u64' { 'uint64' }
        }
    }

    # Convert identifier from snake_case (C) to CamelCase (Go)
    method identifier($/) { make $/.Str.split('_').map(*.tc).join('') }
}

say NQC.parse($*IN.slurp, actions => NQCToGoActions.new(const-types => <OP_ID>)).made;
