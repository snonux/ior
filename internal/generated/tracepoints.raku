#!/usr/bin/env raku

use v6.d;

my @tracepoints = gather for $*IN.slurp.split("\n") {
    take $/<tracepoint>.Str if /^SEC.*sys_$<tracepoint>=(<[a..z_0..9]>+)/;
}

say qq:to/END/;
// This file was generated - don't change manually!
package tracepoints

var List = []string\{
    {@tracepoints.map({ "\"sys_$_\"," }).join("\n\t") }
\}
END
