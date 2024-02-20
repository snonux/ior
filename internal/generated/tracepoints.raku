#!/usr/bin/env raku

use v6.d;

my @tracepoints = gather for $*IN.slurp.split("\n") {
    take $/<tracepoint>.Str if /^SEC.*sys_$<tracepoint>=(<[a..z _]>+)/;
}

say qq:to/END/;
// This file was generated - don't change manually!
package generated

var TracepointList = []string\{
\t{@tracepoints.map({ "\"$_\"," }).join("\n\t") }
\}
END
