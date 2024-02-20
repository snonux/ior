#!/usr/bin/env raku

my @tracepoints = gather {
    $/<tracepoint>.Str.take
        if /^SEC.*sys_$<tracepoint>=(<[a..z _]>+)/ for 
             dir('../c/tracepoints/').map(*.lines).flat;
}

say qq:to/END/;
package generated

var tracepointList = []string\{
\t{@tracepoints.map({ "\"$_\"" }).join("\n\t") }
\}
END
