package globalfilter

import "strings"

// This file implements the directory-children pattern form "^dir/*": the
// files directly inside one directory, and nothing below it. It is what a
// dashboard directory row filters by (DirPattern), and it is plain text, so it
// round-trips through the filter modal and can be typed there like any other
// pattern.
//
// The form is defined by LiteralDir, the function statsengine.DirOf builds
// the dashboard's directory rows on (the engine's dirRanker groups every
// file by DirOf): "^dir/*" matches a value exactly when
// LiteralDir(value) == dir. The row filter therefore selects precisely the
// files the row counts, by construction rather than by a parallel rule that
// could drift. Like the shell glob it resembles, "*" never crosses a "/", so
// "^/*" selects only top-level entries (/etc, /x), not all of /etc/passwd's
// tree.
//
// It is case-sensitive, like the fully anchored ^exact$ form (see
// StringFilter): a directory row is derived from exact values, and Linux paths
// are case-sensitive, so the "/tmp/A" row must not admit "/tmp/a/x".
//
// The text "^dir/*" previously meant the case-insensitive prefix "dir/*"
// (paths starting with a literal "*" entry); that reading is given up, as no
// row filter produced it and a literal "/*" prefix is not a realistic search.
// "^dir/*$" is unaffected: it stays the exact path "dir/*".

// dirChildrenSuffix ends every directory-children pattern body.
const dirChildrenSuffix = "/*"

// LiteralDir returns the directory part of path as the literal text before
// its last "/" ("/" for a top-level entry such as "/etc" or "//x"), and false
// when path has no "/" at all. Unlike filepath.Dir it does not Clean:
// "./src/x" is in "./src", "//usr/lib/x" in "//usr/lib", "a/../b/c" in
// "a/../b" and "a//b" in "a/". Grouping and matching by the literal text keeps
// a directory filter selecting what was grouped; Cleaning put files under
// rows whose filter did not select them.
func LiteralDir(path string) (string, bool) {
	switch idx := strings.LastIndexByte(path, '/'); idx {
	case -1:
		return "", false
	case 0:
		return "/", true
	default:
		return path[:idx], true
	}
}

// DirPattern returns the StringFilter pattern that matches exactly the paths
// whose LiteralDir is dir - the files directly in dir, not its
// subdirectories' files - as "^dir/*". The match is case-sensitive.
//
// The root is written "^/*" rather than "^//*" (both parse to the root).
// Any other dir gets "/*" appended even when it already ends in "/": the
// literal dir "a/" (from "a//b") becomes "^a//*", which selects "a//b" but not
// "a/x". Because the pattern ends in "*", never in "$", no dir content can
// turn it into the exact form, and a leading or trailing blank inside dir sits
// between the anchor and the suffix, where no trim reaches it.
func DirPattern(dir string) string {
	if dir == "/" {
		return "^" + dirChildrenSuffix
	}
	return "^" + dir + dirChildrenSuffix
}

// dirChildrenDir reports whether a pattern body (anchors already stripped by
// trimAnchors, start-anchored but not end-anchored) is the directory-children
// form, and returns the directory it names. An empty directory ("^/*") is the
// root, which is how DirPattern writes it.
func dirChildrenDir(body string) (string, bool) {
	dir, ok := strings.CutSuffix(body, dirChildrenSuffix)
	if !ok {
		return "", false
	}
	if dir == "" {
		dir = "/"
	}
	return dir, true
}

// matchDirChildren reports whether value lies directly in dir. It is a plain
// comparison against a substring of value, so it never allocates.
func matchDirChildren(dir, value string) bool {
	got, ok := LiteralDir(value)
	return ok && got == dir
}

// dirChildrenWitnessLen is the length of the shortest value matching the
// directory-children pattern for dir: dir plus the separator with an empty
// name ("dir/"), or just "/" for the root.
func dirChildrenWitnessLen(dir string) int {
	if dir == "/" {
		return 1
	}
	return len(dir) + 1
}
