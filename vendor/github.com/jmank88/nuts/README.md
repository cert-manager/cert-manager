# Nuts - BoltDB Utilities

[![GoDoc](https://godoc.org/github.com/jmank88/nuts?status.svg)](https://godoc.org/github.com/jmank88/nuts) [![Go Report Card](https://goreportcard.com/badge/github.com/jmank88/nuts)](https://goreportcard.com/report/github.com/jmank88/nuts) [![Coverage Status](https://coveralls.io/repos/github/jmank88/nuts/badge.svg?branch=master)](https://coveralls.io/github/jmank88/nuts?branch=master)

A collection of [BoltDB](https://github.com/boltdb/bolt) utilities.

## Path Prefix Scans

The prefix scanning functions `SeekPathConflict` and `SeekPathMatch` facilitate maintenance and access to buckets of 
paths supporting *variable elements* with *exclusive matches*.  Paths are `/` delimited, must begin with a `/`, and 
elements beginning with `:` or `*` are variable.

Examples:

```
/
/blogs/
/blogs/:blog_id
```

### Variable Elements

Path elements beginning with a `:` match any single element.  Path elements beginning with `*` match any remaining 
elements, and therefore must be last.

Examples: 

```
Path:  /blogs/:blog_id
Match: /blogs/someblog
```

```
Path:  /blogs/:blog_id/comments/:comment_id/*suffix
Match: /blogs/42/comments/100/edit
```

### Exclusive Matches

Using `SeekPathConflict` before putting new paths to ensure the bucket remains conflict-free guarantees that `SeekPathMatch` 
will never match more than one path. 

Examples:

```
Conflicts: `/blogs/:blog_id`, `/blogs/golang`
Match:     `/blogs/golang`
```

```
Conflicts: `/blogs/*`, `/blogs/:blog_id/comments`
Match:     `/blogs/42/comments`
```
