# go-whois

WHOIS client in Go.

Implements a simple [RFC3912](https://tools.ietf.org/html/rfc3912) client in Go. Made mostly for the sake of learning.

## Install

`go get -u github.com/eeko/go-whois`

## Usage

`go-whois example.com`

## Importing as a Go library

```
import "github.com/eeko/go-whois/pkg/whois"
whois.Whois("example.com")
```

You probably want to use [RDAP](https://github.com/openrdap/rdap) instead. It's pretty awesome.