# To build with DAITA

To build this library with DAITA, you must ensure that DAITA can be built
first. It needs a rust toolchain.

```bash
git submodule update --recursive
make -C wireguard-go daita
go build -tags daita
```

# To test with DAITA
One can no longer just run `go test` and see all the tests pass. To be able to
test this module with DAITA and run all the niceties of native Go testing
toolkit (e.g. the race detector) one must reign over some ancient runes like
so:

```bash
 GOEXPERIMENT=cgocheck2 CGO_ENABLE=1 go test -tags daita ./...
```

To run with the race detector, append `-race` to list of arguments passed to
the `go test` command. 

When fighting deadlocks, it is also useful to add a timeout to the tests, via
`-timeout=3s`. 

Individual tests can be ran by using the `-run TestFunctionName` argument.
