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
toolkit (e.g. the race detector), we must build `maybenot` for wireguard-go, so
do please run the above build commands first. One must also reign over some
ancient runes like so:

```bash
 GOEXPERIMENT=cgocheck2 CGO_ENABLE=1 go test -tags daita ./...
```


When fighting deadlocks, it is also useful to add a timeout to the tests, via
`-timeout=3s`. 

Individual tests can be ran by using the `-run TestFunctionName` argument.

To run with the race detector, append `-race` to list of arguments passed to
the `go test` command. For running the whole suite, more than 10 minutes (the
default timeout) will be required, so do set a longer one. Test runtime scales
superlinearly with the amount of goroutines that are spawned, for instance
`TestInTunnelTCP` normally runs for 0.251 seconds, barely any longer than it
takes to run no tests at all (0.242), but with the race detector, it takes up
to 5 seconds.

