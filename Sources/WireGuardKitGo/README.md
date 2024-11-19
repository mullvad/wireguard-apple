#To build with DAITA

To build this library with DAITA, you must ensure that DAITA can be built first.
It needs a rust toolchain.

```bash
git submodule update --recursive
make -C wireguard-go daita
go build -tags daita
```

