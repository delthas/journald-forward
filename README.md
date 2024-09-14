# journald-forward

A tiny pure Go daemon that forwards logs from systemd-journald to an IRC channel.

## Installing

```shell
go install github.com/delthas/journald-forward
```

## Configuring

Copy [the example configuration](journald-forward.example.yaml) to `journald-forward.yaml` and edit it.

See [the reference configuration](journald-forward.reference.yaml) for details.

## Running

```shell
journald-forward
```

## License

MIT
