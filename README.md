# Authorized Keys Tool for SSH (AKT)

## Show keys

Show all keys from `authorized_keys`:

```shell
$ akt show-keys

ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIJRApVG9oMFm8Rf4UHe+L8NDluPrIT3Q9eB/o1PXR2Ld mr.deployer@gmail.com
...
```

### Show old keys

Show keys which used older than X days.

```shell
$ akt show-keys --older-than-days 7
```

### Output format

Output formats supported:
- As is (default)
- Json

**Usage:**

```
--format=json
```

## Limitations

Tool reads files: `auth.log`, `auth.log.X`, `auth.log.X.gz` from `/var/log`.

Journald will be supported in future releases.

## Troubleshooting

Logs are disabled by default.

```shell
$ akt --log-level=debug [COMMAND] [OPTIONS]
```

Check logs in `akt.log`.

## Roadmap

1. Show keys without id
2. Validate e-mail ids
3. Support journald
