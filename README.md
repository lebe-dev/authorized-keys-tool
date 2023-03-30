# Authorized Keys Tool for SSH (AKT)

## Show keys

Show all keys from authorized_keys:

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

## Troubleshooting

Logs are disabled by default.

```shell
$ ack --log-level=debug [COMMAND] [OPTIONS]
```

Check logs in `akt.log`.

## Roadmap

1. Show unused keys
2. Show keys without id
