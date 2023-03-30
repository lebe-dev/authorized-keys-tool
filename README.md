# Authorized Keys Tool for SSH (AKT)

## Show keys

Show keys older than 31 days, without removal:

```shell
$ akt show-keys --file-path ~/.ssh/authorized_keys 

ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIJRApVG9oMFm8Rf4UHe+L8NDluPrIT3Q9eB/o1PXR2Ld mr.deployer@gmail.com
...
```

### Show keys which used more than X days

```shell
$ akt show-keys --older-than-days 7
```

## Specify where to locate logs and files

```shell
akt --log-level=debug show-keys --older-than-days 1 --auth-log-path proxy-user-tests/logs --file-path proxy-user-tests/authorized_keys
```

## Troubleshooting

Logs are disabled by default.

```shell
sack --log-level=debug [COMMAND] [OPTIONS]
```

Check logs in `akt.log`.
