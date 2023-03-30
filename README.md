# Authorized Keys Tool for SSH (AKT)

## Show keys

Show keys older than 31 days, without removal:

```shell
$ akt show-keys --file-path ~/.ssh/authorized_keys 

ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIJRApVG9oMFm8Rf4UHe+L8NDluPrIT3Q9eB/o1PXR2Ld mr.deployer@gmail.com
...
```

## Troubleshooting

Logs are disabled by default.

```shell
sack --log-level=debug [COMMAND] [OPTIONS]
```

Check logs in `akt.log`.