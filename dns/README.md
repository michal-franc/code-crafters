![progress-banner](https://backend.codecrafters.io/progress/dns-server/e8a03b80-9dcf-4aa3-beb1-172857fcd120)](https://app.codecrafters.io/users/codecrafters-bot?r=2qF)

This is a starting point for Go solutions to the
["Build Your Own DNS server" Challenge](https://app.codecrafters.io/courses/dns-server/overview).


### Useful Commands

Build & run (this will start DNS forwarding to google DNS 8.8.8.8)
```shell
make
```

Testing command to check if `google.com` record  return anything.

```shell
dig +norecurse @127.0.0.1 -p 2053 google.com
```
