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
dig +norecurse @127.0.0.1 -p 2053 google.com +noedns
```

What does it do?
- `@127.0.0.1` - address of locally running DNS
- `-p 2053` - is the port number that the service will start by default
- `google.com` - record we want to find
- `+noedns`
  - Disables DNS extension which is added by additiona pseudo record OTP - this changes the message layout which is not implemented - without it dig will return message that packet is malformed
  - EDNS introduced: 
    - new return codes
    - higher message size up to 4096 originally it was only 512 bytes
- `+norecurse` - sets `RD` flag to 0 - its just for testing
  - without recursion  server won't be looking for the  record across the ned - will just lookup its own cache
