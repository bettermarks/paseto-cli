# paseto-cli

A CLI tool to generate V4 paseto tokens.

```
Generate a paseto token

Usage: paseto-cli generate [OPTIONS] [KEY]

Arguments:
  [KEY]  PASETO key [default: -]

Options:
      --iss <ISS>                Issuer
      --sub <SUB>                Subject
      --aud <AUD>                Audience
      --exp <EXP>                Expiry
      --nbf <NBF>                Not before
      --iat <IAT>                Issued at
      --jti <JTI>                Token identifier
  -c, --claim <KEY=VALUE>        Custom claim
      --expires-in <EXPIRES_IN>  Relative expiry in humantime
      --assertion <ASSERTION>    Implicit assertion
  -h, --help                     Print help
```

```shell
cargo run -- key | cargo run -- generate --assertion p14n --expires-in 5s
```

## TODO

- validation
- presentation
