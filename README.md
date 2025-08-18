# paseto-cli

A CLI tool to generate V4 paseto tokens.

## General usage

```

Usage: paseto-cli <COMMAND>

Commands:
  generate  Generate a paseto token
  key       Generate a base64 encoded symmetric key
  validate  Validate a token

  help      Print this message or the help of the given subcommand(s)

Options:
  -h, --help  Print help
```

## Token generation

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
      --valid-in <VALID_IN>      Relative valid-in in humantime
      --assertion <ASSERTION>    Implicit assertion
  -h, --help                     Print help

```

```shell
cargo run -- key | cargo run -- generate --assertion p14n --expires-in 5s
```

## Token validation

```
Validate a token

Usage: paseto-cli validate [OPTIONS] <TOKEN> [KEY]

Arguments:
  <TOKEN>  Token
  [KEY]    PASETO key [default: -]

Options:
      --assertion <ASSERTION>  Implicit assertion
      --iss <ISS>              Validate issuer
      --sub <SUB>              Validate subject
      --aud <AUD>              Validate audience
      --valid-at               Validate valid-at
      --expires                Validate expiry
  -h, --help                   Print help
```

## Installation

```shell
cargo install --git "https://github.com/bettermarks/paseto-cli"
```

## Example usage

```shell
# create a key
KEY=$(paseto-cli key)

# create a token
TOKEN=$(echo ${KEY} | paseto-cli generate \
  --assertion p14n \
  --expires-in 1h \
  --claim 'foo={"bar": 123}'
)

# validate a token
echo ${KEY} | paseto-cli validate ${TOKEN} --assertion p14n --expires
```
