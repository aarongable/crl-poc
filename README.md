# Proof-of-Concept CRL Generator

A system to generate Certificate Revocation Lists, designed and written in the style of [Boulder](https://github.com/letsencrypt/boulder) so that it can be incorporated into that project at a future date.

For in-depth coverage of the requirements and design here, see [DESIGN.md](DESIGN.md).

## Usage

In one terminal:

```sh
go run ./cmd/generator -config test/config/generator.json
```

And then in a different terminal:

```sh
go run ./cmd/updater -config test/config/updater.json
```
