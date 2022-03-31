# gRPC mTLS Certificates

This directory contains keypairs and certificates for this repository's various components to use when connecting to each other over gRPC. Each certificate is valid for a single service name, and also for "localhost", so that they can be used when the components are speaking to each other over simple ports on localhost.

## Usage

To use the certificates here, include a stanza like the following in a component's configuration:

```json
"tls": {
   "caCertFile": "test/grpc-mtls/minica.pem",
   "certFile": "test/grpc-mtls/example.service/cert.pem",
   "keyFile": "test/grpc-mtls/example.service/key.pem"
},
```

Where the `caCertFile` points to the root of the hierarchy, and the `certFile` and `keyFile` point to the certificate and keypair the service should use to identify itself.

## Adding a New Service

To add a new keypair and certificate for a new service:

1. Outside of this repository, install [minica](https://github.com/jsha/minica):

   ```sh
   go install github.com/jsha/minica
   ```

2. Inside this directory, run minica with the name of the new service:

   ```sh
   cd test/grpc-mtls
   minica -domains example.service,localhost
   ```
