# gohttpscerthack
Small library to help you use https and your own certificate authority to answer any host.

## GoDoc

You should read the GoDoc and check the GetTLSConfigWithIPs

## Try It yourself

You can try the code by running `go run ./test/main.go myCA.pem myCA.key`

## If you need a root certificate

You can use any working tools to generate your root certificate like `openssl`

**or**

You can generate a new root certificate and its private RSA key with `go run tools/rootCertificateGenerator myCA.pem myCA.key`

