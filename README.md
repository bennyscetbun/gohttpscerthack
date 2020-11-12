# gohttpscerthack
Small library to help you use https and your own certificate authority to answer any host.

## [GoDoc](https://godoc.org/github.com/bennyscetbun/gohttpscerthack)

You should read the [GoDoc](https://godoc.org/github.com/bennyscetbun/gohttpscerthack) and check the [GetTLSConfigWithIPs](https://godoc.org/github.com/bennyscetbun/gohttpscerthack#GetTLSConfigWithIPs)

## Try It yourself

You can try the code by running `go run ./test/main.go myCA.pem myCA.key`

## If you need a root certificate

You can use any working tools to generate your root certificate like `openssl`

**or**

You can generate a new root certificate and its private RSA key with `go run tools/rootCertificateGenerator myCA.pem myCA.key`

You can even generate the client certificate by adding a third argument

