# tinkrotate

[![Go Reference](https://pkg.go.dev/badge/lds.li/tinkrotate.svg)](https://pkg.go.dev/lds.li/tinkrotate)

[Tink](https://developers.google.com/tink) is a great library for Go crypto, you should use it. It has great support for proper key rotation, but the actual implementation of rotating keys is left up to the user. I've written code to do this many times by now, this is an extraction of the code to enable automated rotation.
