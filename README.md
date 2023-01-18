## ConsoleDot Platform Common Middleware

Common Go code for the `console.redhat.com` open-source platform.

### Documentation

[![Go Reference](https://pkg.go.dev/badge/github.com/redhatinsights/platform-go-middlewares.svg)](https://pkg.go.dev/github.com/redhatinsights/platform-go-middlewares)

### Stable version: v1

Usage:

    go get github.com/redhatinsights/platform-go-middlewares

Non Go-modules users need to explicitly pull required version:

    go get github.com/redhatinsights/platform-go-middlewares@1.0.0

The stable version is frozen now and we only accept security or high-important bugfixes.

Branch name: **v1**

### Experimental version: v2

Usage:

    go get github.com/redhatinsights/platform-go-middlewares@master

We are working on cleaning the API and making it more robust and flexible.

Branch name: **master**

### Major changes (upgrading)

#### v2

* Minimum Go version is 1.20
* Updated of all dependencies to the latest version.
* Updated of unit test version matrix to the last three major Go versions.
* Added new root field `Entitlements` and associated type.
* Deprecated `Get` and `With` functions, use `GetIdentity` and `WithIdentity`.
* Introduced `GetRawIdentity` and `WithRawIdentity` for optional raw identity.
* Deprecated `GetIdentityHeader`, replaced with `GetRawIdentity`. Before calling this function, `WithRawIdentity` must be set.
* `Key` type is no longer exported, use appropriate functions.
* Separated parsing and validation into two exported functions.
* New middleware function `EnforceIdentityWithLogger` with custom logging interface.
