## ConsoleDot Platform Common Middleware

Common Go code for the `console.redhat.com` open-source platform.

### Documentation

[![Go Reference](https://pkg.go.dev/badge/github.com/redhatinsights/platform-go-middlewares.svg)](https://pkg.go.dev/github.com/redhatinsights/platform-go-middlewares)

### Stable version: v2

Usage:

    go get github.com/redhatinsights/platform-go-middlewares/v2

Branch name: **master**

### Deprecated version: v1

Usage:

    go get github.com/redhatinsights/platform-go-middlewares

The version is frozen now and we only accept security or high-important bugfixes.

Branch name: **v1**

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
* The `EnforceIdentity` function is deprecated. Use the new middleware function `EnforceIdentityWithLogger` with custom logging interface.
* Separated CloudWatch batch-writing client from the logrus hook data structure.
  This allows other logging frameworks to use the BatchWriter client, and logrus
  clients can use both the BatchWriter and the Hook.
