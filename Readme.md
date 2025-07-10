<div align="center">
  <h1 align="center">go-did-it</h1>

  <p>
    <a href="https://github.com/ucan-wg/go-did-it/tags">
        <img alt="GitHub Tag" src="https://img.shields.io/github/v/tag/ucan-wg/go-did-it">
    </a>
    <a href="https://github.com/ucan-wg/go-did-it/actions?query=">
      <img src="https://github.com/ucan-wg/go-did-it/actions/workflows/gotest.yml/badge.svg" alt="Build Status">
    </a>
    <a href="https://ucan-wg.github.io/go-did-it/dev/bench/">
        <img alt="Go benchmarks" src="https://img.shields.io/badge/Benchmarks-go-blue">
    </a>
    <a href="https://github.com/ucan-wg/go-did-it/blob/v1/LICENSE.md">
        <img alt="Apache 2.0 + MIT License" src="https://img.shields.io/badge/License-Apache--2.0+MIT-green">
    </a>
    <a href="https://pkg.go.dev/github.com/ucan-wg/go-did-it">
      <img src="https://img.shields.io/badge/Docs-godoc-blue" alt="Docs">
    </a>
  </p>
</div>

This is an implementation of Decentralized Identifiers (DIDs) in go. It differs from the alternatives in the following ways: 
- **simple**: made of shared reusable components and clear interfaces
- **fast**: while it supports DID Documents as JSON files, it's not unnecessary in the way (see below)
- **battery included**: the corresponding cryptographic handling is implemented
- **support producing and using DIDs**: unlike some others, this all-in-one implementation is meant to create, manipulate and handle DIDs
- **extensible**: you can easily register your custom DID method

Built with ❤️ by [Consensys](https://consensys.io/).

## Concepts

![`go-did-it` concepts](.github/concepts.png)
