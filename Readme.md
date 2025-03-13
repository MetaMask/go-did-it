<div align="center">
  <h1 align="center">go-did</h1>

  <p>
    <a href="https://github.com/INFURA/go-did/tags">
        <img alt="GitHub Tag" src="https://img.shields.io/github/v/tag/INFURA/go-did">
    </a>
    <a href="https://github.com/INFURA/go-did/actions?query=">
      <img src="https://github.com/INFURA/go-did/actions/workflows/gotest.yml/badge.svg" alt="Build Status">
    </a>
    <a href="https://INFURA.github.io/go-did/dev/bench/">
        <img alt="Go benchmarks" src="https://img.shields.io/badge/Benchmarks-go-blue">
    </a>
    <a href="https://github.com/INFURA/go-did/blob/v1/LICENSE.md">
        <img alt="Apache 2.0 + MIT License" src="https://img.shields.io/badge/License-Apache--2.0+MIT-green">
    </a>
    <a href="https://pkg.go.dev/github.com/INFURA/go-did">
      <img src="https://img.shields.io/badge/Docs-godoc-blue" alt="Docs">
    </a>
  </p>
</div>

This is an implementation of Decentralized Identifiers (DIDs) in go. It differs from the alternatives in the following ways: 
- **simple**: made of shared reusable components and clear interfaces
- **fast**: while it supports DID Documents as JSON files, it's not unnecessary in the way (see below) 
- **support producing and using DIDs**: unlike some others, this all-in-one implementation is meant to create, manipulate and handle DIDs
- **extensible**: you can easily register your custom DID method

DID spec concepts:

![DID spec concepts](resources/did_brief_architecture_overview.svg)

`go-did` concepts:

![`go-did` concepts](resources/go-did%20concepts.png)