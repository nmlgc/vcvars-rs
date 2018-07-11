# cc-rs

A library to compile C/C++/assembly into a Rust library/application.

[![Build Status](https://travis-ci.org/alexcrichton/cc-rs.svg?branch=master)](https://travis-ci.org/alexcrichton/cc-rs)
[![Build status](https://ci.appveyor.com/api/projects/status/onu270iw98h81nwv?svg=true)](https://ci.appveyor.com/project/alexcrichton/cc-rs)

[Documentation](https://docs.rs/cc)

A simple library meant to be used as a build dependency with Cargo packages in
order to build a set of C/C++ files into a static archive. This crate calls out
to the most relevant compiler for a platform, for example using `cl` on MSVC.

> **Note**: this crate was recently renamed from the `gcc` crate, so if you're
> looking for the `gcc` crate you're in the right spot!

## Using cc-rs

First, you'll want to both add a build script for your crate (`build.rs`) and
also add this crate to your `Cargo.toml` via:

```toml
[build-dependencies]
cc = "1.0"
```

## External configuration via environment variables

To control the programs and flags used for building, the builder can set a
number of different environment variables.

* `CFLAGS` - a series of space separated flags passed to compilers. Note that
             individual flags cannot currently contain spaces, so doing
             something like: "-L=foo\ bar" is not possible.
* `CC` - the actual C compiler used. Note that this is used as an exact
         executable name, so (for example) no extra flags can be passed inside
         this variable, and the builder must ensure that there aren't any
         trailing spaces. This compiler must understand the `-c` flag. For
         certain `TARGET`s, it also is assumed to know about other flags (most
         common is `-fPIC`).
* `AR` - the `ar` (archiver) executable to use to build the static library.

Each of these variables can also be supplied with certain prefixes and suffixes,
in the following prioritized order:

1. `<var>_<target>` - for example, `CC_x86_64-unknown-linux-gnu`
2. `<var>_<target_with_underscores>` - for example, `CC_x86_64_unknown_linux_gnu`
3. `<build-kind>_<var>` - for example, `HOST_CC` or `TARGET_CFLAGS`
4. `<var>` - a plain `CC`, `AR` as above.

If none of these variables exist, cc-rs uses built-in defaults

In addition to the the above optional environment variables, `cc-rs` has some
functions with hard requirements on some variables supplied by [cargo's
build-script driver][cargo] that it has the `TARGET`, `OUT_DIR`, `OPT_LEVEL`,
and `HOST` variables.

[cargo]: http://doc.crates.io/build-script.html#inputs-to-the-build-script

## Compile-time Requirements

To work properly this crate needs access to a C compiler when the build script
is being run. This crate does not ship a C compiler with it. The compiler
required varies per platform, but there are three broad categories:

* Unix platforms require `cc` to be the C compiler. This can be found by
  installing cc/clang on Linux distributions and Xcode on OSX, for example.
* Windows platforms targeting MSVC (e.g. your target triple ends in `-msvc`)
  require `cl.exe` to be available and in `PATH`. This is typically found in
  standard Visual Studio installations and the `PATH` can be set up by running
  the appropriate developer tools shell.
* Windows platforms targeting MinGW (e.g. your target triple ends in `-gnu`)
  require `cc` to be available in `PATH`. We recommend the
  [MinGW-w64](http://mingw-w64.org) distribution, which is using the
  [Win-builds](http://win-builds.org) installation system.
  You may also acquire it via
  [MSYS2](http://msys2.github.io), as explained [here][msys2-help].  Make sure
  to install the appropriate architecture corresponding to your installation of
  rustc. GCC from older [MinGW](http://www.mingw.org) project is compatible
  only with 32-bit rust compiler.

[msys2-help]: http://github.com/rust-lang/rust#building-on-windows

## License

This project is licensed under either of

 * Apache License, Version 2.0, ([LICENSE-APACHE](LICENSE-APACHE) or
   http://www.apache.org/licenses/LICENSE-2.0)
 * MIT license ([LICENSE-MIT](LICENSE-MIT) or
   http://opensource.org/licenses/MIT)

at your option.

### Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in Serde by you, as defined in the Apache-2.0 license, shall be
dual licensed as above, without any additional terms or conditions.
