# V850 Cross-Build Dockerfile Design

Date: 2026-08-17

Status: user-approved design

## Goal

Retain the V850 cross-toolchain container definition already used by
`secoc-icanhack/shellcode` inside this repository, without importing that
project's build scripts, payload source, or build artifacts.

## Repository Layout

Create exactly one build-environment file:

```text
v850-cross-build/
└── Dockerfile
```

The new directory contains no README, wrapper script, Makefile, source file,
toolchain archive, image export, or generated output.

## Dockerfile Contract

Copy `/Users/kevin/Desktop/disable-secoc/secoc-icanhack/shellcode/Dockerfile`
without semantic changes. The resulting image therefore retains:

- Ubuntu 22.04 as the base image;
- target triplet `v850-elf`;
- binutils 2.41 from the `binutils-2_41-release` branch;
- GCC 13.2.0 from the `releases/gcc-13.2.0` branch;
- a freestanding C-only GCC build installed below `/opt`;
- the installed toolchain `bin` directory on `PATH`.

No Docker multi-stage rewrite, package-set cleanup, protocol substitution, or
toolchain-version change is part of this migration. Preserving the known
environment takes priority over optimizing image size.

## Build Interface

The repository continues to use `payload/build.sh` as its only payload build
script. The Dockerfile supplies the `v850-elf-gcc`, `v850-elf-ld`, and
`v850-elf-objcopy` executables expected by that script. The migration does not
change `payload/build.sh`, retained payload binaries, or
`payload/build/manifest.json`.

## Verification

Verification is local and non-hardware:

1. compare the new Dockerfile byte-for-byte with the source Dockerfile;
2. assert that `v850-cross-build` contains only `Dockerfile`;
3. run `git diff --check`;
4. run the existing repository hygiene and payload source-contract tests;
5. do not build the image unless separately requested, because that requires
   external source downloads and substantial build time.

No Panda, comma, ECU, UDS, FACI, Flash, or payload execution is involved.
