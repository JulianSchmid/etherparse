# ensure_no_std

This a helper project to test if `etherparse` compiled in `no_std`
mode does not contain any references to `std` or `alloc`.

## Prerequisite

You have to have a toolchain installed for `no_std` testing:

```
rustup target add x86_64-unknown-none
```

## How to test there are no `std` or `alloc` dependencies?

```sh
cd <repo_dir>/etherparse/ensure_no_std
cargo build --target x86_64-unknown-none
```

If the build passes you are good.