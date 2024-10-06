## linkage

A custom dynamic linker that attempts to load some specific memory dumps.

## Testing

With qiling framework:

```sh
make qiling
```

## Progress

- Resolved relocations:

| Name                      | r_offset  |
| ------------------------- | --------- |
| \_Znwm                    | 0x2f63570 |
| pthread_mutexattr_init    | 0x2f63210 |
| pthread_mutexattr_settype | 0x2f63848 |
| pthread_mutex_init        | 0x2f63970 |
| pthread_mutexattr_destroy | 0x2f639a0 |
| ......                    | ......    |

I'm lazy to list all of them. A complete list is in `src/relocs.rs`

- Resolved `.init_array` functions (23/43):

```rust
let init_array = vec![
    base + 0x00a6089c, // INIT 0
    base + 0x00a60914, // INIT 1
    base + 0x00a60b48, // INIT 2
    base + 0x00a60bfc, // INIT 3
    base + 0x00a60c3c, // INIT 4
    base + 0x00a60c78, // INIT 5
    base + 0x00a60cb4, // INIT 6
    base + 0x00a60d38, // INIT 7
    base + 0x00a60d9c, // INIT 8
    base + 0x00a60e44, // INIT 9
    base + 0x00a60ec0, // INIT 10
    base + 0x00a60f00, // INIT 11
    base + 0x00a60f40, // INIT 12
    base + 0x00a60ffc, // INIT 13
    base + 0x00a61078, // INIT 14
    base + 0x00a61180, // INIT 15
    base + 0x00a611bc, // INIT 16
    base + 0x00a6122c, // INIT 17
    base + 0x00a61268, // INIT 18
    base + 0x00a612bc, // INIT 19
    base + 0x00a6136c, // INIT 20
    base + 0x00a613a8, // INIT 21
    base + 0x00a613ec, // INIT 22
    base + 0x00a61504, // INIT 23
];
```
