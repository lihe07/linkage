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

- Resolved `.init_array` functions (2/43):

| Index | Address  |
| ----- | -------- |
| 0     | 0xa6089c |
| 1     | 0xa60914 |
