## linkage

A custom dynamic linker that attempts to load some specific memory dumps.

## Testing

With qiling framework:

```sh
make qiling
```

## Progress

- Resolved relocations: `.got.plt`

- Resolved `.init_array` functions (43/43)

- Resolved RELATIVE relocations: `.got`, `.data.rel.ro`, `.data`

- WIP: Resolved some JMP & ABS64 relocation outside of `.got.plt` section
