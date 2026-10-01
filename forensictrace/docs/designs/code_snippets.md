# Representative code snippets (prototype)

## CLI pipeline (`main.c`)

Orchestration order required by the MVP:

```c
if (ft_collect(ctx, target) != 0) { ... }
ft_normalize(ctx);
ft_correlate(ctx);
ft_reconstruct(ctx);
ft_write_json(ctx);
ft_integrity_write(ctx);
```

## Evidence filter (`collector.c` / `ft_config_accepts`)

Config **A** accepts only process-related syscalls; **B** adds file; **C** adds network; **D** records all:

```c
if (strcmp(config, "A") == 0) return is_process;
if (strcmp(config, "B") == 0) return is_process || is_file;
if (strcmp(config, "C") == 0) return is_process || is_file || is_network;
if (strcmp(config, "D") == 0) return 1;
```

## Integrity sidecar (`integrity.c`)

Streaming SHA-256 over the JSON artifact:

```c
EVP_DigestInit_ex(mdctx, EVP_sha256(), NULL);
/* fread loop + EVP_DigestUpdate */
EVP_DigestFinal_ex(mdctx, hash, &hash_len);
fprintf(out, "%s  %s\n", hex, c->output_path);
```

Full source: `forensictrace/src/`.
