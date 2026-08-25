# Central Tool Catalog Architecture

The file `catalog/tools.tsv` is the single source of truth for the entire TraceForge toolkit.

## Schema Specification

`catalog/tools.tsv` is a strict, tab-separated table with 15 columns:

```text
id  name    binary  category    subcategory ecosystem   mac_install linux_install   description status  requires_root   requires_api    requires_hardware   notes   source_url
```

### Column Definitions
1. **`id`**: Unique numeric identifier (1-based index).
2. **`name`**: Official human-readable project name.
3. **`binary`**: Executable command name resolved on `$PATH`. Must be globally unique across catalog entries.
4. **`category`**: One of the 7 main investigation domains.
5. **`subcategory`**: Technical sub-discipline (e.g. "Steganography", "Subdomain Discovery", "VBA Macros").
6. **`ecosystem`**: Delivery mechanism (`native`, `pipx`, `go`, `ruby_gem`, `cargo`, `manual`, `api`).
7. **`mac_install`**: Homebrew formula or package name.
8. **`linux_install`**: APT package, Go module URI, or pipx package name.
9. **`description`**: Clear, concise functional description.
10. **`status`**: Current verification level (`verified`, `manual`, `api`, `optional`).
11. **`requires_root`**: Whether execution requires elevated privileges (`yes`, `no`, `optional`).
12. **`requires_api`**: Whether operation depends on cloud API keys (`yes`, `no`, `optional`).
13. **`requires_hardware`**: Whether physical hardware (e.g. Wi-Fi adapter, GPU) is needed (`yes`, `no`).
14. **`notes`**: Operational notes, constraints, or usage tips.
15. **`source_url`**: Official upstream repository or project home page.

## Synchronizing Documentation

Whenever `catalog/tools.tsv` is modified, run:

```bash
./scripts/generate_catalog_docs.sh
```

This validates schema integrity and regenerates `catalog/TOOLS.md` and `docs/TOOLING.md` automatically.
