# nup_extract

A small, dependency-free Windows tool to **extract** and **pack** [NUP](https://github.com/a55uka/nup)
(NX Package) containers, the format for unencrypted Nintendo Switch / Switch 2 game dumps.

Written in C++17 as a single static `.exe`. No Python, no DLLs.

## Usage

**Drag and drop:**

- Drag a `.nup` file onto `nup_extract.exe` to extract it into a folder next to it.
- Drag a folder onto `nup_extract.exe` to create `<folder>_packed.nup` next to it.
  For a folder named `pokopia`, the output is `pokopia_packed.nup`. An existing
  file is never overwritten; a numeric suffix is added instead.

**Command line:**

    nup_extract file.nup [-o out_folder] [--no-verify]
    nup_extract folder [--level N] [--title-id HEX] [--name NAME] [--publisher P]
                       [--display-version V] [--keep-listings]
                       [--icon path] [--lang-name ja=Name] [--lang-icon ja=path]

## Features

- Extracts base, update and DLC packages using the same layout as `nup pack`:
  `base/`, `updates/<version>/`, `dlc/<title id>/<n>/`.
- Validates the superblock and TOC SHA-256, and checks every extracted file's SHA-256
  (disable with `--no-verify`).
- Multithreaded extraction and packing (one thread per core, up to 16).
- zstd compression (default level 3). Files that do not shrink are stored raw.
  Identical files share one extent. Files over 64 MB are streamed to keep memory low.
- Reads the title ID from `exefs/main.npdm`, and stores the NPDM and build ID as metadata.
- The title defaults to the folder name. `icon.jpg`, `icon.jpeg` or `icon.png` in the folder root is used as the icon.
- Supports localized titles and icons (`--lang-name`, `--lang-icon`).
- `.listing` files are skipped unless `--keep-listings` is given.

## Packing layout

| Folder | Becomes |
|---|---|
| `base/` with `exefs/` and/or `romfs/` | the base package |
| `updates/<decimal version>/` | one update package per version |
| `dlc/<16-hex title id>/<n>/` | one add-on package per index |
| a folder with `exefs/` or `romfs/` directly inside | a single base package |

If a dump has no base, its updates are flagged `standalone_update`.

## Building

Requires a C++17 compiler (tested with MSYS2 UCRT64 g++) and libzstd:

    g++ -std=c++17 -O2 -municode -static -s nup_extract.cpp -o nup_extract.exe -lzstd -lbcrypt

## Notes

- Follows the [NUP v1 specification](https://github.com/a55uka/nup/blob/main/SPEC.md).
  NUP contains no keys and no encryption; you must provide decrypted content.
- Only the zstd and raw codecs are supported, which are the only ones defined in v1.
- Not tested against every real-world dump. Please open an issue if you find a file that fails.
