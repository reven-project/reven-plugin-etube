# Reven Plugin Etube 🦊🔌🚴

A plugin for [Reven](https://github.com/reven-project/reven) that facilitates reverse engineering Shmiano E-Tube firmware.

## Installation 👷

The plugin can be installed using `pip`.

```console
$ pip install reven-plugin-etube
```

## Usage

Run `reven etube --help` to see the help and all available commands.

```console
$ reven etube --help
                                                                                  
 Usage: reven etube [OPTIONS] COMMAND [ARGS]...                                   
                                                                                  
 Operations for reverse engineering Shimano E-Tube firmware.                      
                                                                                  
╭─ Options ──────────────────────────────────────────────────────────────────────╮
│ --help          Show this message and exit.                                    │
╰────────────────────────────────────────────────────────────────────────────────╯
╭─ Commands ─────────────────────────────────────────────────────────────────────╮
│ fwinfo    Read the headers of E-Tube firmware files.                           │
│ decrypt   Decrypt E-Tube file using AES.                                       │
│ encrypt   Encrypt an E-Tube file using AES.                                    │
│ hexpat    Generates ImHex *.hexpat files                                       │
╰────────────────────────────────────────────────────────────────────────────────╯
```
