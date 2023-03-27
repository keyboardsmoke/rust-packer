# packer

A simple executable packer for rust that includes a decryption module component using the [lpReserved trick](https://j00ru.vexillium.org/2009/07/dllmain-and-its-uncovered-possibilites/).

Usage:
`packer --bin <target> --out <output_file> --key <encryption_key>`

The key must be provided as a valid hex string that will be decoded, e.x. `01020A0B`

The output binary will be a copy of the input binary with the executable sections xor'd by the input key.
