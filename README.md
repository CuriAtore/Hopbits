# Hopbits

Open-source software that powers the [Hopbits](https://hopbits.io) global network measurement platform: the node agent that operators run on residential, mobile, and datacenter networks, and the command-line tool that developers use to run on-demand probes and manage monitors.

## Components

| Directory | Version | Description |
| :--- | :--- | :--- |
| [`client/`](client/) | `hopbits-agent v0.2.6` | The Linux and Docker measurement node agent (`http`, `tcp_connect`, `icmp_ping`, `dns`, `traceroute`, `mtr`), wire protocol, and compiled safety layer (`--cap-drop ALL`, RFC 1918 / metadata / own-subnet denial, Hop-1 operator subnet redaction, target-free local job logging, Ed25519 job & release verification). |
| [`cli/`](cli/) | `hopbits v0.2.0` | The developer CLI for running global measurements (`http`, `tcp_connect`, `icmp_ping`, `dns`, `traceroute`, `mtr`), estimating credit costs, and managing recurring checks as code. |

## Documentation

- [Run a Node Documentation](https://hopbits.io/docs/run-a-node)
- [Quick Install Guide](https://hopbits.io/docs/run-a-node/quick-install)
- [API & CLI Reference](https://hopbits.io/docs/api/cli)
- [Live Network Status](https://hopbits.io/status)

## License

Licensed under the [Apache License, Version 2.0](LICENSE) (`Apache-2.0`).