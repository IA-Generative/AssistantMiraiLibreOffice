# Bundled CA chain for bootstrap HTTPS

This folder contains CA certificates loaded by the plugin SSL context when
LibreOffice Python has no usable trust store.

File:

- `scaleway-bootstrap-ca-chain.pem`:
  - Let's Encrypt intermediate `R13`
  - ISRG Root `X1`

The plugin loads this bundle automatically from `src/mirai/CAbundle/`.
