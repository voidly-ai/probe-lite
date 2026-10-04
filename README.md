# Voidly Probe Lite — archived prototype

> This Node.js probe is a historical Raspberry Pi and headless Linux prototype. Do not use its registration or result-submission instructions for a live Voidly node.

The client tested a rotating set of domains and attempted to submit observations to Voidly. Its registration request uses a route absent from the current service. When that request fails, the code can still save a local ID, which does **not** show that a node was registered or that results were accepted.

For a supported volunteer path, use the [Python community probe](https://github.com/voidly-ai/community-probe) and read the [current setup and consent guide](https://voidly.ai/probes/join). That guide explains what the probe sends and how to verify registration and measurements.

The historical [`package.json`](package.json) declares an MIT license.
