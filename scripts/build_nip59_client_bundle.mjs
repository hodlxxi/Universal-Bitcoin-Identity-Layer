import { mkdirSync, writeFileSync } from "node:fs";
import { dirname } from "node:path";

const out = "app/static/js/nip59_client_bundle.js";

const banner = `/*
 * HODLXXI NIP-59 client bundle skeleton.
 *
 * This file is intentionally zero-dependency and non-cryptographic.
 * It does not finalize NIP-59 events.
 * It does not POST.
 * It does not publish to relays.
 * It does not handle private keys.
 */
`;

const body = `(function () {
  "use strict";

  const api = Object.freeze({
    name: "hodlxxi-nip59-client",
    version: "0.0.0",
    status: "skeleton",
    cryptoReady: false,
    canFinalizeGiftWrap: false,
    canPostEnvelope: false,
    relayPublishing: false,
    plaintextPost: false,
    dependencies: []
  });

  Object.defineProperty(window, "HODLXXI_NIP59_CLIENT", {
    value: api,
    writable: false,
    configurable: false
  });
})();
`;

mkdirSync(dirname(out), { recursive: true });
writeFileSync(out, banner + body, "utf8");
console.log(`wrote ${out}`);
