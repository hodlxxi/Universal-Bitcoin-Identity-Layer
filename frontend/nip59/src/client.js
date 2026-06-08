import {
  finalizeEvent,
  generateSecretKey,
  getPublicKey,
  verifyEvent
} from "nostr-tools/pure";

import * as nip44 from "nostr-tools/nip44";

export const HODLXXI_NIP59_SOURCE_STATUS = Object.freeze({
  name: "hodlxxi-nip59-client-source",
  status: "minimal-source-no-send",
  dependency: "nostr-tools",
  cryptoReadyCandidate: true,
  networkPost: false,
  relayPublishing: false,
  plaintextPost: false,
  sendEnabled: false
});

export function getSourceCapabilities() {
  return Object.freeze({
    ...HODLXXI_NIP59_SOURCE_STATUS,
    hasFinalizeEvent: typeof finalizeEvent === "function",
    hasGenerateSecretKey: typeof generateSecretKey === "function",
    hasGetPublicKey: typeof getPublicKey === "function",
    hasVerifyEvent: typeof verifyEvent === "function",
    hasNip44: typeof nip44 === "object"
  });
}

export function createLocalProbeEvent(nowSeconds = Math.floor(Date.now() / 1000)) {
  const secret = generateSecretKey();
  const publicKey = getPublicKey(secret);

  const unsigned = {
    kind: 1,
    created_at: nowSeconds,
    tags: [],
    content: "hodlxxi-p44-local-source-probe-only"
  };

  const event = finalizeEvent(unsigned, secret);

  return Object.freeze({
    status: "local-source-probe-only",
    networkPost: false,
    relayPublishing: false,
    plaintextPost: false,
    publicKeyLength: publicKey.length,
    eventKind: event.kind,
    eventVerified: verifyEvent(event),
    nip44Available: typeof nip44 === "object"
  });
}

export function assertNoSendAvailable() {
  return Object.freeze({
    sendEnabled: false,
    postEnabled: false,
    relayPublishing: false,
    reason: "P44 source module is crypto-capability only; network send is intentionally absent."
  });
}
