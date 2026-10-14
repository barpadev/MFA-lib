import { bytesToBase64Url, constantTimeEqual, randomBytes } from "./buffer.ts";

const defaultChallengeBytes = 32;
const minimumChallengeBytes = 16;

export interface Challenge {
  /** A copy of the challenge bytes. Mutating it does not change the stored value. */
  readonly bytes: Uint8Array;
  /** Unpadded base64url of the challenge bytes. */
  readonly value: string;
  /**
   * Compare `presented` once. The first call consumes the challenge.
   * A later call returns false.
   */
  verify(presented: Uint8Array): boolean;
}

/** Mint a WebAuthn challenge. Default length is 32 bytes. Minimum is 16. */
export function createChallenge(byteLength = defaultChallengeBytes): Challenge {
  if (!Number.isInteger(byteLength) || byteLength < minimumChallengeBytes) {
    throw new Error("invalid challenge");
  }
  const bytes = randomBytes(byteLength);
  let spent = false;
  return {
    get bytes() {
      return bytes.slice();
    },
    get value() {
      return bytesToBase64Url(bytes);
    },
    verify(presented: Uint8Array): boolean {
      const matches = constantTimeEqual(bytes, presented);
      if (spent) {
        return false;
      }
      spent = true;
      return matches;
    },
  };
}
