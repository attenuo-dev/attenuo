/**
 * Sender-constrained tokens: DPoP proofs (RFC 9449).
 *
 * A token bound to a key carries `cnf.jkt`, the RFC 7638 thumbprint of that key, and the server
 * accepts it only with a DPoP proof made by the key for each request. Give a client a `dpopKey`
 * and it does this for you: every request carries a proof, exchanges bind the new token to the
 * key, and bound tokens are sent as `Authorization: DPoP <token>`.
 *
 * Keys are private JWKs: Ed25519 (`{ kty: "OKP", crv: "Ed25519", x, d }`, what
 * `attenuo key gen --dpop` writes) or P-256 (`{ kty: "EC", crv: "P-256", x, y, d }`). Signing
 * uses WebCrypto (`globalThis.crypto.subtle`); there are no extra dependencies.
 *
 * **Server nonces** (RFC 9449 §8). A server with `[token] dpop_nonce = "required"` wants a
 * `nonce` it issued in every proof. It sends the current one in a `DPoP-Nonce` response header
 * and refuses a proof without it with `use_dpop_nonce`. The clients keep the latest nonce they
 * were sent (`NonceCache`), put it in every proof, and retry a request once when the server
 * answers `use_dpop_nonce`.
 */

import { AttenuoError, TransportError } from "./errors.js";
import { b64urlDecode } from "./token.js";

/** `typ` of a DPoP proof. */
export const PROOF_TYPE = "dpop+jwt";
/** `typ` of the client assertions `DpopKey.clientAssertion` makes. */
export const CLIENT_ASSERTION_TYP = "client-authentication+jwt";
/** Sign-off claim naming the new token's key thumbprint. */
export const SIGN_OFF_CHILD_JKT = "child_jkt";
/** Sign-off claim naming the new token's agent. */
export const SIGN_OFF_CHILD_ACTOR = "child_actor";
/** Response header carrying the server's current DPoP nonce. */
export const NONCE_HEADER = "DPoP-Nonce";
/** `error` of a refusal asking for a proof with the server's nonce. */
export const USE_DPOP_NONCE = "use_dpop_nonce";

/** A private JWK as stored on disk, or any JWK-shaped object. */
export type Jwk = Record<string, unknown>;

/** A key, or a private JWK to make one from. */
export type DpopKeyLike = DpopKey | Jwk;

const ED25519 = "Ed25519";
const P256: EcKeyImportParams = { name: "ECDSA", namedCurve: "P-256" };
const ES256: EcdsaParams = { name: "ECDSA", hash: "SHA-256" };

export function b64urlEncode(data: Uint8Array | ArrayBuffer | string): string {
  const bytes =
    typeof data === "string"
      ? new TextEncoder().encode(data)
      : data instanceof Uint8Array
        ? data
        : new Uint8Array(data);
  let bin = "";
  for (const b of bytes) bin += String.fromCharCode(b);
  return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

async function sha256(text: string): Promise<string> {
  return b64urlEncode(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(text)));
}

/** `ath`: base64url of the SHA-256 of the token. */
export function accessTokenHash(token: string): Promise<string> {
  return sha256(token);
}

function str(jwk: Jwk, member: string): string {
  const v = jwk[member];
  if (typeof v !== "string" || v === "") {
    throw new AttenuoError(`DPoP key: JWK member \`${member}\` is missing`);
  }
  return v;
}

/** The public members of an Ed25519 or P-256 JWK, in RFC 7638 (lexicographic) order. */
function publicMembers(jwk: Jwk): Record<string, string> {
  const kty = jwk.kty;
  const crv = jwk.crv;
  if (kty === "OKP" && crv === ED25519) return { crv, kty, x: str(jwk, "x") };
  if (kty === "EC" && crv === "P-256") return { crv, kty, x: str(jwk, "x"), y: str(jwk, "y") };
  throw new AttenuoError(
    `unsupported DPoP key type ${JSON.stringify(kty)} / curve ${JSON.stringify(crv)}`,
  );
}

/** RFC 7638 SHA-256 thumbprint of an Ed25519 or P-256 JWK (private members are ignored). */
export function jwkThumbprint(jwk: Jwk): Promise<string> {
  return sha256(JSON.stringify(publicMembers(jwk)));
}

/** A DPoP private key that signs proofs (`EdDSA` or `ES256`). Make one with `fromJwk`/`generate`. */
export class DpopKey {
  private constructor(
    private readonly key: CryptoKey,
    private readonly d: string,
    readonly alg: "EdDSA" | "ES256",
    /** The public JWK carried in each proof header. */
    readonly publicJwk: Readonly<Record<string, string>>,
    /** RFC 7638 thumbprint: the `cnf.jkt` of tokens bound to this key. */
    readonly thumbprint: string,
    /** The `kid` of the JWK the key was imported from, if it had one. */
    readonly kid?: string,
  ) {}

  /** Import a private JWK. Throws `AttenuoError` for a public key or a key that does not match. */
  static async fromJwk(jwk: Jwk): Promise<DpopKey> {
    if (typeof jwk !== "object" || jwk === null) throw new AttenuoError("DPoP key: not a JWK");
    const pub = publicMembers(jwk);
    const d = typeof jwk.d === "string" ? jwk.d : "";
    if (!d) throw new AttenuoError("a DPoP key must be a private JWK (with `d`)");
    const ed = pub.kty === "OKP";
    let key: CryptoKey;
    try {
      // WebCrypto checks that `d` and the public members belong together.
      key = await crypto.subtle.importKey(
        "jwk",
        { ...pub, d } as JsonWebKey,
        ed ? ED25519 : P256,
        false,
        ["sign"],
      );
    } catch (e) {
      throw new AttenuoError(`DPoP key: invalid ${pub.crv} key: ${(e as Error).message}`);
    }
    const kid = typeof jwk.kid === "string" && jwk.kid !== "" ? jwk.kid : undefined;
    return new DpopKey(key, d, ed ? "EdDSA" : "ES256", pub, await jwkThumbprint(pub), kid);
  }

  /** A fresh Ed25519 key. Keep `privateJwk()` somewhere safe to reuse it. */
  static async generate(): Promise<DpopKey> {
    const pair = (await crypto.subtle.generateKey(ED25519, true, [
      "sign",
      "verify",
    ])) as CryptoKeyPair;
    const jwk = await crypto.subtle.exportKey("jwk", pair.privateKey);
    return DpopKey.fromJwk({ kty: "OKP", crv: ED25519, x: jwk.x, d: jwk.d });
  }

  /** Accept a key, a private JWK, or `undefined`. */
  static async of(key: DpopKeyLike | undefined): Promise<DpopKey | undefined> {
    if (key === undefined || key instanceof DpopKey) return key;
    return DpopKey.fromJwk(key);
  }

  /** The private JWK, for storage. Secret. */
  privateJwk(): Record<string, string> {
    return { ...this.publicJwk, d: this.d };
  }

  /** Never print the private key. */
  toJSON(): Record<string, string> {
    return { alg: this.alg, jkt: this.thumbprint };
  }

  /**
   * A proof for one request: `htm` = `method`, `htu` = `url` without query or fragment, a fresh
   * `jti`, `ath` when `accessToken` (a bound token sent with the request) is given, and `nonce`
   * (the server's latest `DPoP-Nonce`) when given.
   */
  async proof(
    method: string,
    url: string,
    accessToken?: string,
    opts: { iat?: number; nonce?: string } = {},
  ): Promise<string> {
    const claims: Record<string, unknown> = {
      jti: crypto.randomUUID(),
      htm: method.toUpperCase(),
      htu: url.split("#", 1)[0]!.split("?", 1)[0]!,
      iat: opts.iat ?? Math.floor(Date.now() / 1000),
    };
    if (accessToken !== undefined) claims.ath = await accessTokenHash(accessToken);
    if (opts.nonce !== undefined) claims.nonce = opts.nonce;
    return this.sign(claims);
  }

  /**
   * The `subject_token_dpop` sign-off of an exchange: a proof by the subject token's key that
   * also names the new token's key (`child_jkt`) and agent (`child_actor`), so it is consent to
   * delegate to that key and agent only. The parent's holder makes it and hands it to the
   * sub-agent; the parent's key never leaves the parent's process.
   */
  async signOff(
    url: string,
    subjectToken: string,
    childJkt: string,
    actor: string,
    opts: { iat?: number } = {},
  ): Promise<string> {
    return this.sign({
      jti: crypto.randomUUID(),
      htm: "POST",
      htu: url.split("#", 1)[0]!.split("?", 1)[0]!,
      iat: opts.iat ?? Math.floor(Date.now() / 1000),
      ath: await accessTokenHash(subjectToken),
      [SIGN_OFF_CHILD_JKT]: childJkt,
      [SIGN_OFF_CHILD_ACTOR]: actor,
    });
  }

  /**
   * A `private_key_jwt` client assertion (RFC 7523 §2.2) signed by this key, for an agent or PEP
   * whose server entry lists the public key in `jwks`: `iss` = `sub` = `clientId`, `aud` =
   * `audience` (the server's `[issuer] issuer`, the `iss` of the tokens it mints), a fresh `jti`,
   * and `exp` `lifetime` seconds (default 60) ahead. `kid` defaults to the imported JWK's `kid`.
   * Each assertion authenticates one request: pass it as `clientAssertion`.
   */
  async clientAssertion(
    clientId: string,
    audience: string,
    opts: { kid?: string; lifetime?: number; iat?: number } = {},
  ): Promise<string> {
    const iat = opts.iat ?? Math.floor(Date.now() / 1000);
    const header: Record<string, unknown> = { alg: this.alg, typ: CLIENT_ASSERTION_TYP };
    const kid = opts.kid ?? this.kid;
    if (kid !== undefined) header.kid = kid;
    return this.signJws(header, {
      iss: clientId,
      sub: clientId,
      aud: audience,
      jti: crypto.randomUUID(),
      iat,
      exp: iat + Math.trunc(opts.lifetime ?? 60),
    });
  }

  /** Sign arbitrary proof claims under a DPoP header (for tests and special cases). */
  async sign(claims: Record<string, unknown>): Promise<string> {
    return this.signJws({ typ: PROOF_TYPE, alg: this.alg, jwk: this.publicJwk }, claims);
  }

  private async signJws(
    header: Record<string, unknown>,
    claims: Record<string, unknown>,
  ): Promise<string> {
    const signing = `${b64urlEncode(JSON.stringify(header))}.${b64urlEncode(JSON.stringify(claims))}`;
    const data = new TextEncoder().encode(signing);
    // ES256 in WebCrypto already produces the JWS form (r || s, 64 bytes).
    const sig = await crypto.subtle.sign(this.alg === "EdDSA" ? ED25519 : ES256, this.key, data);
    return `${signing}.${b64urlEncode(sig)}`;
  }
}

/** `cnf.jkt` of a token, read without verification; `undefined` for a bearer token. */
export function tokenJkt(token: string): string | undefined {
  try {
    const claims: unknown = JSON.parse(
      new TextDecoder().decode(b64urlDecode(token.split(".")[1]!)),
    );
    const cnf = (claims as { cnf?: { jkt?: unknown } } | null)?.cnf;
    return typeof cnf?.jkt === "string" ? cnf.jkt : undefined;
  } catch {
    return undefined;
  }
}

/** `Authorization` (and `DPoP`) headers to present `token` for a request. */
export async function presented(
  token: string,
  key: DpopKey | undefined,
  method: string,
  url: string,
  nonce?: string,
): Promise<Record<string, string>> {
  if (key === undefined) return { authorization: `Bearer ${token}` };
  const opts = nonce === undefined ? {} : { nonce };
  return { authorization: `DPoP ${token}`, dpop: await key.proof(method, url, token, opts) };
}

/**
 * Send the retry that follows a `use_dpop_nonce` refusal, and once more, unchanged, when `fetch`
 * fails at the network level (a `TypeError`, such as undici's "other side closed").
 *
 * The refusal usually goes out before the server has read the request body, and the server then
 * closes that keep-alive connection right after the 401 without saying so (no
 * `Connection: close`). `fetch` puts the retry on the pooled connection unless the close has
 * already reached it, so now and then the retry meets the close and fails. `send` must make the
 * same request with the same headers each time, so the same DPoP proof: if the server did get
 * the first copy, its `jti` is used and the second is refused as a replay, never acted on twice.
 * The client's own requests throw that `TypeError` wrapped in a `TransportError`, which is resent
 * the same way. An abort or a timeout (a `DOMException`, or a `TransportError` around one) is not
 * resent.
 */
export async function resendOnce(send: () => Promise<Response>): Promise<Response> {
  try {
    return await send();
  } catch (e) {
    // The SDK's own requests wrap the `TypeError` in a `TransportError` (its `cause`).
    const network =
      e instanceof TypeError || (e instanceof TransportError && e.cause instanceof TypeError);
    if (!network) throw e;
    return send();
  }
}

/** The latest `DPoP-Nonce` a server sent (RFC 9449 §8), for the next proof. */
export class NonceCache {
  /** The nonce to put in the next proof, or undefined before the server sent one. */
  value: string | undefined;

  /**
   * Remember `res`'s `DPoP-Nonce`. True when the response refused the proof with
   * `use_dpop_nonce` and gave a nonce: the request should be retried, once, with a new proof
   * carrying it.
   */
  async update(res: Response): Promise<boolean> {
    const nonce = res.headers.get(NONCE_HEADER);
    if (!nonce) return false;
    this.value = nonce;
    return isUseDpopNonce(res);
  }
}

/**
 * Did the server refuse the proof for want of its nonce? A 401 with
 * `WWW-Authenticate: DPoP error="use_dpop_nonce"` (resource servers, and attenuo's own routes),
 * or a 400 or 401 whose JSON `error` is `use_dpop_nonce` (authorization servers). Reads a clone
 * of the body, so `res` stays readable.
 */
export async function isUseDpopNonce(res: Response): Promise<boolean> {
  if (res.status !== 400 && res.status !== 401) return false;
  if ((res.headers.get("www-authenticate") ?? "").includes(USE_DPOP_NONCE)) return true;
  try {
    const body: unknown = await res.clone().json();
    return (body as { error?: unknown } | null)?.error === USE_DPOP_NONCE;
  } catch {
    return false;
  }
}

/**
 * The `DPoP` header and the `subject_token_dpop` sign-off of an exchange.
 *
 * `key` binds the new token; its proof covers the subject token when the subject token is bound
 * to the same key. `subjectKey` is the subject token's key when the new token is bound to another
 * one: its sign-off names `key` and `actor` (see `DpopKey.signOff`), so it consents to that
 * delegation only. `nonce` goes in the header proof only: the server does not ask for one in the
 * sign-off.
 */
export async function exchangeProofs(
  url: string,
  subjectToken: string,
  key: DpopKey | undefined,
  subjectKey: DpopKey | undefined,
  actor: string,
  nonce?: string,
): Promise<{ header?: string; signOff?: string }> {
  const parent = tokenJkt(subjectToken);
  const out: { header?: string; signOff?: string } = {};
  if (key !== undefined) {
    const same = parent !== undefined && parent === key.thumbprint;
    out.header = await key.proof(
      "POST",
      url,
      same ? subjectToken : undefined,
      nonce === undefined ? {} : { nonce },
    );
  }
  if (subjectKey !== undefined) {
    if (key === undefined) {
      throw new AttenuoError("subjectDpopKey needs a dpopKey to bind the new token to");
    }
    if (parent !== undefined && parent !== subjectKey.thumbprint) {
      throw new AttenuoError("subjectDpopKey is not the key the subject token is bound to");
    }
    out.signOff = await subjectKey.signOff(url, subjectToken, key.thumbprint, actor);
  }
  return out;
}
