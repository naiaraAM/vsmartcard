package com.vsmartcard.remotesmartcardreader.app;

import java.io.ByteArrayOutputStream;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.util.Arrays;
import java.security.SecureRandom;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

/**
 * Application profile for SPAKE2+.
 * This centralizes the fixed protocol parameters and the identities used by the app as Prover.
 */
final class Spake2Plus {

    static final String CIPHERSUITE = "P-256-SHA256-HKDF-HMAC-SHA256";
    static final String CONTEXT = "vsmartcard-spake2plus-v1";
    private static final String REGISTRATION_INFO = "vsmartcard-spake2plus-registration-v1";
    private static final String CONFIRMATION_INFO = "ConfirmationKeys";
    private static final String SHARED_KEY_INFO = "SharedKey";
    private static final String HMAC_SHA256 = "HmacSHA256";
    private static final int P256_SCALAR_LENGTH = 32;
    private static final int P256_COMPRESSED_POINT_LENGTH = 33;
    private static final int REGISTRATION_HALF_LENGTH = 40;
    private static final int REGISTRATION_OUTPUT_LENGTH = REGISTRATION_HALF_LENGTH * 2;
    private static final SecureRandom RNG = new SecureRandom();
    private static final BigInteger P256_FIELD_PRIME =
            new BigInteger("FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF", 16);
    private static final BigInteger P256_A = P256_FIELD_PRIME.subtract(BigInteger.valueOf(3));
    private static final BigInteger P256_B =
            new BigInteger("5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B", 16);
    private static final BigInteger P256_ORDER =
            new BigInteger("FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551", 16);
    private static final BigInteger P256_GENERATOR_X =
            new BigInteger("6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296", 16);
    private static final BigInteger P256_GENERATOR_Y =
            new BigInteger("4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5", 16);
    private static final byte[] P256_M_COMPRESSED = CryptoUtils.hexToBytes(
            "02886e2f97ace46e55ba9dd7242579f2993b64e16ef3dcab95afd497333d8fa12f");
        private static final byte[] P256_N_COMPRESSED = CryptoUtils.hexToBytes(
            "03d8bbd6c639c62937b04d997f38c3770719c629d7014d49a24b4f98baa1292b49");
    private static final AffinePoint P256_GENERATOR = new AffinePoint(P256_GENERATOR_X, P256_GENERATOR_Y);
    private static final AffinePoint P256_M_POINT = decodeCompressedPoint(P256_M_COMPRESSED);
        private static final AffinePoint P256_N_POINT = decodeCompressedPoint(P256_N_COMPRESSED);

    private Spake2Plus() {}

    static ProverConfig buildProverConfig(String deviceId, String pairingId) {
        if (deviceId == null || deviceId.isEmpty()) {
            throw new IllegalArgumentException("Missing device_id for SPAKE2+ Prover");
        }
        if (pairingId == null || pairingId.isEmpty()) {
            throw new IllegalArgumentException("Missing pairing_id for SPAKE2+ Verifier identity");
        }
        return new ProverConfig(CIPHERSUITE, CONTEXT, deviceId, pairingId);
    }

    static ProverRegistration deriveProverRegistration(byte[] qrSecret, ProverConfig config) {
        if (config == null) {
            throw new IllegalArgumentException("Missing SPAKE2+ Prover config");
        }
        if (qrSecret == null || qrSecret.length == 0) {
            throw new IllegalArgumentException("Missing qr_secret bytes for SPAKE2+ registration");
        }

        byte[] registrationInput = encodeLengthPrefixed(qrSecret,
                config.idProverBytes(),
                config.idVerifierBytes());
        byte[] registrationSalt = encodeLengthPrefixed(config.contextBytes(), config.ciphersuiteBytes());

        /*
         * RFC 9383 recommends a PBKDF for passwords entered by humans.
         * Our qr_secret is already random high-entropy input from the QR, so this profile
         * uses HKDF-SHA256 to expand the registration input into enough material for w0 and w1.
         */
        byte[] expanded = hkdfSha256(
                registrationSalt,
                registrationInput,
                REGISTRATION_INFO.getBytes(StandardCharsets.UTF_8),
                REGISTRATION_OUTPUT_LENGTH);

        byte[] w0 = reduceScalar(Arrays.copyOfRange(expanded, 0, REGISTRATION_HALF_LENGTH));
        byte[] w1 = reduceScalar(Arrays.copyOfRange(expanded, REGISTRATION_HALF_LENGTH, REGISTRATION_OUTPUT_LENGTH));

        Arrays.fill(expanded, (byte) 0);
        Arrays.fill(registrationInput, (byte) 0);

        return new ProverRegistration(config, w0, w1);
    }

    static ProverSession beginProverSession(ProverRegistration registration) {
        if (registration == null) {
            throw new IllegalArgumentException("Missing SPAKE2+ Prover registration");
        }

        byte[] x = generateEphemeralScalar();
        BigInteger xScalar = new BigInteger(1, x);
        BigInteger w0Scalar = new BigInteger(1, registration.w0);

        AffinePoint xP = scalarMultiply(P256_GENERATOR, xScalar);
        AffinePoint w0M = scalarMultiply(P256_M_POINT, w0Scalar);
        AffinePoint sharePPoint = addPoints(xP, w0M);
        byte[] shareP = encodeCompressedPoint(sharePPoint);

        return new ProverSession(registration, x, shareP);
    }

    static ProverResult finishProverSession(ProverSession session, byte[] shareV, byte[] confirmV)
            throws GeneralSecurityException {
        if (session == null || session.registration == null || session.registration.config == null) {
            throw new IllegalArgumentException("Missing SPAKE2+ Prover session");
        }
        if (shareV == null || shareV.length != P256_COMPRESSED_POINT_LENGTH) {
            throw new IllegalArgumentException("shareV must be a compressed P-256 point");
        }
        if (confirmV == null || confirmV.length != 32) {
            throw new IllegalArgumentException("confirmV must be 32 bytes (HMAC-SHA256)");
        }

        ProverRegistration reg = session.registration;
        ProverConfig cfg = reg.config;

        AffinePoint shareVPoint = decodeCompressedPoint(shareV);

        BigInteger w0Scalar = new BigInteger(1, reg.w0);
        BigInteger w1Scalar = new BigInteger(1, reg.w1);
        BigInteger xScalar = new BigInteger(1, session.x);

        AffinePoint w0N = scalarMultiply(P256_N_POINT, w0Scalar);
        AffinePoint yP = subtractPoints(shareVPoint, w0N);
        if (yP.isInfinity()) {
            throw new GeneralSecurityException("Invalid shareV (yP at infinity)");
        }

        AffinePoint zPoint = scalarMultiply(yP, xScalar);
        AffinePoint vPoint = scalarMultiply(yP, w1Scalar);
        if (zPoint.isInfinity() || vPoint.isInfinity()) {
            throw new GeneralSecurityException("Invalid SPAKE2+ intermediate point (infinity)");
        }

        byte[] zOctets = encodeCompressedPoint(zPoint);
        byte[] vOctets = encodeCompressedPoint(vPoint);

        byte[] transcript = encodeLengthPrefixed(
                cfg.contextBytes(),
                cfg.idProverBytes(),
                cfg.idVerifierBytes(),
                P256_M_COMPRESSED,
                P256_N_COMPRESSED,
                session.shareP,
                shareV,
                zOctets,
                vOctets,
                reg.w0);

        byte[] kMain = sha256(transcript);
        byte[] confirmationKeys = hkdfSha256(
                null,
                kMain,
                CONFIRMATION_INFO.getBytes(StandardCharsets.UTF_8),
                64);
        byte[] kShared = hkdfSha256(
                null,
                kMain,
                SHARED_KEY_INFO.getBytes(StandardCharsets.UTF_8),
                32);

        byte[] kcP = Arrays.copyOfRange(confirmationKeys, 0, 32);
        byte[] kcV = Arrays.copyOfRange(confirmationKeys, 32, 64);

        byte[] confirmVExpected = hmacSha256(kcV, session.shareP);
        if (!MessageDigest.isEqual(confirmVExpected, confirmV)) {
            throw new GeneralSecurityException("SPAKE2+ confirmV mismatch");
        }

        byte[] confirmP = hmacSha256(kcP, shareV);

        Arrays.fill(kMain, (byte) 0);
        Arrays.fill(confirmationKeys, (byte) 0);
        Arrays.fill(kcP, (byte) 0);
        Arrays.fill(kcV, (byte) 0);
        Arrays.fill(confirmVExpected, (byte) 0);

        return new ProverResult(kShared, confirmP);
    }

    private static byte[] sha256(byte[] data) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            return md.digest(data);
        } catch (Exception e) {
            throw new IllegalStateException("SHA-256 unavailable", e);
        }
    }

    private static byte[] hmacSha256(byte[] key, byte[] data) {
        try {
            Mac mac = Mac.getInstance(HMAC_SHA256);
            mac.init(new SecretKeySpec(key, HMAC_SHA256));
            return mac.doFinal(data);
        } catch (Exception e) {
            throw new IllegalStateException("HMAC-SHA256 unavailable", e);
        }
    }

    private static AffinePoint negatePoint(AffinePoint point) {
        if (point == null || point.isInfinity()) {
            return AffinePoint.infinity();
        }
        return new AffinePoint(point.x, modP(P256_FIELD_PRIME.subtract(point.y)));
    }

    private static AffinePoint subtractPoints(AffinePoint left, AffinePoint right) {
        return addPoints(left, negatePoint(right));
    }

    private static byte[] hkdfSha256(byte[] salt, byte[] ikm, byte[] info, int length) {
        try {
            Mac mac = Mac.getInstance(HMAC_SHA256);
            byte[] actualSalt = (salt == null || salt.length == 0) ? new byte[mac.getMacLength()] : salt;
            mac.init(new SecretKeySpec(actualSalt, HMAC_SHA256));
            byte[] prk = mac.doFinal(ikm);

            byte[] okm = new byte[length];
            byte[] previous = new byte[0];
            int offset = 0;
            int counter = 1;

            while (offset < length) {
                mac.init(new SecretKeySpec(prk, HMAC_SHA256));
                mac.update(previous);
                if (info != null) {
                    mac.update(info);
                }
                mac.update((byte) counter);
                byte[] block = mac.doFinal();
                int remaining = Math.min(block.length, length - offset);
                System.arraycopy(block, 0, okm, offset, remaining);
                offset += remaining;
                previous = block;
                counter++;
            }

            Arrays.fill(prk, (byte) 0);
            Arrays.fill(previous, (byte) 0);
            return okm;
        } catch (Exception e) {
            throw new IllegalStateException("Could not derive SPAKE2+ registration material", e);
        }
    }

    private static byte[] encodeLengthPrefixed(byte[]... values) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        if (values == null) {
            return out.toByteArray();
        }

        for (byte[] value : values) {
            byte[] current = value == null ? new byte[0] : value;
            writeUint64LE(out, current.length);
            out.write(current, 0, current.length);
        }

        return out.toByteArray();
    }

    private static void writeUint64LE(ByteArrayOutputStream out, int value) {
        long unsignedValue = value & 0xffffffffL;
        for (int i = 0; i < 8; i++) {
            out.write((byte) (unsignedValue & 0xff));
            unsignedValue >>>= 8;
        }
    }

    private static byte[] reduceScalar(byte[] input) {
        BigInteger scalar = new BigInteger(1, input).mod(P256_ORDER);
        byte[] raw = scalar.toByteArray();
        byte[] out = new byte[P256_SCALAR_LENGTH];

        int srcPos = Math.max(0, raw.length - P256_SCALAR_LENGTH);
        int destPos = Math.max(0, P256_SCALAR_LENGTH - raw.length);
        int len = Math.min(P256_SCALAR_LENGTH, raw.length);

        System.arraycopy(raw, srcPos, out, destPos, len);
        Arrays.fill(raw, (byte) 0);
        return out;
    }

    private static byte[] generateEphemeralScalar() {
        byte[] candidate = new byte[P256_SCALAR_LENGTH];
        BigInteger scalar;

        do {
            RNG.nextBytes(candidate);
            scalar = new BigInteger(1, candidate);
        } while (scalar.signum() == 0 || scalar.compareTo(P256_ORDER) >= 0);

        return candidate;
    }

    private static AffinePoint scalarMultiply(AffinePoint point, BigInteger scalar) {
        if (point == null || point.isInfinity()) {
            return AffinePoint.infinity();
        }
        if (scalar == null || scalar.signum() == 0) {
            return AffinePoint.infinity();
        }

        AffinePoint result = AffinePoint.infinity();
        AffinePoint addend = point;

        for (int i = scalar.bitLength() - 1; i >= 0; i--) {
            result = doublePoint(result);
            if (scalar.testBit(i)) {
                result = addPoints(result, addend);
            }
        }

        return result;
    }

    private static AffinePoint addPoints(AffinePoint left, AffinePoint right) {
        if (left == null || left.isInfinity()) {
            return right;
        }
        if (right == null || right.isInfinity()) {
            return left;
        }

        if (left.x.equals(right.x)) {
            if (modP(left.y.add(right.y)).equals(BigInteger.ZERO)) {
                return AffinePoint.infinity();
            }
            return doublePoint(left);
        }

        BigInteger lambda = modP(right.y.subtract(left.y))
                .multiply(modP(right.x.subtract(left.x)).modInverse(P256_FIELD_PRIME))
                .mod(P256_FIELD_PRIME);
        BigInteger x3 = modP(lambda.multiply(lambda).subtract(left.x).subtract(right.x));
        BigInteger y3 = modP(lambda.multiply(left.x.subtract(x3)).subtract(left.y));
        return new AffinePoint(x3, y3);
    }

    private static AffinePoint doublePoint(AffinePoint point) {
        if (point == null || point.isInfinity()) {
            return AffinePoint.infinity();
        }
        if (point.y.signum() == 0) {
            return AffinePoint.infinity();
        }

        BigInteger numerator = point.x.multiply(point.x).multiply(BigInteger.valueOf(3)).add(P256_A);
        BigInteger denominator = point.y.shiftLeft(1).modInverse(P256_FIELD_PRIME);
        BigInteger lambda = modP(numerator.multiply(denominator));
        BigInteger x3 = modP(lambda.multiply(lambda).subtract(point.x.shiftLeft(1)));
        BigInteger y3 = modP(lambda.multiply(point.x.subtract(x3)).subtract(point.y));
        return new AffinePoint(x3, y3);
    }

    private static byte[] encodeCompressedPoint(AffinePoint point) {
        if (point == null || point.isInfinity()) {
            throw new IllegalArgumentException("Cannot encode point at infinity");
        }

        byte[] x = toFixedLength(point.x, P256_SCALAR_LENGTH);
        byte[] encoded = new byte[P256_COMPRESSED_POINT_LENGTH];
        encoded[0] = point.y.testBit(0) ? (byte) 0x03 : (byte) 0x02;
        System.arraycopy(x, 0, encoded, 1, x.length);
        Arrays.fill(x, (byte) 0);
        return encoded;
    }

    private static AffinePoint decodeCompressedPoint(byte[] encoded) {
        if (encoded == null || encoded.length != P256_COMPRESSED_POINT_LENGTH) {
            throw new IllegalArgumentException("Invalid compressed P-256 point");
        }
        if (encoded[0] != 0x02 && encoded[0] != 0x03) {
            throw new IllegalArgumentException("Unsupported compressed point format");
        }

        byte[] xBytes = Arrays.copyOfRange(encoded, 1, encoded.length);
        BigInteger x = new BigInteger(1, xBytes);
        BigInteger rhs = modP(x.multiply(x).multiply(x)
                .add(P256_A.multiply(x))
                .add(P256_B));
        BigInteger y = rhs.modPow(P256_FIELD_PRIME.add(BigInteger.ONE).shiftRight(2), P256_FIELD_PRIME);

        if (!modP(y.multiply(y)).equals(rhs)) {
            throw new IllegalArgumentException("Compressed point is not on P-256");
        }
        if ((encoded[0] == 0x03) != y.testBit(0)) {
            y = P256_FIELD_PRIME.subtract(y);
        }

        Arrays.fill(xBytes, (byte) 0);
        return new AffinePoint(x, y);
    }

    private static BigInteger modP(BigInteger value) {
        BigInteger reduced = value.mod(P256_FIELD_PRIME);
        if (reduced.signum() < 0) {
            return reduced.add(P256_FIELD_PRIME);
        }
        return reduced;
    }

    private static byte[] toFixedLength(BigInteger value, int length) {
        byte[] raw = value.toByteArray();
        byte[] out = new byte[length];

        int srcPos = Math.max(0, raw.length - length);
        int destPos = Math.max(0, length - raw.length);
        int copyLen = Math.min(length, raw.length);

        System.arraycopy(raw, srcPos, out, destPos, copyLen);
        Arrays.fill(raw, (byte) 0);
        return out;
    }

    static final class ProverConfig {
        final String ciphersuite;
        final String context;
        final String idProver;
        final String idVerifier;

        private ProverConfig(String ciphersuite, String context, String idProver, String idVerifier) {
            this.ciphersuite = ciphersuite;
            this.context = context;
            this.idProver = idProver;
            this.idVerifier = idVerifier;
        }

        byte[] contextBytes() {
            return context.getBytes(StandardCharsets.UTF_8);
        }

        byte[] ciphersuiteBytes() {
            return ciphersuite.getBytes(StandardCharsets.UTF_8);
        }

        byte[] idProverBytes() {
            return idProver.getBytes(StandardCharsets.UTF_8);
        }

        byte[] idVerifierBytes() {
            return idVerifier.getBytes(StandardCharsets.UTF_8);
        }
    }

    static final class ProverRegistration {
        final ProverConfig config;
        final byte[] w0;
        final byte[] w1;

        private ProverRegistration(ProverConfig config, byte[] w0, byte[] w1) {
            this.config = config;
            this.w0 = w0;
            this.w1 = w1;
        }
    }

    static final class ProverSession {
        final ProverRegistration registration;
        final byte[] x;
        final byte[] shareP;

        private ProverSession(ProverRegistration registration, byte[] x, byte[] shareP) {
            this.registration = registration;
            this.x = x;
            this.shareP = shareP;
        }
    }

    static final class ProverResult {
        final byte[] sharedKey;
        final byte[] confirmP;

        private ProverResult(byte[] sharedKey, byte[] confirmP) {
            this.sharedKey = sharedKey;
            this.confirmP = confirmP;
        }
    }

    private static final class AffinePoint {
        private static final AffinePoint INFINITY = new AffinePoint(null, null);

        final BigInteger x;
        final BigInteger y;

        private AffinePoint(BigInteger x, BigInteger y) {
            this.x = x;
            this.y = y;
        }

        static AffinePoint infinity() {
            return INFINITY;
        }

        boolean isInfinity() {
            return x == null || y == null;
        }
    }
}
