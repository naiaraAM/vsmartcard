package com.vsmartcard.remotesmartcardreader.app;

import android.content.Context;
import android.content.SharedPreferences;
import android.preference.PreferenceManager;
import android.util.Base64;
import android.util.Log;

import androidx.security.crypto.EncryptedSharedPreferences;
import androidx.security.crypto.MasterKey; 

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Security;
import java.security.PrivateKey;
import java.security.KeyFactory;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.PublicKey;
import java.lang.reflect.Method;
import java.util.Arrays;

import org.conscrypt.Conscrypt;

/**
 * Utility class for cryptographic operations, including key generation, encoding, and secure storage.
 */
public class CryptoUtils {

    private static final String TAG =              "CryptoUtils";
    private static final String SEC_PREFS =         "crypto_prefs";
    private static final String PRIV_KEY =          "privkey_app";
    private static final String PUB_KEY =           "pubkey_app";

    private CryptoUtils() {}

    /**
     * Convert a byte array to a hexadecimal string.
     * @param bytes the byte array to convert
     * @return the hexadecimal string representation of the byte array
     */
    public static String bytesToHex(byte[] bytes) {
        // convert byte array to hex string
        StringBuilder sb = new StringBuilder(bytes.length * 2);
        for (byte b : bytes) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }

    /**
     * Convert a BigInteger to a 32-byte array, padding with leading zeros if necessary.
     * @param u the BigInteger to convert
     * @return the 32-byte array representation of the BigInteger
     */
    public static byte[] toRaw32(BigInteger u) {
        byte[] raw = u.toByteArray();
        byte[] out = new byte[32];

        int srcPos = Math.max(0, raw.length - 32);
        int destPos = Math.max(0, 32 - raw.length);
        int len = Math.min(32, raw.length);

        System.arraycopy(raw, srcPos, out, destPos, len);
        return out;
    }


    /**
     * Generate an X25519 key pair using Conscrypt provider.
     * @return the generated KeyPair
     * @throws Exception if key generation fails
     */
    public static KeyPair generateX25519KeyPair() throws Exception {
        ensureConscrypt();
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("X25519");

        return kpg.generateKeyPair();
    }

    /**
     * Extract the raw public key bytes from a KeyPair.
     * @param kp the KeyPair from which to extract the public key
     * @return the raw public key bytes
     */
    public static byte[] getRawPublicKeyBytes(KeyPair kp) {
        PublicKey pub = kp.getPublic();
        try {
            Method m = pub.getClass().getMethod("getU");
            Object u = m.invoke(pub);

            if (u instanceof BigInteger) {
                return toRaw32((BigInteger) u);
            }
        } catch (Exception ignored) {}

        byte[] raw = extractX25519RawFromSpki(pub.getEncoded());
        if (raw == null) {
            throw new IllegalStateException("Cannot obtain raw public key");
        }
        return raw;
    }

    /**
     * Extract the raw public key bytes from a SubjectPublicKeyInfo (SPKI) encoded byte array.
     * @param spki the SPKI encoded byte array
     * @return the raw public key bytes, or null if not found
     */
    private static byte[] extractX25519RawFromSpki(byte[] spki) {
        for (int i = 0; i + 35 <= spki.length; i++) {
            if ((spki[i] & 0xFF) == 0x03 &&
                (spki[i + 1] & 0xFF) == 0x21 &&
                (spki[i + 2] & 0xFF) == 0x00) {
                return Arrays.copyOfRange(spki, i + 3, i + 35);
            }
        }
        return null;
    }

    /**
     * Ensure that a public key is generated and stored in SharedPreferences.
     * If a public key already exists, it is returned.
     * Otherwise, a new key pair is generated, the public key is stored in SharedPreferences, and the private key is securely stored using EncryptedSharedPreferences.
     * @param ctx the application context
     * @return the hexadecimal string representation of the public key
     * @throws Exception if key generation or storage fails
     */
    public static String ensureAndStorePublicKey(Context ctx) throws Exception {
        SharedPreferences sp = PreferenceManager.getDefaultSharedPreferences(ctx);
        String existing = sp.getString(PUB_KEY, null);
        if (existing != null && !existing.isEmpty()) {
            try {
                PrivateKey priv = loadPrivateKey(ctx);
                if (priv != null) {
                    return existing;
                }
                Log.w(TAG, "Stored public key exists but private key is missing. Regenerating app keypair.");
            } catch (Exception e) {
                Log.w(TAG, "Stored app keypair is unusable. Regenerating app keypair.", e);
            }
            resetAppKeypair(ctx);
        }

        KeyPair kp = generateX25519KeyPair();
        byte[] pubRaw = getRawPublicKeyBytes(kp);
        String pubHex = bytesToHex(pubRaw);
        sp.edit().putString(PUB_KEY, pubHex).apply();

        storePrivateKey(ctx, kp.getPrivate());

        return pubHex;
    }

    /**
     * Ensure that the Conscrypt provider is available.
     */
    public static void ensureConscrypt() {
        if (Security.getProvider("Conscrypt") == null) {
            Security.insertProviderAt(Conscrypt.newProvider(), 1);
        }
    }

    /**
     * Get an instance of EncryptedSharedPreferences for secure storage of sensitive data.
     * @param ctx the application context
     * @return the EncryptedSharedPreferences instance
     * @throws Exception if secure preference initialization fails
     */
    private static SharedPreferences securePrefs(Context ctx) throws Exception {
        try {
            return createSecurePrefs(ctx);
        } catch (Exception e) {
            Log.w(TAG, "Secure preferences could not be opened. Resetting encrypted key storage.", e);
            resetEncryptedKeyStorage(ctx);
            return createSecurePrefs(ctx);
        }
    }

    private static SharedPreferences createSecurePrefs(Context ctx) throws Exception {
        MasterKey masterKey = new MasterKey.Builder(ctx)
            .setKeyScheme(MasterKey.KeyScheme.AES256_GCM)
            .build();

        return EncryptedSharedPreferences.create(
            ctx,
            SEC_PREFS,
            masterKey,
            EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
            EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM
        );
    }

    /**
     * Store the private key securely in EncryptedSharedPreferences.
     * The private key is encoded in PKCS#8 format and stored as a Base64 string.
     * @param ctx the application context
     * @param priv the private key to store
     * @throws Exception if storage fails
     */
    public static void storePrivateKey(Context ctx, PrivateKey priv) throws Exception {
        byte[] pkcs8 = priv.getEncoded();
        String b64 = Base64.encodeToString(pkcs8, Base64.NO_WRAP);

        SharedPreferences sp = securePrefs(ctx);
        sp.edit().putString(PRIV_KEY, b64).apply();
    }

    /**
     * Load the private key from EncryptedSharedPreferences.
     * @param ctx the application context
     * @return the loaded PrivateKey, or null if not found
     * @throws Exception if loading fails
     */
    public static PrivateKey loadPrivateKey(Context ctx) throws Exception {
        ensureConscrypt();

        SharedPreferences sp = securePrefs(ctx);
        String b64 = sp.getString(PRIV_KEY, null);
        if (b64 == null || b64.isEmpty()) {
            return null;
        }

        byte[] pkcs8 = Base64.decode(b64, Base64.NO_WRAP);
        KeyFactory kf = KeyFactory.getInstance("X25519");
        return kf.generatePrivate(new PKCS8EncodedKeySpec(pkcs8));
    }

    private static void resetAppKeypair(Context ctx) {
        resetEncryptedKeyStorage(ctx);
        PreferenceManager.getDefaultSharedPreferences(ctx).edit().remove(PUB_KEY).apply();
    }

    private static void resetEncryptedKeyStorage(Context ctx) {
        SharedPreferences raw = ctx.getSharedPreferences(SEC_PREFS, Context.MODE_PRIVATE);
        raw.edit().clear().commit();
    }
}
