package com.vsmartcard.remotesmartcardreader.app;

import android.content.Context;
import android.content.SharedPreferences;
import android.util.Base64;
import android.util.Log;

import androidx.security.crypto.EncryptedSharedPreferences;
import androidx.security.crypto.MasterKey; 

import java.security.Security;


import org.conscrypt.Conscrypt;

/**
 * Utility class for cryptographic operations, including key generation, encoding, and secure storage.
 */
public class CryptoUtils {

    private static final String TAG =              "CryptoUtils";
    private static final String SEC_PREFS =         "crypto_prefs";
    private static final String SHARED_SECRET =      "shared_secret";

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
     * Convert a hexadecimal string to a byte array.
     * @param hex the hexadecimal string to convert
     * @return the decoded byte array
     * @throws IllegalArgumentException if the input is null, has odd length, or contains non-hex characters
     */
    public static byte[] hexToBytes(String hex) {
        if (hex == null) {
            throw new IllegalArgumentException("hex is null");
        }

        int len = hex.length();
        if ((len % 2) != 0) {
            throw new IllegalArgumentException("hex length must be even");
        }

        byte[] out = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            int hi = Character.digit(hex.charAt(i), 16);
            int lo = Character.digit(hex.charAt(i + 1), 16);
            if (hi < 0 || lo < 0) {
                throw new IllegalArgumentException("hex contains non-hex characters");
            }
            out[i / 2] = (byte) ((hi << 4) | lo);
        }
        return out;
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
     * Store the established shared secret (K_shared) securely.
     * This is used as the AES-256 key material for the encrypted channel.
     */
    public static void storeSharedSecret(Context ctx, byte[] sharedSecret) throws Exception {
        if (sharedSecret == null || sharedSecret.length == 0) {
            throw new IllegalArgumentException("sharedSecret is empty");
        }
        String b64 = Base64.encodeToString(sharedSecret, Base64.NO_WRAP);
        SharedPreferences sp = securePrefs(ctx);
        sp.edit().putString(SHARED_SECRET, b64).apply();
    }

    /**
     * Load the stored shared secret (K_shared), or null if missing.
     */
    public static byte[] loadSharedSecret(Context ctx) throws Exception {
        SharedPreferences sp = securePrefs(ctx);
        String b64 = sp.getString(SHARED_SECRET, null);
        if (b64 == null || b64.isEmpty()) {
            return null;
        }
        return Base64.decode(b64, Base64.NO_WRAP);
    }

    private static void resetEncryptedKeyStorage(Context ctx) {
        SharedPreferences raw = ctx.getSharedPreferences(SEC_PREFS, Context.MODE_PRIVATE);
        raw.edit().clear().commit();
    }
}
