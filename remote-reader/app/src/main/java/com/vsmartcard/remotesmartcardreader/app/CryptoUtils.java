package com.vsmartcard.remotesmartcardreader.app;

import android.content.Context;
import android.content.SharedPreferences;
import android.preference.PreferenceManager;
import android.util.Base64;

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


public class CryptoUtils {

    private static final String SEC_PREFS =         "crypto_prefs";
    private static final String PRIV_KEY =          "privkey_app";

    private CryptoUtils() {}

    public static String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder(bytes.length * 2);
        for (byte b : bytes) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }

    public static byte[] toRaw32(BigInteger u) {
        byte[] raw = u.toByteArray();
        byte[] out = new byte[32];

        int srcPos = Math.max(0, raw.length - 32);
        int destPos = Math.max(0, 32 - raw.length);
        int len = Math.min(32, raw.length);

        System.arraycopy(raw, srcPos, out, destPos, len);
        return out;
    }


    public static KeyPair generateX25519KeyPair() throws Exception {
        ensureConscrypt();
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("X25519");

        return kpg.generateKeyPair();
    }

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


    public static String ensureAndStorePublicKey(Context ctx) throws Exception {
        SharedPreferences sp = PreferenceManager.getDefaultSharedPreferences(ctx);
        String existing = sp.getString("pubkey_app", null);
        if (existing != null && !existing.isEmpty()) {
            return existing;
        }

        KeyPair kp = generateX25519KeyPair();
        byte[] pubRaw = getRawPublicKeyBytes(kp);
        String pubHex = bytesToHex(pubRaw);
        sp.edit().putString("pubkey_app", pubHex).apply();

        storePrivateKey(ctx,kp.getPrivate());

        return pubHex;
    }

    public static void ensureConscrypt() {
        if (Security.getProvider("Conscrypt") == null) {
            Security.insertProviderAt(Conscrypt.newProvider(), 1);
        }
    }

    private static SharedPreferences securePrefs(Context ctx) throws Exception {
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

    public static void storePrivateKey(Context ctx, PrivateKey priv) throws Exception {
        byte[] pkcs8 = priv.getEncoded();
        String b64 = Base64.encodeToString(pkcs8, Base64.NO_WRAP);

        SharedPreferences sp = securePrefs(ctx);
        sp.edit().putString(PRIV_KEY, b64).apply();
    }

    public static PrivateKey loadPrivateKey(Context ctx) throws Exception {
        ensureConscrypt();

        SharedPreferences sp = securePrefs(ctx);
        String b64 = sp.getString(PRIV_KEY, null);
        if (b64 == null) {
            return null;
        }

        byte[] pkcs8 = Base64.decode(b64, Base64.NO_WRAP);
        KeyFactory kf = KeyFactory.getInstance("X25519");
        return kf.generatePrivate(new PKCS8EncodedKeySpec(pkcs8));
    }
}
