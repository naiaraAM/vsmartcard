/*
 * Copyright (C) 2014 Frank Morgner
 *
 * This file is part of RemoteSmartCardReader.
 *
 * RemoteSmartCardReader is free software: you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or (at your
 * option) any later version.
 *
 * RemoteSmartCardReader is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
 * or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * RemoteSmartCardReader.  If not, see <http://www.gnu.org/licenses/>.
 */

package com.vsmartcard.remotesmartcardreader.app;


import android.content.Context;
import android.content.Intent;
import android.content.SharedPreferences;
import android.content.res.Configuration;
import android.net.Uri;
import android.os.Bundle;
import android.preference.ListPreference;
import android.preference.Preference;
import android.preference.PreferenceActivity;
import android.provider.Settings;
import android.preference.PreferenceFragment;
import android.preference.PreferenceManager;
import android.view.MenuItem;
import android.view.View;

import androidx.appcompat.app.ActionBar;

import com.google.android.material.snackbar.Snackbar;
import com.google.zxing.integration.android.IntentIntegrator;
import com.google.zxing.integration.android.IntentResult;

import com.example.android.common.logger.Log;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.Socket;
import java.net.URI;
import javax.crypto.KeyAgreement;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Objects;

/**
 * A {@link PreferenceActivity} that presents a set of application settings. On
 * handset devices, settings are presented as a single list. On tablets,
 * settings are split by category, with category headers shown to the left of
 * the list of settings.
 * <p>
 * See <a href="http://developer.android.com/design/patterns/settings.html">
 * Android Design: Settings</a> for design guidelines and the <a
 * href="http://developer.android.com/guide/topics/ui/settings.html">Settings
 * API Guide</a> for more information on developing a Settings UI.
 */
public class SettingsActivity extends AppCompatPreferenceActivity {
    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setupActionBar();

        // Display the fragment as the main content.
        getFragmentManager().beginTransaction().replace(android.R.id.content,
                new VPCDPreferenceFragment()).commit();
    }

    /**
     * Set up the {@link android.app.ActionBar}, if the API is available.
     */
    private void setupActionBar() {
        ActionBar actionBar = getSupportActionBar();
        if (actionBar != null) {
            // Show the Up button in the action bar.
            actionBar.setDisplayHomeAsUpEnabled(true);
        }
    }


    /** {@inheritDoc} */
    @Override
    public boolean onIsMultiPane() {
        return isXLargeTablet(this);
    }

    @Override
    public boolean onOptionsItemSelected(MenuItem item) {
        int id = item.getItemId();
        if (id == android.R.id.home) {
            finish();
            return true;
        }
        return super.onOptionsItemSelected(item);
    }

    /**
     * Helper method to determine if the device has an extra-large screen. For
     * example, 10" tablets are extra-large.
     */
    private static boolean isXLargeTablet(Context context) {
        return (context.getResources().getConfiguration().screenLayout
        & Configuration.SCREENLAYOUT_SIZE_MASK) >= Configuration.SCREENLAYOUT_SIZE_XLARGE;
    }

    /**
     * A settings value change listener that updates the settings' summary
     * to reflect its new value.
     */
    private static final Preference.OnPreferenceChangeListener sBindPreferenceSummaryToValueListener = new Preference.OnPreferenceChangeListener() {
        @Override
        public boolean onPreferenceChange(Preference preference, Object value) {
            String stringValue = value.toString();

            if (preference instanceof ListPreference) {
                // For list preferences, look up the correct display value in
                // the settings' 'entries' list.
                ListPreference listPreference = (ListPreference) preference;
                int index = listPreference.findIndexOfValue(stringValue);

                // Set the summary to reflect the new value.
                preference.setSummary(
                        index >= 0
                                ? listPreference.getEntries()[index]
                                : null);
            } else {
                // For all other preferences, set the summary to the value's
                // simple string representation.
                preference.setSummary(stringValue);
            }
            return true;
        }
    };

    /**
     * Binds a settings' summary to its value. More specifically, when the
     * settings's value is changed, its summary (line of text below the
     * settings title) is updated to reflect the value. The summary is also
     * immediately updated upon calling this method. The exact display format is
     * dependent on the type of settings.
     *
     * @see #sBindPreferenceSummaryToValueListener
     */
    private static void bindPreferenceSummaryToValue(Preference preference) {
        if (preference == null) {
            return;
        }
        // Set the listener to watch for value changes.
        preference.setOnPreferenceChangeListener(sBindPreferenceSummaryToValueListener);

        // Trigger the listener immediately with the settings'
        // current value.
        sBindPreferenceSummaryToValueListener.onPreferenceChange(preference,
                PreferenceManager
                        .getDefaultSharedPreferences(preference.getContext())
                        .getString(preference.getKey(), ""));
    }

    /**
     * This fragment shows data and sync preferences only. It is used when the
     * activity is showing a two-pane settings UI.
     */
    public static class VPCDPreferenceFragment extends PreferenceFragment {
        @Override
        public void onCreate(Bundle savedInstanceState) {
            super.onCreate(savedInstanceState);
            addPreferencesFromResource(R.xml.settings);
            setHasOptionsMenu(true);

            // Bind the summaries of EditText/List/Dialog/Ringtone preferences
            // to their values. When their values change, their summaries are
            // updated to reflect the new value, per the Android Design
            // guidelines.
            // bindPreferenceSummaryToValue(findPreference("hostname"));
            // bindPreferenceSummaryToValue(findPreference("port"));

            
            CryptoUtils.ensureConscrypt();
            getOrCreateDeviceId(getActivity());
            try {
                CryptoUtils.ensureAndStorePublicKey(getActivity());
            } catch (Exception e) {
                e.printStackTrace();
            }
            
            bindPreferenceSummaryToValue(findPreference("delay"));
            bindPreferenceSummaryToValue(findPreference("timeout"));

            // add new fields
            bindPreferenceSummaryToValue(findPreference("pairing_id"));
            bindPreferenceSummaryToValue(findPreference("device_id"));
            bindPreferenceSummaryToValue(findPreference("pubkey_pc"));
            bindPreferenceSummaryToValue(findPreference("pubkey_app"));
            bindPreferenceSummaryToValue(findPreference("qr_secret"));


            Preference nfcSettings = findPreference("nfcSettings");
            if (nfcSettings != null) {
                nfcSettings.setOnPreferenceClickListener(new Preference.OnPreferenceClickListener() {
                    public boolean onPreferenceClick(Preference preference) {
                        Intent viewIntent = new Intent(Settings.ACTION_NFC_SETTINGS);
                        startActivity(viewIntent);
                        return true;
                    }
                });
            }

            Preference scan = findPreference("scan");
            if (scan != null) {
                scan.setOnPreferenceClickListener(new Preference.OnPreferenceClickListener() {
                    public boolean onPreferenceClick(Preference preference) {
                        IntentIntegrator.forFragment(VPCDPreferenceFragment.this).initiateScan();
                        return true;
                    }
                });
            }
        }

        @Override
        public void onActivityResult(int requestCode, int resultCode, Intent intent) {
            if (getActivity() instanceof SettingsActivity
                    && ((SettingsActivity) getActivity()).handleScanResult(requestCode, resultCode, intent)) {
                return;
            }
            super.onActivityResult(requestCode, resultCode, intent);
        }

        @Override
        public boolean onOptionsItemSelected(MenuItem item) {
            int id = item.getItemId();
            if (id == android.R.id.home) {
                startActivity(new Intent(getActivity(), SettingsActivity.class));
                return true;
            }
            return super.onOptionsItemSelected(item);
        }

    }

    @Override
    public void onActivityResult(int requestCode, int resultCode, Intent intent) {
        if (!handleScanResult(requestCode, resultCode, intent)) {
            super.onActivityResult(requestCode, resultCode, intent);
        }
    }

    boolean handleScanResult(int requestCode, int resultCode, Intent intent) {
        IntentResult scanResult = IntentIntegrator.parseActivityResult(requestCode, resultCode, intent);
        if (scanResult == null) {
            return false;
        }

        if (resultCode == RESULT_CANCELED || scanResult.getContents() == null || scanResult.getContents().isEmpty()) {
            return true;
        }

        handleScannedURI(Uri.parse(scanResult.getContents()));
        return true;
    }

    private void handleScannedURI(Uri uri) {
        try {
            String pairing_id, pub_key_pc, qr_secret;

            // get fields by name
            pairing_id = getParam(uri, "pairing_id");
            pub_key_pc = getParam(uri, "pubkey");
            qr_secret = getParam(uri, "qr_secret");

            CryptoUtils.ensureConscrypt();
            String deviceId = getOrCreateDeviceId(this);
            String pubKeyApp = CryptoUtils.ensureAndStorePublicKey(this);


            SharedPreferences SP = PreferenceManager.getDefaultSharedPreferences(this);
            SharedPreferences.Editor editor = SP.edit();
            editor.putString("pairing_id", pairing_id);
            editor.putString("device_id", deviceId);
            editor.putString("pubkey_pc", pub_key_pc);
            editor.putString("pubkey_app", pubKeyApp);
            editor.putString("qr_secret", qr_secret);
            editor.putBoolean("pairing_confirmed", false);
            editor.apply();
            
            getFragmentManager().beginTransaction().replace(android.R.id.content,
                    new VPCDPreferenceFragment()).commit();

            showMessage("Configuration imported");
        } catch (Exception e) {
            Log.e(getClass().getName(), "Could not import configuration", e);
            showMessage("Could not import configuration");
        }
    }

    @Override
    public void onResume() {
        super.onResume();
        Intent intent = getIntent();
        // Check to see that the Activity started due to a configuration URI
        if (Intent.ACTION_VIEW.equals(intent.getAction())) {
            Uri uri = intent.getData();
            handleScannedURI(uri);
            super.onNewIntent(intent);
        }
    }

    @Override
    public void onNewIntent(Intent intent) {
        // onResume gets called after this to handle the intent
        setIntent(intent);
    }

    private static String getOrCreateDeviceId(Context ctx) {
        // try to get existing device id or create a new one if not present
        SharedPreferences sp = PreferenceManager.getDefaultSharedPreferences(ctx);
        String existing = sp.getString("device_id", null);
        if (existing != null && !existing.isEmpty()) {
            return existing;
        }

        byte[] bytes = new byte[16];
        new java.security.SecureRandom().nextBytes(bytes);
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02x", b));
        }

        String id = sb.toString();
        sp.edit().putString("device_id", id).apply();
        return id;
    }

    private static String getParam(Uri uri, String key) {
        // first try to get the parameter by name
        String val = uri.getQueryParameter(key);
        if (val != null) {
            return val;
        }

        String ssp = uri.getSchemeSpecificPart();
        if (ssp == null) {
            return null;
        }

        if (ssp.startsWith("//")) {
            ssp = ssp.substring(2);
        }
        if (ssp.startsWith("?")) {
            ssp = ssp.substring(1);
        }

        Uri tmp = Uri.parse("http://dummy/?" + ssp);
        return tmp.getQueryParameter(key);
    }

    private static String getFirstParam(Uri uri, String... keys) {
        if (keys == null) {
            return null;
        }
        for (String key : keys) {
            String value = getParam(uri, key);
            if (value != null && !value.isEmpty()) {
                return value;
            }
        }
        return null;
    }

    private static boolean isValidPort(String port) {
        if (port == null || port.isEmpty()) {
            return false;
        }
        try {
            int value = Integer.parseInt(port);
            return value > 0 && value < 65536;
        } catch (NumberFormatException e) {
            return false;
        }
    }

    private void showMessage(String message) {
        View content = findViewById(android.R.id.content);
        if (content != null) {
            Snackbar.make(content, message, Snackbar.LENGTH_LONG).show();
        }
    }

    /**
     * Tarea ligera para validar el emparejamiento nada más escanear el QR.
     * Usa la misma lógica de handshake+pairing que VPCDWorker pero sin esperar a una tarjeta NFC.
     */
    private static class PairingTask extends android.os.AsyncTask<Void, Void, Void> {
        private final Context ctx;
        PairingTask(Context ctx) {
            this.ctx = ctx.getApplicationContext();
        }

        @Override
        protected Void doInBackground(Void... voids) {
            SharedPreferences sp = PreferenceManager.getDefaultSharedPreferences(ctx);
            String pairingId = sp.getString("pairing_id", null);
            String deviceId  = sp.getString("device_id", null);
            String pubKeyPc  = sp.getString("pubkey_pc", null);
            String qrSecret  = sp.getString("qr_secret", null);
            String hostname  = sp.getString("hostname", VPCDWorker.DEFAULT_HOSTNAME);
            int port;
            try {
                port = Integer.parseInt(sp.getString("port", Integer.toString(VPCDWorker.DEFAULT_PORT)));
            } catch (NumberFormatException e) {
                port = VPCDWorker.DEFAULT_PORT;
            }

            if (pairingId == null || deviceId == null || pubKeyPc == null || qrSecret == null) {
                Log.i(PairingTask.class.getName(), "Pairing data missing, skip auto pairing");
                return null;
            }

            Log.i(PairingTask.class.getName(), "Trying auto pairing to " + hostname + ":" + port +
                    " pairingId=" + pairingId + " deviceId=" + deviceId);

            Socket sock = null;
            try {
                CryptoUtils.ensureConscrypt();
                String pubKeyAppHex = CryptoUtils.ensureAndStorePublicKey(ctx);
                byte[] pubKeyAppRaw = hexToBytes(pubKeyAppHex);

                byte[] secret = deriveSharedSecret(ctx, pubKeyPc);

                InetAddress address = VPCDWorker.resolveAddress(hostname);
                Log.i(PairingTask.class.getName(), "Resolved " + hostname + " to " + address.getHostAddress());
                sock = new Socket(address, port);
                sock.setTcpNoDelay(true);

                OutputStream out = sock.getOutputStream();
                InputStream in = sock.getInputStream();

                sendLine(out, String.format("{\"message_type\":\"handshake\",\"pairing_id\":\"%s\",\"device_id\":\"%s\",\"role\":\"app\"}", pairingId, deviceId));
                waitStatusOk(in);

                String macHex = computeMac(qrSecret, pubKeyAppRaw);
                String payload = "mac=" + macHex + "&pubKeyApp=" + pubKeyAppHex;
                sendLine(out, String.format("{\"message_type\":\"communication\",\"source_id\":\"%s\",\"payload\":\"%s\"}", deviceId, payload));
                waitStatusOk(in);

                Log.i(PairingTask.class.getName(), "Auto pairing succeeded; shared secret derived (" + secret.length + " bytes)");
            } catch (Exception e) {
                Log.e(PairingTask.class.getName(), "Auto pairing failed", e);
            } finally {
                if (sock != null) {
                    try { sock.close(); } catch (IOException ignored) {}
                }
            }
            return null;
        }

        private static void sendLine(OutputStream out, String json) throws IOException {
            out.write((json + "\n").getBytes(java.nio.charset.StandardCharsets.UTF_8));
            out.flush();
        }

        private static void waitStatusOk(InputStream in) throws IOException {
            String line;
            while ((line = readLine(in)) != null) {
                if (line.isEmpty()) continue;
                Log.i(PairingTask.class.getName(), "Server line: " + line);
                try {
                    org.json.JSONObject obj = new org.json.JSONObject(line);
                    if (obj.has("status_code")) {
                        int code = obj.getInt("status_code");
                        if (code != 200) {
                            String payload = obj.optString("payload", "");
                            throw new IOException("status " + code + (payload.isEmpty() ? "" : (" payload=" + payload)));
                        }
                        return;
                    }
                    // Si llegó algo que no tiene status_code, sigue leyendo
                } catch (org.json.JSONException ignored) {}
            }
            throw new IOException("connection closed");
        }

        private static String readLine(InputStream in) throws IOException {
            StringBuilder sb = new StringBuilder();
            int ch;
            while ((ch = in.read()) != -1) {
                if (ch == '\n') break;
                sb.append((char) ch);
            }
            if (sb.length() == 0 && ch == -1) return null;
            return sb.toString().trim();
        }

        private static byte[] deriveSharedSecret(Context ctx, String peerHex) throws Exception {
            if (peerHex == null || peerHex.isEmpty()) {
                throw new IOException("Missing peer public key");
            }
            byte[] peerRaw = hexToBytes(peerHex);
            PrivateKey priv = CryptoUtils.loadPrivateKey(ctx);
            PublicKey peer = decodeX25519PublicKey(peerRaw);
            KeyAgreement ka = KeyAgreement.getInstance("X25519");
            ka.init(priv);
            ka.doPhase(peer, true);
            return ka.generateSecret();
        }

        private static PublicKey decodeX25519PublicKey(byte[] raw) throws Exception {
            byte[] spki = new byte[12 + raw.length];
            byte[] prefix = new byte[]{0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x6e, 0x03, 0x21, 0x00};
            System.arraycopy(prefix, 0, spki, 0, prefix.length);
            System.arraycopy(raw, 0, spki, prefix.length, raw.length);
            java.security.spec.X509EncodedKeySpec spec = new java.security.spec.X509EncodedKeySpec(spki);
            return java.security.KeyFactory.getInstance("X25519").generatePublic(spec);
        }

        private static String computeMac(String secret, byte[] data) throws Exception {
            javax.crypto.Mac mac = javax.crypto.Mac.getInstance("HmacSHA256");
            mac.init(new javax.crypto.spec.SecretKeySpec(secret.getBytes(java.nio.charset.StandardCharsets.UTF_8), "HmacSHA256"));
            return CryptoUtils.bytesToHex(mac.doFinal(data));
        }

        private static byte[] hexToBytes(String hex) {
            if (hex == null) throw new IllegalArgumentException("hex is null");
            int len = hex.length();
            if ((len % 2) != 0) throw new IllegalArgumentException("hex length must be even");
            byte[] out = new byte[len / 2];
            for (int i = 0; i < len; i += 2) {
                out[i / 2] = (byte) ((Character.digit(hex.charAt(i), 16) << 4)
                        + Character.digit(hex.charAt(i + 1), 16));
            }
            return out;
        }
    }
}
