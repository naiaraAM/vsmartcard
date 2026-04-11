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
            
            bindPreferenceSummaryToValue(findPreference("delay"));
            bindPreferenceSummaryToValue(findPreference("timeout"));

            // add new fields
            bindPreferenceSummaryToValue(findPreference("pairing_id"));
            bindPreferenceSummaryToValue(findPreference("device_id"));
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
            String pairing_id, qr_secret;
            byte[] qrSecretBytes;
            Spake2Plus.ProverConfig spake2PlusConfig;
            Spake2Plus.ProverRegistration spake2PlusRegistration;
            Spake2Plus.ProverSession spake2PlusSession;

            // get fields by name
            pairing_id = getParam(uri, "pairing_id");
            qr_secret = getParam(uri, "qr_secret");
            qrSecretBytes = CryptoUtils.hexToBytes(Objects.requireNonNull(qr_secret, "Missing qr_secret"));
            qr_secret = CryptoUtils.bytesToHex(qrSecretBytes);

            CryptoUtils.ensureConscrypt();
            String deviceId = getOrCreateDeviceId(this);
            spake2PlusConfig = Spake2Plus.buildProverConfig(deviceId, pairing_id);
            spake2PlusRegistration = Spake2Plus.deriveProverRegistration(qrSecretBytes, spake2PlusConfig);
            spake2PlusSession = Spake2Plus.beginProverSession(spake2PlusRegistration);

            Log.i(getClass().getName(), "Prepared SPAKE2+ Prover profile " +
                    spake2PlusConfig.ciphersuite +
                    " idProver=" + spake2PlusConfig.idProver +
                    " idVerifier=" + spake2PlusConfig.idVerifier);
            Log.i(getClass().getName(), "Derived SPAKE2+ Prover registration w0=" +
                    spake2PlusRegistration.w0.length + " bytes w1=" +
                    spake2PlusRegistration.w1.length + " bytes");
            Log.i(getClass().getName(), "Prepared local SPAKE2+ shareP=" +
                    spake2PlusSession.shareP.length + " bytes");


            SharedPreferences SP = PreferenceManager.getDefaultSharedPreferences(this);
            SharedPreferences.Editor editor = SP.edit();
            editor.putString("pairing_id", pairing_id);
            editor.putString("device_id", deviceId);
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


    private void showMessage(String message) {
        View content = findViewById(android.R.id.content);
        if (content != null) {
            Snackbar.make(content, message, Snackbar.LENGTH_LONG).show();
        }
    }
}
