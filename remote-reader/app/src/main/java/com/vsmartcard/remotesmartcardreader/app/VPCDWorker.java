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
import android.content.SharedPreferences;
import android.os.AsyncTask;
import android.preference.PreferenceManager;
import android.util.Base64;

import androidx.annotation.Nullable;

import com.example.android.common.logger.Log;
import com.vsmartcard.remotesmartcardreader.app.screaders.SCReader;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.InterfaceAddress;
import java.net.NetworkInterface;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.SocketTimeoutException;
import java.net.UnknownHostException;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.Enumeration;
import java.util.LinkedList;
import java.util.List;

import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import javax.crypto.Mac;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

class VPCDWorker extends AsyncTask<VPCDWorker.VPCDWorkerParams, Void, Void> {

    public static class VPCDWorkerParams {
        final String hostname;
        final int port;
        final SCReader reader;
        final boolean listen;
        final Context context;
        VPCDWorkerParams(String hostname, int port, SCReader reader, boolean listen, Context context) {
            this.hostname = hostname;
            this.port = port;
            this.reader = reader;
            this.listen = listen;
            this.context = context;
        }
    }

    public static final int DEFAULT_PORT = 80;
    public static final String DEFAULT_HOSTNAME = "middlepoint.test";
    public static final boolean DEFAULT_LISTEN = false;

    private SCReader reader;
    private ServerSocket listenSocket;
    private Socket socket;
    private InputStream inputStream;
    private OutputStream outputStream;
    private byte[] sharedSecret;
    private boolean secureMode = false;
    private String pairingId;
    private String deviceId;
    private String pubKeyPcHex;
    private String qrSecret;
    private Context appContext;

    @Override
    protected void onCancelled () {
        try {
            if (socket != null)
                // interrupt all blocking socket communication
                socket.close();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    private static final int VPCD_CTRL_LEN = 1;
    private static final byte VPCD_CTRL_OFF = 0;
    private static final byte VPCD_CTRL_ON = 1;
    private static final byte VPCD_CTRL_RESET = 2;
    private static final byte VPCD_CTRL_ATR = 4;

    @Override
    public Void doInBackground(VPCDWorkerParams... params) {
        try {
            reader = params[0].reader;
            appContext = params[0].context != null ? params[0].context.getApplicationContext() : null;
            vpcdConnection(params[0]);

            while (!isCancelled()) {
                vpcdAccept();
                byte[] out = null;
                boolean disconnectAfterSend = false;
                byte[] in = receiveFromVPCD();
                if (in == null) {
                    if (listenSocket == null) {
                        Log.i(this.getClass().getName(), "End of stream, finishing");
                        break;
                    } else {
                        Log.i(this.getClass().getName(), "End of stream, closing connection");
                        vpcdCloseClient();
                        continue; // back to accept
                    }
                }

                if (in.length == VPCD_CTRL_LEN) {
                    switch (in[0]) {
                        case VPCD_CTRL_OFF:
                            reader.powerOff();
                            Log.i(this.getClass().getName(), "Powered down the card (cold reset)");
                            break;
                        case VPCD_CTRL_ON:
                            reader.powerOn();
                            byte[] atrOn = reader.getATR();
                            if (atrOn != null) {
                                Log.i(this.getClass().getName(), "Powered up the card with ATR " + Hex.getHexString(atrOn));
                            } else {
                                Log.i(this.getClass().getName(), "Powered up the card (ATR unavailable)");
                            }
                            break;
                        case VPCD_CTRL_RESET:
                            reader.reset();
                            Log.i(this.getClass().getName(), "Reset the card (warm reset)");
                            break;
                        case VPCD_CTRL_ATR:
                            out = reader.getATR();
                            if (out == null) {
                                // Tag removed: reply with an empty frame so vpcd/pcscd won't block,
                                // then disconnect to transition to 'no card'.
                                out = new byte[0];
                                disconnectAfterSend = true;
                            }
                            break;
                        default:
                            throw new IOException("Unhandled command from VPCD.");
                    }
                } else {
                    Log.i(this.getClass().getName(), "C-APDU: " + Hex.getHexString(in));
                    try {
                        out = reader.transmit(in);
                        Log.i(this.getClass().getName(), "R-APDU: " + Hex.getHexString(out));
                    } catch (IOException e) {
                        // Most commonly TagLostException: card removed during APDU.
                        Log.i(this.getClass().getName(), "Card I/O failed (card removed?): " + e.getMessage());
                        out = new byte[0];
                        disconnectAfterSend = true;
                    }
                }
                if (out != null) {
                    sendToVPCD(out);
                }

                if (disconnectAfterSend) {
                    break;
                }
            }
        } catch (Exception e) {
            if (!isCancelled()) {
                e.printStackTrace();
                Log.i(this.getClass().getName(), "ERROR: " + e.getMessage());
            }
        }
        try {
            vpcdDisconnect();
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }

    @Nullable
    private byte[] receiveFromVPCD() throws IOException {
        if (secureMode) {
            try {
                return receiveEncryptedFrame();
            } catch (Exception e) {
                throw new IOException("Failed to receive encrypted frame: " + e.getMessage(), e);
            }
        }
        /* convert length from network byte order.
        Note that Java always uses network byte order internally. */
        int length1 = inputStream.read();
        int length2 = inputStream.read();
        if (length1 == -1 || length2 == -1) {
            // EOF
            return null;
        }
        int length = (length1 << 8) + length2;

        byte[] data = new byte[length];

        int offset = 0;
        while (length > 0) {
            int read = inputStream.read(data, offset, length);
            if (read == -1) {
                // EOF
                return null;
            }
            offset += read;
            length -= read;
        }

        return data;
    }

    private void sendToVPCD(byte[] data) throws IOException {
        if (secureMode) {
            try {
                sendEncryptedFrame(data);
                return;
            } catch (Exception e) {
                throw new IOException("Failed to send encrypted frame: " + e.getMessage(), e);
            }
        }
        /* convert length to network byte order.
        Note that Java always uses network byte order internally. */
        byte[] packet = new byte[2 + data.length];
        packet[0] = (byte) (data.length >> 8);
        packet[1] = (byte) (data.length & 0xff);
        System.arraycopy(data, 0, packet, 2, data.length);

        outputStream.write(packet);
        outputStream.flush();
    }

    private void vpcdConnection(VPCDWorkerParams params) throws IOException {
        if (params.listen){
            vpcdListen(params.port);
            return;
        }

        loadConfigFromPrefs();
        try {
            CryptoUtils.ensureConscrypt();
            String pubKeyAppHex = CryptoUtils.ensureAndStorePublicKey(appContext);
            sharedSecret = deriveSharedSecret(pubKeyPcHex);

            Log.i(this.getClass().getName(), "Connecting to " + params.hostname + ":" + params.port + "...");
            vpcdConnect(params.hostname, params.port);
            Log.i(this.getClass().getName(), "Connected to middlepoint");

            performHandshake();
            if (!isPairingConfirmed()) {
                sendPairingMessage(pubKeyAppHex, hexToBytes(pubKeyAppHex));
                setPairingConfirmed(true);
                Log.i(this.getClass().getName(), "Pairing message delivered on persistent connection");
            }
            secureMode = true;
            Log.i(this.getClass().getName(), "Secure channel established with existing pairing");
        } catch (Exception e) {
            throw new IOException("Could not initialize secure channel: " + e.getMessage(), e);
        }
    }

    private void vpcdListen(int port) throws IOException {
        listenSocket = new ServerSocket(port);

        final List<String> ifaceAddresses = new LinkedList<>();
        final Enumeration<NetworkInterface> ifaces = NetworkInterface.getNetworkInterfaces();
        while(ifaces.hasMoreElements()){
            final NetworkInterface iface = ifaces.nextElement();
            if (!iface.isUp() || iface.isLoopback() || iface.isVirtual()) {
                continue;
            }
            for(InterfaceAddress addr : iface.getInterfaceAddresses()){
                final InetAddress inetAddr = addr.getAddress();
                ifaceAddresses.add(inetAddr.getHostAddress());
            }
        }

        Log.i(this.getClass().getName(), "Listening on port " + port + ". Local addresses: " + join(", ", ifaceAddresses));
    }

    private void vpcdAccept() throws IOException {
        if(listenSocket == null){
            return;
        }

        if (socket != null){
            return;  // Already accepted, only one client allowed
        }

        Log.i(this.getClass().getName(),"Waiting for connections...");
        while(!isCancelled()) {
            listenSocket.setSoTimeout(1000);
            try {
                socket = listenSocket.accept();
                socket.setTcpNoDelay(true);
            } catch (SocketTimeoutException ignored){}
            if (socket != null){
                break;
            }
        }

        Log.i(this.getClass().getName(),"Connected, " + socket.getInetAddress());
        listenSocket.setSoTimeout(0);
        outputStream = socket.getOutputStream();
        inputStream = socket.getInputStream();
    }

    private void vpcdCloseClient(){
        try {
            outputStream.close();
        } catch (IOException ignored) { }
        try {
            inputStream.close();
        } catch (IOException ignored) { }
        try {
            socket.close();
        } catch (IOException ignored) { }
        outputStream = null;
        inputStream = null;
        socket = null;
    }

    private void vpcdConnect(String hostname, int port) throws IOException {
        listenSocket = null;
        InetAddress address = resolveAddress(hostname);
        Log.i(this.getClass().getName(), "Resolved " + hostname + " to " + address.getHostAddress());
        socket = new Socket(address, port);
        socket.setTcpNoDelay(true);
        outputStream = socket.getOutputStream();
        inputStream = socket.getInputStream();
    }

    static InetAddress resolveAddress(String hostname) throws IOException {
        try {
            return InetAddress.getByName(hostname);
        } catch (UnknownHostException e) {
            throw new IOException("Could not resolve hostname '" + hostname + "'. Use a reachable IP or fix DNS.", e);
        }
    }

    private void vpcdDisconnect() throws IOException {
        if (reader != null) {
            reader.eject();
        }
        if  (socket != null) {
            socket.close();
            Log.i(this.getClass().getName(), "Disconnected from VPCD");
        }
        if  (listenSocket != null) {
            Log.i(this.getClass().getName(), "Closing listening socket");
            listenSocket.close();
        }
    }

    private void loadConfigFromPrefs() throws IOException {
        if (appContext == null) {
            throw new IOException("Application context unavailable");
        }
        SharedPreferences sp = PreferenceManager.getDefaultSharedPreferences(appContext);
        pairingId = sp.getString("pairing_id", null);
        deviceId = sp.getString("device_id", null);
        pubKeyPcHex = sp.getString("pubkey_pc", null);
        qrSecret = sp.getString("qr_secret", null);
        if (pairingId == null || pairingId.isEmpty()
                || deviceId == null || deviceId.isEmpty()
                || pubKeyPcHex == null || pubKeyPcHex.isEmpty()
                || qrSecret == null || qrSecret.isEmpty()) {
            throw new IOException("Missing pairing configuration, scan QR again.");
        }
    }

    private boolean isPairingConfirmed() throws IOException {
        if (appContext == null) {
            throw new IOException("Application context unavailable");
        }
        SharedPreferences sp = PreferenceManager.getDefaultSharedPreferences(appContext);
        return sp.getBoolean("pairing_confirmed", true);
    }

    private void setPairingConfirmed(boolean confirmed) throws IOException {
        if (appContext == null) {
            throw new IOException("Application context unavailable");
        }
        SharedPreferences sp = PreferenceManager.getDefaultSharedPreferences(appContext);
        if (!sp.edit().putBoolean("pairing_confirmed", confirmed).commit()) {
            throw new IOException("Could not persist pairing state");
        }
    }

    private static byte[] hexToBytes(String hex) {
        if (hex == null) return null;
        int len = hex.length();
        if ((len % 2) != 0) {
            throw new IllegalArgumentException("Hex string must have even length");
        }
        byte[] out = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            out[i / 2] = (byte) ((Character.digit(hex.charAt(i), 16) << 4)
                    + Character.digit(hex.charAt(i + 1), 16));
        }
        return out;
    }

    private byte[] deriveSharedSecret(String peerHex) throws Exception {
        byte[] peerRaw = hexToBytes(peerHex);
        if (peerRaw == null || peerRaw.length != 32) {
            throw new IllegalArgumentException("Invalid peer public key");
        }
        PrivateKey priv = CryptoUtils.loadPrivateKey(appContext);
        if (priv == null) {
            throw new IllegalStateException("Private key missing, rescan QR.");
        }
        PublicKey peer = decodeX25519PublicKey(peerRaw);
        KeyAgreement ka = KeyAgreement.getInstance("X25519");
        ka.init(priv);
        ka.doPhase(peer, true);
        return ka.generateSecret();
    }

    private PublicKey decodeX25519PublicKey(byte[] raw) throws Exception {
        byte[] spki = new byte[12 + raw.length];
        byte[] prefix = new byte[]{0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x6e, 0x03, 0x21, 0x00};
        System.arraycopy(prefix, 0, spki, 0, prefix.length);
        System.arraycopy(raw, 0, spki, prefix.length, raw.length);
        X509EncodedKeySpec spec = new X509EncodedKeySpec(spki);
        KeyFactory kf = KeyFactory.getInstance("X25519");
        return kf.generatePublic(spec);
    }

    private void performHandshake() throws IOException, GeneralSecurityException {
        String msg = String.format("{\"message_type\":\"handshake\",\"pairing_id\":\"%s\",\"device_id\":\"%s\",\"role\":\"app\"}", pairingId, deviceId);
        sendJsonLine(msg);
        waitForStatusOk();
    }

    private void sendPairingMessage(String pubKeyAppHex, byte[] pubKeyAppRaw) throws Exception {
        String macHex = computeMac(qrSecret, pubKeyAppRaw);
        String payload = "mac=" + macHex + "&pubKeyApp=" + pubKeyAppHex;
        String msg = String.format("{\"message_type\":\"communication\",\"source_id\":\"%s\",\"payload\":\"%s\"}", deviceId, payload);
        sendJsonLine(msg);
        waitForStatusOk();
    }

    private String computeMac(String secret, byte[] data) throws Exception {
        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(new SecretKeySpec(secret.getBytes(StandardCharsets.UTF_8), "HmacSHA256"));
        return CryptoUtils.bytesToHex(mac.doFinal(data));
    }

    private void sendJsonLine(String json) throws IOException {
        byte[] bytes = (json + "\n").getBytes(StandardCharsets.UTF_8);
        outputStream.write(bytes);
        outputStream.flush();
    }

    private String readJsonLine() throws IOException {
        StringBuilder sb = new StringBuilder();
        int ch;
        while ((ch = inputStream.read()) != -1) {
            if (ch == '\n') {
                break;
            }
            sb.append((char) ch);
        }
        if (sb.length() == 0 && ch == -1) {
            return null;
        }
        return sb.toString().trim();
    }

    private void waitForStatusOk() throws IOException {
        while (true) {
            String line = readJsonLine();
            if (line == null) {
                throw new IOException("Connection closed while waiting for status");
            }
            if (line.isEmpty()) {
                continue;
            }
            try {
                org.json.JSONObject obj = new org.json.JSONObject(line);
                if (obj.has("status_code")) {
                    int code = obj.getInt("status_code");
                    if (code != 200) {
                        throw new IOException("Server returned status " + code);
                    }
                    return;
                }
            } catch (org.json.JSONException ignored) { }
        }
    }

    private byte[] receiveEncryptedFrame() throws Exception {
        while (true) {
            String line = readJsonLine();
            if (line == null) {
                return null;
            }
            if (line.isEmpty()) {
                continue;
            }
            try {
                org.json.JSONObject obj = new org.json.JSONObject(line);
                if (obj.has("status_code")) {
                    int code = obj.getInt("status_code");
                    if (code != 200) {
                        throw new IOException("Received status " + code);
                    }
                    continue;
                }
                if (!obj.has("payload")) {
                    continue;
                }
                String payload = obj.getString("payload");
                byte[] plain = decryptPayload(payload);
                if (plain == null || plain.length < 2) {
                    throw new IOException("Invalid decrypted frame");
                }
                int length = ((plain[0] & 0xff) << 8) | (plain[1] & 0xff);
                if (length > plain.length - 2) {
                    throw new IOException("Frame length mismatch");
                }
                byte[] out = new byte[length];
                System.arraycopy(plain, 2, out, 0, length);
                return out;
            } catch (org.json.JSONException ignored) { }
        }
    }

    private void sendEncryptedFrame(byte[] data) throws Exception {
        if (sharedSecret == null) {
            throw new IllegalStateException("Shared secret not established");
        }
        byte[] plain = new byte[data.length + 2];
        plain[0] = (byte) (data.length >> 8);
        plain[1] = (byte) (data.length & 0xff);
        System.arraycopy(data, 0, plain, 2, data.length);

        String payload = encryptPayload(plain);
        String msg = String.format("{\"message_type\":\"communication\",\"source_id\":\"%s\",\"payload\":\"%s\"}", deviceId, payload);
        sendJsonLine(msg);
        waitForStatusOk();
    }

    private String encryptPayload(byte[] plain) throws Exception {
        byte[] nonce = new byte[12];
        new SecureRandom().nextBytes(nonce);
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        GCMParameterSpec spec = new GCMParameterSpec(128, nonce);
        SecretKeySpec keySpec = new SecretKeySpec(sharedSecret, "AES");
        cipher.init(Cipher.ENCRYPT_MODE, keySpec, spec);
        byte[] ct = cipher.doFinal(plain);
        byte[] blob = new byte[nonce.length + ct.length];
        System.arraycopy(nonce, 0, blob, 0, nonce.length);
        System.arraycopy(ct, 0, blob, nonce.length, ct.length);
        return Base64.encodeToString(blob, Base64.NO_WRAP);
    }

    private byte[] decryptPayload(String payload) throws Exception {
        byte[] blob = Base64.decode(payload, Base64.DEFAULT);
        if (blob.length < 12 + 16) {
            throw new IOException("Ciphertext too short");
        }
        byte[] nonce = Arrays.copyOfRange(blob, 0, 12);
        byte[] ct = Arrays.copyOfRange(blob, 12, blob.length);
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        GCMParameterSpec spec = new GCMParameterSpec(128, nonce);
        SecretKeySpec keySpec = new SecretKeySpec(sharedSecret, "AES");
        cipher.init(Cipher.DECRYPT_MODE, keySpec, spec);
        return cipher.doFinal(ct);
    }

    /**
     * Usage of API level 24+ would allow streams(), join can be removed.
     */
    private static String join(String separator, List<String> input) {
        if (input == null || input.isEmpty()) return "";
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < input.size(); i++) {
            sb.append(input.get(i));
            if (i != input.size() - 1) {
                sb.append(separator);
            }
        }
        return sb.toString();

    }
}
