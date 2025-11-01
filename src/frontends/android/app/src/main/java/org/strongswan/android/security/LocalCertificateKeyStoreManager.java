package org.strongswan.android.security;

import android.content.Context;
import android.util.Base64;
import android.util.Log;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.Enumeration;

public class LocalCertificateKeyStoreManager {
    private static final String TAG = "LocalCertKeyStoreMgr";
    private static final String CERT_DIR = "user_certificates";
    private static final String KEY_DIR = "user_keys";
    private static final String P12_DIR = "user_p12";

    private final Context context;
    private final LocalCertificateStore certificateStore;

    public LocalCertificateKeyStoreManager(Context context) {
        this.context = context.getApplicationContext();
        this.certificateStore = new LocalCertificateStore();
        ensureDirectoriesExist();
    }

    private void ensureDirectoriesExist() {
        createDirIfNeeded(CERT_DIR);
        createDirIfNeeded(KEY_DIR);
        createDirIfNeeded(P12_DIR);
    }

    private void createDirIfNeeded(String dirName) {
        File dir = new File(context.getFilesDir(), dirName);
        if (!dir.exists()) {
            dir.mkdirs();
        }
    }

    public String importP12Certificate(String p12Base64, String password) {
        try {
            String cleanBase64 = p12Base64.replaceAll("\\s", "");
            byte[] p12Bytes = Base64.decode(cleanBase64, Base64.DEFAULT);
            if (p12Bytes == null || p12Bytes.length == 0) {
                return null;
            }
            KeyStore keyStore = KeyStore.getInstance("PKCS12");
            char[] passwordChars = (password != null && !password.isEmpty()) ? password.toCharArray() : new char[0];
            try {
                keyStore.load(new ByteArrayInputStream(p12Bytes), passwordChars);
            } catch (Exception e) {
                keyStore.load(new ByteArrayInputStream(p12Bytes), new char[0]);
            }
            Enumeration<String> aliases = keyStore.aliases();
            X509Certificate userCert = null;
            PrivateKey privateKey = null;
            while (aliases.hasMoreElements()) {
                String alias = aliases.nextElement();
                Certificate cert = keyStore.getCertificate(alias);
                if (cert instanceof X509Certificate) {
                    try {
                        PrivateKey key = (PrivateKey) keyStore.getKey(alias, passwordChars);
                        if (key != null) {
                            userCert = (X509Certificate) cert;
                            privateKey = key;
                            break;
                        }
                    } catch (Exception ignored) { }
                }
            }
            if (userCert == null || privateKey == null) {
                return null;
            }
            boolean certStored = certificateStore.addCertificate(userCert);
            if (!certStored) {
                return null;
            }
            String certAlias = certificateStore.getCertificateAlias(userCert);
            if (!storePrivateKey(certAlias, privateKey)) {
                certificateStore.deleteCertificate(certAlias);
                return null;
            }
            storeP12File(certAlias, p12Bytes, password);
            return certAlias;
        } catch (Exception e) {
            Log.e(TAG, "Failed to import P12 certificate", e);
            return null;
        }
    }

    private boolean storePrivateKey(String certAlias, PrivateKey privateKey) {
        try {
            String keyId = certAlias.startsWith("local:") ? certAlias.substring(6) : certAlias;
            File keyFile = new File(context.getFilesDir(), KEY_DIR + "/key-" + keyId);
            FileOutputStream out = new FileOutputStream(keyFile);
            try {
                out.write(privateKey.getEncoded());
                return true;
            } finally {
                out.close();
            }
        } catch (Exception e) {
            Log.e(TAG, "Failed to store private key", e);
            return false;
        }
    }

    private boolean storeP12File(String certAlias, byte[] p12Bytes, String password) {
        try {
            String keyId = certAlias.startsWith("local:") ? certAlias.substring(6) : certAlias;
            File p12File = new File(context.getFilesDir(), P12_DIR + "/cert-" + keyId + ".p12");
            FileOutputStream out = new FileOutputStream(p12File);
            try {
                out.write(p12Bytes);
            } finally {
                out.close();
            }
            if (password != null && !password.isEmpty()) {
                File pwdFile = new File(context.getFilesDir(), P12_DIR + "/cert-" + keyId + ".pwd");
                FileOutputStream pwdOut = new FileOutputStream(pwdFile);
                try {
                    pwdOut.write(password.getBytes("UTF-8"));
                } finally {
                    pwdOut.close();
                }
            }
            return true;
        } catch (Exception e) {
            Log.e(TAG, "Failed to store P12 file", e);
            return false;
        }
    }

    public String getP12FilePath(String certAlias) {
        if (certAlias == null) return null;
        String keyId = certAlias.startsWith("local:") ? certAlias.substring(6) : certAlias;
        File p12File = new File(context.getFilesDir(), P12_DIR + "/cert-" + keyId + ".p12");
        return p12File.exists() ? p12File.getAbsolutePath() : null;
    }

    public String getP12Password(String certAlias) {
        if (certAlias == null) return null;
        try {
            String keyId = certAlias.startsWith("local:") ? certAlias.substring(6) : certAlias;
            File pwdFile = new File(context.getFilesDir(), P12_DIR + "/cert-" + keyId + ".pwd");
            if (!pwdFile.exists()) {
                return "";
            }
            java.io.FileInputStream in = new java.io.FileInputStream(pwdFile);
            try {
                byte[] pwdBytes = new byte[(int) pwdFile.length()];
                in.read(pwdBytes);
                return new String(pwdBytes, "UTF-8");
            } finally {
                in.close();
            }
        } catch (Exception e) {
            Log.e(TAG, "Failed to read P12 password", e);
            return "";
        }
    }

    public boolean isCertificateAvailable(String certAlias) {
        if (certAlias == null || certAlias.isEmpty()) {
            return false;
        }
        return certificateStore.containsAlias(certAlias);
    }

    public PrivateKey getPrivateKey(String certAlias) {
        if (certAlias == null) return null;
        try {
            String keyId = certAlias.startsWith("local:") ? certAlias.substring(6) : certAlias;
            File keyFile = new File(context.getFilesDir(), KEY_DIR + "/key-" + keyId);
            if (!keyFile.exists()) {
                return null;
            }
            java.io.FileInputStream in = new java.io.FileInputStream(keyFile);
            try {
                byte[] keyBytes = new byte[(int) keyFile.length()];
                in.read(keyBytes);
                java.security.spec.PKCS8EncodedKeySpec keySpec = new java.security.spec.PKCS8EncodedKeySpec(keyBytes);
                java.security.KeyFactory keyFactory = java.security.KeyFactory.getInstance("RSA");
                try {
                    return keyFactory.generatePrivate(keySpec);
                } catch (Exception e) {
                    keyFactory = java.security.KeyFactory.getInstance("EC");
                    return keyFactory.generatePrivate(keySpec);
                }
            } finally {
                in.close();
            }
        } catch (Exception e) {
            Log.e(TAG, "Failed to load private key", e);
            return null;
        }
    }

    public void deleteCertificate(String certAlias) {
        if (certAlias == null) return;
        try {
            certificateStore.deleteCertificate(certAlias);
            String keyId = certAlias.startsWith("local:") ? certAlias.substring(6) : certAlias;
            File keyFile = new File(context.getFilesDir(), KEY_DIR + "/key-" + keyId);
            if (keyFile.exists()) keyFile.delete();
            File p12File = new File(context.getFilesDir(), P12_DIR + "/cert-" + keyId + ".p12");
            if (p12File.exists()) p12File.delete();
            File pwdFile = new File(context.getFilesDir(), P12_DIR + "/cert-" + keyId + ".pwd");
            if (pwdFile.exists()) pwdFile.delete();
        } catch (Exception e) {
            Log.e(TAG, "Failed to delete certificate", e);
        }
    }
}

