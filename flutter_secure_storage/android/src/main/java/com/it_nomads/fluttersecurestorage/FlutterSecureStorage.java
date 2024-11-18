package com.it_nomads.fluttersecurestorage;

import android.content.Context;
import android.content.SharedPreferences;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;
import android.util.Base64;
import android.util.Log;

import com.it_nomads.fluttersecurestorage.ciphers.StorageCipherFactory;
import com.it_nomads.fluttersecurestorage.crypto.EncryptedSharedPreferences;
import com.it_nomads.fluttersecurestorage.crypto.MasterKey;

import java.io.IOException;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.util.HashMap;
import java.util.Map;

public class FlutterSecureStorage {

    private final String TAG = "SecureStorageAndroid";
    private final Charset charset = StandardCharsets.UTF_8;
    private final Context applicationContext;
    protected String ELEMENT_PREFERENCES_KEY_PREFIX = "VGhpcyBpcyB0aGUgcHJlZml4IGZvciBhIHNlY3VyZSBzdG9yYWdlCg";
    protected Map<String, Object> options;
    private String SHARED_PREFERENCES_NAME = "FlutterSecureStorage";
    private SharedPreferences preferences;

    public FlutterSecureStorage(Context context, Map<String, Object> options) {
        this.options = options;
        applicationContext = context.getApplicationContext();
    }

    boolean getResetOnError() {
        Object value = options.containsKey("resetOnError") ? options.get("resetOnError") : "false";
        return String.valueOf(value).equals("true");
    }

    public boolean containsKey(String key) {
        ensureInitialized();
        return preferences.contains(key);
    }

    public String addPrefixToKey(String key) {
        return ELEMENT_PREFERENCES_KEY_PREFIX + "_" + key;
    }

    public String read(String key) {
        ensureInitialized();

        return preferences.getString(key, null);
    }

    @SuppressWarnings("unchecked")
    public Map<String, String> readAll() {
        ensureInitialized();

        Map<String, String> raw = (Map<String, String>) preferences.getAll();

        Map<String, String> all = new HashMap<>();
        for (Map.Entry<String, String> entry : raw.entrySet()) {
            String keyWithPrefix = entry.getKey();
            if (keyWithPrefix.contains(ELEMENT_PREFERENCES_KEY_PREFIX)) {
                String key = entry.getKey().replaceFirst(ELEMENT_PREFERENCES_KEY_PREFIX + '_', "");
                all.put(key, entry.getValue());
            }
        }
        return all;
    }

    public void write(String key, String value) {
        ensureInitialized();

        SharedPreferences.Editor editor = preferences.edit();

        editor.putString(key, value);
        editor.apply();
    }

    public void delete(String key) {
        ensureInitialized();

        SharedPreferences.Editor editor = preferences.edit();
        editor.remove(key);
        editor.apply();
    }

    public void deleteAll() {
        ensureInitialized();

        final SharedPreferences.Editor editor = preferences.edit();
        editor.clear();
        editor.apply();
    }

    protected void ensureOptions() {
        String sharedPreferencesName = getStringOption("sharedPreferencesName");
        if (!sharedPreferencesName.isEmpty()) {
            SHARED_PREFERENCES_NAME = sharedPreferencesName;
        }

        String preferencesKeyPrefix = getStringOption("preferencesKeyPrefix");
        if (!preferencesKeyPrefix.isEmpty()) {
            ELEMENT_PREFERENCES_KEY_PREFIX = preferencesKeyPrefix;
        }
    }

    private String getStringOption(String key) {
        Object value = options.get(key);
        return value instanceof String ? (String) value : "";
    }

    private void ensureInitialized() {
        ensureOptions();

        try {
            preferences = initializeEncryptedSharedPreferencesManager(applicationContext);
            checkAndMigrateToEncrypted(preferences);
        } catch (Exception e) {
            Log.e(TAG, "EncryptedSharedPreferences initialization failed", e);
        }
    }

    private void checkAndMigrateToEncrypted(SharedPreferences target) {
        SharedPreferences source = applicationContext.getSharedPreferences(
                SHARED_PREFERENCES_NAME,
                Context.MODE_PRIVATE
        );
        try {
            final var storageCipherFactory = new StorageCipherFactory(source, options);
            final var storageCipher = storageCipherFactory.getSavedStorageCipher(applicationContext);

            try {
                for (Map.Entry<String, ?> entry : source.getAll().entrySet()) {
                    Object v = entry.getValue();
                    String key = entry.getKey();
                    if (v instanceof String && key.contains(ELEMENT_PREFERENCES_KEY_PREFIX)) {

                        byte[] data = Base64.decode((String) v, 0);
                        byte[] result = storageCipher.decrypt(data);

                        final String decodedValue = new String(result, charset);

                        target.edit().putString(key, (decodedValue)).apply();
                        source.edit().remove(key).apply();
                    }
                }
                final SharedPreferences.Editor sourceEditor = source.edit();
                storageCipherFactory.removeCurrentAlgorithms(sourceEditor);
                sourceEditor.apply();
            } catch (Exception e) {
                Log.e(TAG, "Data migration failed", e);
            }
        } catch (Exception e) {
            Log.e(TAG, "StorageCipher initialization failed", e);
        }
    }

    private SharedPreferences initializeEncryptedSharedPreferencesManager(Context context) throws GeneralSecurityException, IOException {
        MasterKey key = new MasterKey.Builder(context)
                .setKeyGenParameterSpec(
                        new KeyGenParameterSpec
                                .Builder(MasterKey.DEFAULT_MASTER_KEY_ALIAS, KeyProperties.PURPOSE_ENCRYPT | KeyProperties.PURPOSE_DECRYPT)
                                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                                .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                                .setKeySize(256).build())
                .build();
        return EncryptedSharedPreferences.create(
                context,
                SHARED_PREFERENCES_NAME,
                key,
                EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
                EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM
        );
    }
}
