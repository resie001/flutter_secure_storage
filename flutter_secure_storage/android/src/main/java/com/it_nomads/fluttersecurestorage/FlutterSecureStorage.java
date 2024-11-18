package com.it_nomads.fluttersecurestorage;

import android.content.Context;
import android.content.SharedPreferences;
import android.os.Build;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;
import android.util.Base64;
import android.util.Log;

import androidx.annotation.RequiresApi;

import com.it_nomads.fluttersecurestorage.ciphers.StorageCipher;
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
    private StorageCipher storageCipher;
    private StorageCipherFactory storageCipherFactory;

    public FlutterSecureStorage(Context context, Map<String, Object> options) {
        this.options = options;
        applicationContext = context.getApplicationContext();
    }

    @SuppressWarnings({"ConstantConditions"})
    boolean getResetOnError() {
        return options.containsKey("resetOnError") && options.get("resetOnError").equals("true");
    }

    public boolean containsKey(String key) {
        ensureInitialized();
        return preferences.contains(key);
    }

    public String addPrefixToKey(String key) {
        return ELEMENT_PREFERENCES_KEY_PREFIX + "_" + key;
    }

    public String read(String key) throws Exception {
        ensureInitialized();

        return preferences.getString(key, null);
    }

    @SuppressWarnings("unchecked")
    public Map<String, String> readAll() throws Exception {
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

    public void write(String key, String value) throws Exception {
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

   protected void ensureOptions(){
       if (options.containsKey("sharedPreferencesName") && !((String) options.get("sharedPreferencesName")).isEmpty()) {
           SHARED_PREFERENCES_NAME = (String) options.get("sharedPreferencesName");
       }

       if (options.containsKey("preferencesKeyPrefix") && !((String) options.get("preferencesKeyPrefix")).isEmpty()) {
           ELEMENT_PREFERENCES_KEY_PREFIX = (String) options.get("preferencesKeyPrefix");
       }
    }


    @SuppressWarnings({"ConstantConditions"})
    private void ensureInitialized() {
        ensureOptions();

        try {
            preferences = initializeEncryptedSharedPreferencesManager(applicationContext);
            checkAndMigrateToEncrypted(preferences);
        } catch (Exception e) {
            Log.e(TAG, "EncryptedSharedPreferences initialization failed", e);
        }

    }

    private void initStorageCipher(SharedPreferences source) throws Exception {
        storageCipherFactory = new StorageCipherFactory(source, options);
        storageCipher = storageCipherFactory.getSavedStorageCipher(applicationContext);
//        if (getUseEncryptedSharedPreferences()) {
//            storageCipher = storageCipherFactory.getSavedStorageCipher(applicationContext);
//        } else if (storageCipherFactory.requiresReEncryption()) {
//            reEncryptPreferences(storageCipherFactory, source);
//        } else {
//            storageCipher = storageCipherFactory.getCurrentStorageCipher(applicationContext);
//        }
    }

    private void checkAndMigrateToEncrypted(SharedPreferences target) {
        SharedPreferences source = applicationContext.getSharedPreferences(
                SHARED_PREFERENCES_NAME,
                Context.MODE_PRIVATE
        );
        if (storageCipher == null) {
            try {
                initStorageCipher(source);

            } catch (Exception e) {
                Log.e(TAG, "StorageCipher initialization failed", e);
            }
        }

        try {
            for (Map.Entry<String, ?> entry : source.getAll().entrySet()) {
                Object v = entry.getValue();
                String key = entry.getKey();
                if (v instanceof String && key.contains(ELEMENT_PREFERENCES_KEY_PREFIX)) {
                    final String decodedValue = decodeRawValue((String) v);
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

    private String decodeRawValue(String value) throws Exception {
        if (value == null) {
            return null;
        }
        byte[] data = Base64.decode(value, 0);
        byte[] result = storageCipher.decrypt(data);

        return new String(result, charset);
    }
}
