package pl.isec.baseapp.invalidauthentication;


import static java.nio.charset.StandardCharsets.UTF_8;
import static java.nio.file.StandardOpenOption.CREATE;
import static java.nio.file.StandardOpenOption.READ;
import static java.nio.file.StandardOpenOption.TRUNCATE_EXISTING;
import static java.nio.file.StandardOpenOption.WRITE;

import android.content.Context;
import androidx.annotation.NonNull;
import androidx.biometric.BiometricPrompt;
import androidx.core.content.ContextCompat;
import androidx.fragment.app.FragmentActivity;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.security.GeneralSecurityException;
import java.security.KeyException;
import java.security.KeyStore;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;

public final class SecureFileBiometricImpl extends SecureFile {
    private static final String ANDROID_KEYSTORE = "AndroidKeyStore";
    private static final String AUTHENTICATION_FAILED = "Authentication failed";

    private static final String AES_GCM_NOPADDING = "AES/GCM/NoPadding";
    private static final int IV_SIZE_IN_BYTES = 12;
    private static final int TAG_SIZE_IN_BYTES = 16;

    private final BiometricPrompt.PromptInfo mPromptInfo;
    private final FragmentActivity mActivity;

    public SecureFileBiometricImpl(
            @NonNull File file,
            @NonNull Context context,
            @NonNull String keyAlias,
            @NonNull FragmentActivity activity,
            @NonNull BiometricPrompt.PromptInfo promptInfo
    ){
        super(file, context, keyAlias);
        mActivity = activity;
        mPromptInfo = promptInfo;
    }

    @Override
    public void openFileInput(@NonNull OpenFileInputCallback callback){
        try {
            byte[] iv = new byte[IV_SIZE_IN_BYTES];
            InputStream inputStream = Files.newInputStream(mFile.toPath(), READ);
            inputStream.read(iv, 0, IV_SIZE_IN_BYTES);
            inputStream.close();

            Cipher cipher = Cipher.getInstance(AES_GCM_NOPADDING);
            GCMParameterSpec spec = new GCMParameterSpec(8 * TAG_SIZE_IN_BYTES, iv);
            cipher.init(Cipher.DECRYPT_MODE, getSecretKey(), spec);

            newBiometricPrompt(callback).authenticate(
                    mPromptInfo,
                    new BiometricPrompt.CryptoObject(cipher)
            );
        } catch (Exception e) {
            callback.onError(e.getMessage());
        }
    }

    @Override
    public void openFileOutput(@NonNull OpenFileOutputCallback callback){
        try {
            Cipher cipher = Cipher.getInstance(AES_GCM_NOPADDING);
            cipher.init(Cipher.ENCRYPT_MODE, getSecretKey());

            newBiometricPrompt(callback).authenticate(
                    mPromptInfo,
                    new BiometricPrompt.CryptoObject(cipher)
            );
        } catch (Exception e) {
            callback.onError(e.getMessage());
        }
    }

    private BiometricPrompt newBiometricPrompt(OpenFileInputCallback callback){
        return new BiometricPrompt(
                mActivity,
                ContextCompat.getMainExecutor(mContext),
                new BiometricPrompt.AuthenticationCallback() {
                    @Override
                    public void onAuthenticationError(int errorCode, CharSequence errString) {
                        super.onAuthenticationError(errorCode, errString);
                        callback.onError(errString);
                    }

                    @Override
                    public void onAuthenticationSucceeded(BiometricPrompt.AuthenticationResult result) {
                        super.onAuthenticationSucceeded(result);
                        try {
                            byte[] ciphertext = Files.readAllBytes(mFile.toPath());
                            Cipher cipher = result.getCryptoObject().getCipher();
                            cipher.updateAAD(mFile.getName().getBytes(UTF_8));

                            callback.onInputStreamReady(
                                    new ByteArrayInputStream(
                                            cipher.doFinal(
                                                    ciphertext,
                                                    IV_SIZE_IN_BYTES,
                                                    ciphertext.length - IV_SIZE_IN_BYTES
                                            )
                                    )
                            );
                        } catch (Exception e){
                            callback.onError(e.getMessage());
                        }
                    }

                    @Override
                    public void onAuthenticationFailed() {
                        super.onAuthenticationFailed();
                        callback.onError(AUTHENTICATION_FAILED);
                    }
                });
    }

    private BiometricPrompt newBiometricPrompt(OpenFileOutputCallback callback){
        return new BiometricPrompt(
                mActivity,
                ContextCompat.getMainExecutor(mContext),
                new BiometricPrompt.AuthenticationCallback() {
                    @Override
                    public void onAuthenticationError(int errorCode, CharSequence errString) {
                        super.onAuthenticationError(errorCode, errString);
                        callback.onError(errString);
                    }

                    @Override
                    public void onAuthenticationSucceeded(BiometricPrompt.AuthenticationResult result) {
                        super.onAuthenticationSucceeded(result);
                        try {
                            ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
                            callback.onOutputStreamReady(outputStream);
                            byte[] plaintext = outputStream.toByteArray();

                            Cipher cipher = result.getCryptoObject().getCipher();
                            byte[] ciphertext = new byte[
                                    IV_SIZE_IN_BYTES + cipher.getOutputSize(plaintext.length)
                                    ];

                            System.arraycopy(cipher.getIV(), 0, ciphertext, 0, IV_SIZE_IN_BYTES);
                            cipher.updateAAD(mFile.getName().getBytes(UTF_8));
                            cipher.doFinal(
                                    plaintext,0, plaintext.length,
                                    ciphertext, IV_SIZE_IN_BYTES
                            );

                            Files.write(mFile.toPath(), ciphertext, CREATE, WRITE, TRUNCATE_EXISTING);
                        } catch (Exception e){
                            callback.onError(e.getMessage());
                        }
                    }

                    @Override
                    public void onAuthenticationFailed() {
                        super.onAuthenticationFailed();
                        callback.onError(AUTHENTICATION_FAILED);
                    }
                });
    }

    private SecretKey getSecretKey() throws IOException, GeneralSecurityException {
        KeyStore ks = KeyStore.getInstance(ANDROID_KEYSTORE);
        ks.load(null);

        if (!ks.containsAlias(mKeyAlias)) {
            throw new KeyException("Key alias not found: "+ mKeyAlias);
        }
        return (SecretKey) ks.getKey(mKeyAlias, null);
    }
}
