package pl.isec.baseapp.invalidauthentication;

import android.content.Context;
import androidx.annotation.NonNull;
import java.io.File;
import java.io.InputStream;
import java.io.OutputStream;

public abstract class SecureFile {
    protected final File mFile;
    protected final Context mContext;
    protected final String mKeyAlias;

    public SecureFile(
            @NonNull File file,
            @NonNull Context context,
            @NonNull String keyAlias
    ) {
        mFile = file;
        mContext = context;
        mKeyAlias = keyAlias;
    }

    public abstract void openFileInput(@NonNull OpenFileInputCallback callback);

    public abstract void openFileOutput(@NonNull OpenFileOutputCallback callback);

    public abstract static class OpenFileInputCallback {
        public abstract void onError(@NonNull CharSequence errString);
        public abstract void onInputStreamReady(@NonNull InputStream inputStream);
    }

    public abstract static class OpenFileOutputCallback {
        public abstract void onError(@NonNull CharSequence errString);
        public abstract void onOutputStreamReady(@NonNull OutputStream outputStream);
    }
}
