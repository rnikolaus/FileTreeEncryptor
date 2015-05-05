package rnikolaus.filetreeencryptor;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Base64.Decoder;
import java.util.Base64.Encoder;
import java.util.List;
import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/**
 *
 * @author rapnik
 */
public class Crypt {

    private final Path sourcePath;
    private final Path targetPath;

    private final boolean encrypt;
    private final static String ALGORITHM = "Blowfish";
    private final static String FULLALGORITHM = ALGORITHM + "/CBC/PKCS5Padding";
    private final SecretKeySpec secretKeySpec;
    private final ThreadLocal<Cipher> cipher;
    private final ThreadLocal<Encoder> encoder;
    private final ThreadLocal<Decoder> decoder;

    private final IvParameterSpec iv;

    public Crypt(boolean encrypt, Path sourcePath, Path targetPath, byte[] key) {
        checkParameters(targetPath, sourcePath);
        this.sourcePath = sourcePath;
        this.targetPath = targetPath;
        this.encrypt = encrypt;
        iv = new IvParameterSpec(new byte[]{100, 20, 3, 127, 5, 10, 7, 80});
        secretKeySpec = new SecretKeySpec(key, ALGORITHM);
        cipher = new ThreadLocal<Cipher>() {//this allows multithreaded crypt operations
            @Override
            protected Cipher initialValue() {
                try {
                    return getCipher();
                } catch (Exception ex) {
                    throw new RuntimeException(ex);
                }
            }
        };
        if (encrypt) {
            encoder = constructEncoder();
            decoder = null;
        } else {
            encoder = null;
            decoder = constructDecoder();
        }

    }

    private void checkParameters(Path targetPath1, Path sourcePath1) throws RuntimeException, IllegalArgumentException {
        if (targetPath1.startsWith(sourcePath1)) {
            throw new IllegalArgumentException(targetPath1 + " may not be a subpath of " + sourcePath1);
        }
        if (!Files.exists(sourcePath1)) {
            throw new IllegalArgumentException(sourcePath1 + " doesn't exist");
        }
        if (!Files.isDirectory(sourcePath1)) {
            throw new IllegalArgumentException(sourcePath1 + " is not a directory");
        }
        if (Files.exists(targetPath1)) {
            if (!Files.isDirectory(targetPath1)) {
                throw new IllegalArgumentException(targetPath1 + " is not a directory");
            }
            if (targetPath1.toFile().list().length > 0) {
                throw new IllegalArgumentException(targetPath1 + " is not empty");
            }
        } else {
            //failing fast if the directory cannot be created
            try {
                Files.createDirectories(targetPath1);
            }catch (Exception ex) {
                throw new RuntimeException(ex);
            }
        }
    }

    private static ThreadLocal<Encoder> constructEncoder() {
        return new ThreadLocal<Encoder>() {//this allows multithreaded crypt operations
            @Override
            protected Encoder initialValue() {
                try {
                    return Base64.getUrlEncoder();
                } catch (Exception ex) {
                    throw new RuntimeException(ex);
                }
            }
        };
    }

    private static ThreadLocal<Decoder> constructDecoder() {
        return new ThreadLocal<Decoder>() {//this allows multithreaded crypt operations
            @Override
            protected Decoder initialValue() {
                try {
                    return Base64.getUrlDecoder();
                } catch (Exception ex) {
                    throw new RuntimeException(ex);
                }
            }
        };
    }

    public void work() throws IOException {
        Files.walk(sourcePath).parallel()
                .filter(p -> Files.isRegularFile(p))
                .forEach((Path t) -> {
                    crypt(t);
                });
    }

    private Cipher getCipher() throws Exception {
        Cipher cipher1 = Cipher.getInstance(FULLALGORITHM);

        if (encrypt) {
            cipher1.init(Cipher.ENCRYPT_MODE, secretKeySpec, iv);
        } else {
            cipher1.init(Cipher.DECRYPT_MODE, secretKeySpec, iv);
        }
        return cipher1;
    }

    private void crypt(Path file) {
        try {
            CipherInputStream input = new CipherInputStream(Files.newInputStream(file), cipher.get());
            final Path preparePath = preparePath(file);
            Files.copy(input, preparePath);
            preparePath.toFile().setLastModified(file.toFile().lastModified());
        } catch (Exception ex) {
            throw new RuntimeException(ex);
        }
    }

    private Path preparePath(Path file) throws Exception {
        final Path path = sourcePath.relativize(file);
        Path result;
        List<String> pathList = new ArrayList<>();
        if (encrypt) {
            for (Path subpath : path) {
                final String subPathName = subpath.getFileName().toString();
                byte[] res = encoder.get().encode(cipher.get().doFinal(subPathName.getBytes()));
                pathList.add(new String(res));
            }
        } else {
            for (Path subpath : path) {
                final String supPathName = subpath.getFileName().toString();
                byte[] res = cipher.get().doFinal(decoder.get().decode(supPathName.getBytes()));
                pathList.add(new String(res));
            }
        }
        String first = pathList.remove(0);
        result = Paths.get(first, pathList.toArray(new String[pathList.size()]));
        result = targetPath.resolve(result);
        final Path parent = result.getParent();
        if (!Files.exists(parent)) {
            Files.createDirectories(parent);
        }
        return result;
    }

}
