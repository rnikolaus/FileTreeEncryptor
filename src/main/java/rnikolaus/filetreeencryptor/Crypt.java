package rnikolaus.filetreeencryptor;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardCopyOption;
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
    private final IvParameterSpec iv;

    public Crypt(boolean encrypt, Path sourcePath, Path targetPath, byte[] key) {
        if (targetPath.startsWith(sourcePath)) {
            throw new IllegalArgumentException(targetPath+" may not be a subpath of "+sourcePath);
        }
        if (!Files.exists(sourcePath)) {
            throw new IllegalArgumentException(sourcePath + " doesn't exist");
        }
        if (!Files.isDirectory(sourcePath)) {
            throw new IllegalArgumentException(sourcePath + " is not a directory");
        }
        if (Files.exists(targetPath)) {
            if (!Files.isDirectory(targetPath)) {
                throw new IllegalArgumentException(targetPath + " is not a directory");
            }
            if (targetPath.toFile().list().length > 0) {
                throw new IllegalArgumentException(targetPath + " is not empty");
            }
        } else {//failing fast if the directory cannot be created
            try {
                Files.createDirectories(targetPath);
            } catch (Exception ex) {
                throw new RuntimeException(ex);
            }
        }

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

    private Path preparePath(Path file) throws IOException {
        final String pathString = targetPath.resolve(sourcePath.relativize(file)).toString();
        Path result;
        if (encrypt) {
            result = Paths.get(pathString + ".enc");
        } else {
            result = Paths.get(pathString.replaceFirst("\\.enc$", ""));
        }
        final Path parent = result.getParent();
        if (!Files.exists(parent)) {
            Files.createDirectories(parent);
        }
        return result;
    }

}
