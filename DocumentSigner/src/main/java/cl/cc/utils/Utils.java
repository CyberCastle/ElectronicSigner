package cl.cc.utils;

import java.io.File;
import java.security.SecureRandom;

/**
 *
 * @author CyberCastle
 */
public final class Utils {

    private Utils() {
    }

    public static void deleteDirectory(File path) {
        if (path.exists()) {
            File[] files = path.listFiles();
            if (files != null) {
                for (File f : files) {
                    if (f.isDirectory()) {
                        deleteDirectory(f);
                    } else {
                        f.delete();
                    }
                }
            }
            path.delete();
        }
    }

    public static String generateRandomText(String prefix, int len) {
        final SecureRandom rnd = new SecureRandom();
        rnd.setSeed(System.currentTimeMillis());
        byte[] buf = new byte[len * 2];
        char[] text = new char[len];
        int c = 0;
        while (c < text.length) {
            rnd.nextBytes(buf);
            for (byte b : buf) {
                if (b >= 'a' && b <= 'z') {
                    text[c++] = (char) b;
                    if (c >= text.length) {
                        break;
                    }
                }
            }
        }
        return prefix + new String(text);
    }
}
