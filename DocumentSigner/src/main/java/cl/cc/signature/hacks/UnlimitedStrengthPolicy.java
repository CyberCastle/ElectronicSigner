package cl.cc.signature.hacks;

import cl.cc.utils.log.Logger;
import java.lang.reflect.Field;
import java.lang.reflect.Modifier;
import java.security.Permission;
import java.security.PermissionCollection;
import java.security.Provider;
import java.util.IdentityHashMap;
import java.util.Map;

/**
 *
 * @author CyberCastle
 * @Note: Code obtain from here:
 * http://stackoverflow.com/questions/1179672/unlimited-strength-jce-policy-files
 * more help from here:
 * http://zarnekow.blogspot.com/2013/01/java-hacks-changing-final-fields.html
 */
public final class UnlimitedStrengthPolicy {

    private UnlimitedStrengthPolicy() {
    }

    @SuppressWarnings("UseSpecificCatch")
    public static void removeCryptographyRestrictions() {
        if (!isRestrictedCryptography()) {
            Logger.info("Cryptography restrictions removal not needed");
            return;
        }
        try {
            /*
             * Do the following, but with reflection to bypass access checks:
             *
             * JceSecurity.isRestricted = false;
             * JceSecurity.defaultPolicy.perms.clear();
             * JceSecurity.defaultPolicy.add(CryptoAllPermission.INSTANCE);
             */
            final Class<?> jceSecurity = Class.forName("javax.crypto.JceSecurity");
            final Class<?> cryptoPermissions = Class.forName("javax.crypto.CryptoPermissions");
            final Class<?> cryptoAllPermission = Class.forName("javax.crypto.CryptoAllPermission");

            final Field isRestrictedField = jceSecurity.getDeclaredField("isRestricted");
            isRestrictedField.setAccessible(true);
            isRestrictedField.set(null, false);

            final Field defaultPolicyField = jceSecurity.getDeclaredField("defaultPolicy");
            defaultPolicyField.setAccessible(true);
            final PermissionCollection defaultPolicy = (PermissionCollection) defaultPolicyField.get(null);

            final Field perms = cryptoPermissions.getDeclaredField("perms");
            perms.setAccessible(true);
            ((Map<?, ?>) perms.get(defaultPolicy)).clear();

            final Field instance = cryptoAllPermission.getDeclaredField("INSTANCE");
            instance.setAccessible(true);
            defaultPolicy.add((Permission) instance.get(null));
            Logger.info("Successfully removed cryptography restrictions");
        } catch (final Exception e) {
            Logger.error("Failed to remove cryptography restrictions");
        }
    }

    @SuppressWarnings("UseSpecificCatch")
    public synchronized static void registerUntrustedProvider() {
        if (!isRestrictedCryptography()) {
            Logger.info("Register untrusted provider not needed");
            return;
        }
        try {
            /*
             * Do the following, but with reflection JceSecurity.getVerificationResult
             * method always return Boolean.TRUE.           
             * Now any untrusted provider can be used.
             */
            final Class<?> jceSecurity = Class.forName("javax.crypto.JceSecurity");
            final Field verificationResults = jceSecurity.getDeclaredField("verificationResults");
            makeModifiable(verificationResults);
            // Oracle Fuck!!!!!!!
            verificationResults.set(null, new HackMap());

            Logger.info("Successfully registered untrusted provider");
        } catch (final Exception e) {
            Logger.error("Failed to register untrusted provider", e);
        }
    }

    public static boolean isRestrictedCryptography() {
        // This simply matches the Oracle JRE, but not OpenJDK.
        return "Java(TM) SE Runtime Environment".equals(System.getProperty("java.runtime.name"));
    }

    /**
     * Force the field to be modifiable and accessible.
     */
    private static void makeModifiable(Field nameField) throws Exception {
        nameField.setAccessible(true);
        int modifiers = nameField.getModifiers();
        Field modifierField = nameField.getClass().getDeclaredField("modifiers");
        modifiers = modifiers & ~Modifier.FINAL;
        modifierField.setAccessible(true);
        modifierField.setInt(nameField, modifiers);
    }

    /**
     * Here's the magic!!!!, always return true...
     */
    private static class HackMap extends IdentityHashMap<Provider, Object> {

        private static final long serialVersionUID = -4691209441761652202L;

        @Override
        public Object get(Object key) {
            return Boolean.TRUE;
        }
    }
}
