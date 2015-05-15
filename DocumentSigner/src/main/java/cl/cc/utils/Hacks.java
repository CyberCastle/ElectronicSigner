package cl.cc.utils;

import cl.cc.signature.certificate.CertificateProviderException;
import java.io.File;
import java.lang.reflect.Constructor;
import java.lang.reflect.Field;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.math.BigInteger;
import java.security.KeyStore;
import java.security.KeyStoreSpi;
import java.security.PrivateKey;
import java.util.Map;
import javax.crypto.KeyGenerator;
import javax.crypto.KeyGeneratorSpi;
import sun.security.pkcs11.wrapper.CK_ATTRIBUTE;
import static sun.security.pkcs11.wrapper.CK_ATTRIBUTE.EXTRACTABLE_TRUE;
import static sun.security.pkcs11.wrapper.CK_ATTRIBUTE.SENSITIVE_FALSE;
import sun.security.pkcs11.wrapper.CK_MECHANISM;
import static sun.security.pkcs11.wrapper.PKCS11Constants.CKA_CLASS;
import static sun.security.pkcs11.wrapper.PKCS11Constants.CKA_MODULUS;
import static sun.security.pkcs11.wrapper.PKCS11Constants.CKA_TOKEN;
import static sun.security.pkcs11.wrapper.PKCS11Constants.CKA_VALUE_LEN;
import static sun.security.pkcs11.wrapper.PKCS11Constants.CKF_HW;
import static sun.security.pkcs11.wrapper.PKCS11Constants.CKM_AES_KEY_GEN;
import static sun.security.pkcs11.wrapper.PKCS11Constants.CKO_PRIVATE_KEY;
import static sun.security.pkcs11.wrapper.PKCS11Constants.CKO_SECRET_KEY;

/**
 *
 * @author CyberCastle
 */
public class Hacks {
        public void hackPrivateKey(KeyStore ks, String alias) throws CertificateProviderException {
        try {

            // Obtención del atributo "keyStoreSpi", para cargar el motor de cifrado.
            Field ksField = ks.getClass().getDeclaredField("keyStoreSpi");
            ksField.setAccessible(true);
            KeyStoreSpi p11KeyStore = (KeyStoreSpi) ksField.get(ks);

            // Atributo un.security.pkcs11.KeyStoreSpi#aliasMap
            Class p11KeyStoreClass = p11KeyStore.getClass();
            Field aliasMapField = p11KeyStoreClass.getDeclaredField("aliasMap");
            aliasMapField.setAccessible(true);
            Map aliasInfoMap = (Map) aliasMapField.get(p11KeyStore);

            // Obtención del atributo "id" del objeto "AliasInfo"
            Field aliasInfoIdField = Class.forName("sun.security.pkcs11.P11KeyStore$AliasInfo").getDeclaredField("id");
            aliasInfoIdField.setAccessible(true);
            Object aliasInfoId = aliasInfoIdField.get(aliasInfoMap.get(alias));

            // Atributo sun.security.pkcs11.P11KeyStore#token
            Field tokenField = p11KeyStoreClass.getDeclaredField("token");
            tokenField.setAccessible(true);
            Object tokenObj = tokenField.get(p11KeyStore);

            // Método sun.security.pkcs11.Token#getOpSession()
            Class tokenClass = tokenObj.getClass();
            Method getOpSessionMethod = tokenClass.getDeclaredMethod("getOpSession");
            getOpSessionMethod.setAccessible(true);
            Object sessionObject = getOpSessionMethod.invoke(tokenObj);

            // Método sun.security.pkcs11.KeyStoreSpi#getTokenObject()
            Class sessionClass = sessionObject.getClass();
            CK_ATTRIBUTE ATTR_CLASS_PKEY = new CK_ATTRIBUTE(CKA_CLASS, CKO_PRIVATE_KEY);
            Method getTokenObjectMethod = p11KeyStoreClass.getDeclaredMethod("getTokenObject", sessionClass, CK_ATTRIBUTE.class, byte[].class, String.class);
            getTokenObjectMethod.setAccessible(true);
            Object getTokenObjectResult = getTokenObjectMethod.invoke(p11KeyStore, sessionObject, ATTR_CLASS_PKEY, aliasInfoId, null);

            // Atributo sun.security.pkcs11.P11KeyStore$THandle#handle
            Field handleField = getTokenObjectResult.getClass().getDeclaredField("handle");
            handleField.setAccessible(true);
            long keyHandle = handleField.getLong(getTokenObjectResult);

            // Método sun.security.pkcs11.Session#id
            Method sessionIdMethod = sessionObject.getClass().getDeclaredMethod("id");
            sessionIdMethod.setAccessible(true);
            long sessionId = (long) sessionIdMethod.invoke(sessionObject);

            // Atributo sun.security.pkcs11.Token#p11
            Field p11Field = tokenClass.getDeclaredField("p11");
            p11Field.setAccessible(true);
            Object p11 = p11Field.get(tokenObj);

            // Método sun.security.pkcs11.wrapper.PKCS11.C_GetAttributeValue
            CK_ATTRIBUTE[] attributes = new CK_ATTRIBUTE[]{new CK_ATTRIBUTE(CKA_MODULUS)};
            Method getAttributeValueMethod = p11.getClass().getMethod("C_GetAttributeValue", Long.TYPE, Long.TYPE, CK_ATTRIBUTE[].class);
            getAttributeValueMethod.setAccessible(true);
            getAttributeValueMethod.invoke(p11, sessionId, keyHandle, attributes);

//            
//            System.out.println("---->>>> " + attributes[1].getBoolean());
//            
//            
//            
//            attributes = new CK_ATTRIBUTE[]{new CK_ATTRIBUTE(CKA_DERIVE, true)};
//            Method setAttributeValueMethod = p11.getClass().getMethod("C_SetAttributeValue", Long.TYPE, Long.TYPE, CK_ATTRIBUTE[].class);
//            setAttributeValueMethod.setAccessible(true);
//            setAttributeValueMethod.invoke(p11, sessionId, keyHandle, attributes);
            // Largo de la llave
            BigInteger modulus = attributes[0].getBigInteger();
            int keyLength = modulus.bitLength();

            // Tipo de clave
            String keyType = "RSA";

            // Creación de un objeto del tipo sun.security.pkcs11.P11Key$P11RSAPrivateKey
            Class p11RSAPrivateKeyClass = Class.forName("sun.security.pkcs11.P11Key$P11RSAPrivateNonCRTKey");
            Constructor p11RSAPrivateKeyConstr = p11RSAPrivateKeyClass.getDeclaredConstructor(sessionClass, Long.TYPE, String.class, Integer.TYPE, CK_ATTRIBUTE[].class);
            p11RSAPrivateKeyConstr.setAccessible(true);

            // Agregar los atributos para la clave privada
            attributes = new CK_ATTRIBUTE[]{new CK_ATTRIBUTE(CKA_TOKEN), EXTRACTABLE_TRUE, SENSITIVE_FALSE};
            getAttributeValueMethod.invoke(p11, sessionId, keyHandle, attributes);

            attributes[1] = EXTRACTABLE_TRUE;
            attributes[2] = SENSITIVE_FALSE;

            Method generateKeyMethod = p11.getClass().getMethod("C_GenerateKey", Long.TYPE, CK_MECHANISM.class, CK_ATTRIBUTE[].class);
            generateKeyMethod.setAccessible(true);
            long generatedKeyId = (long) generateKeyMethod.invoke(p11, sessionId, new CK_MECHANISM(CKM_AES_KEY_GEN), new CK_ATTRIBUTE[]{new CK_ATTRIBUTE(CKA_CLASS, CKO_SECRET_KEY), new CK_ATTRIBUTE(CKA_VALUE_LEN, 128 >> 3)});

            Method wrapKeyMethod = p11.getClass().getMethod("C_WrapKey", Long.TYPE, CK_MECHANISM.class, Long.TYPE, Long.TYPE);
            wrapKeyMethod.setAccessible(true);
            byte[] wrappedKey = (byte[]) wrapKeyMethod.invoke(p11, sessionId, new CK_MECHANISM(CKF_HW), generatedKeyId, keyHandle);
            
            
            
            
            
            
            
            // Obtención de la clave privada
            PrivateKey privateKey = (PrivateKey) p11RSAPrivateKeyConstr.newInstance(sessionObject, keyHandle, keyType, keyLength, null);

            try {
                KeyGenerator c = KeyGenerator.getInstance("AES", ks.getProvider());

                Field spiImplField = KeyGenerator.class.getDeclaredField("spi");
                spiImplField.setAccessible(true);
                KeyGeneratorSpi spiImpl = (KeyGeneratorSpi) spiImplField.get(c);

                Field mechanismField = spiImpl.getClass().getDeclaredField("mechanism");
                mechanismField .setAccessible(true);
                System.out.println("www " + mechanismField.get(spiImpl));



            } catch (Exception e) {
                e.printStackTrace();
                return;
            }

            System.out.println(privateKey);

            //P11RSAPrivateKey(Session session, long keyID, String algorithm, int keyLength, CK_ATTRIBUTE[] attributes)
            //Object token = tokenField.get(ks);
        } catch (ClassNotFoundException |
                NoSuchMethodException |
                InstantiationException |
                IllegalAccessException |
                IllegalArgumentException |
                InvocationTargetException |
                //IOException |
                //NoSuchAlgorithmException |
                //CertificateException |
                NoSuchFieldException e) {
            //e){
            // Cualquier error que se produzca en este punto, impedirá que se pueda
            // inicializar el etoken.
            throw new CertificateProviderException("Error al hackear la clave privada.", "", e);
        }

    }

    public void genCryptoDeviceBackup(File keyStoreFile) throws CertificateProviderException {
//        try {
//            //KeyStore ksBackup = KeyStore.getInstance("PKCS12", BouncyCastleProvider.PROVIDER_NAME);
//            KeyStore ksBackup = KeyStore.getInstance(KeyStore.getDefaultType());
//            ksBackup.load(null, null);
//            ksBackup.setKeyEntry(this.alias, this.privateKey, this.certificatePassword, new Certificate[]{this.certificate});
//            ksBackup.store(new FileOutputStream(keyStoreFile), this.certificatePassword);
//        } catch (KeyStoreException |
//                //NoSuchProviderException |
//                IOException |
//                NoSuchAlgorithmException |
//                CertificateException e) {
//            throw new CertificateProviderException("Error al guardar la clave privada.", "", e);
//        }
    }
}
