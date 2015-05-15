package cl.cc.signature.certificate;

import cl.cc.signature.hacks.UnlimitedStrengthPolicy;
import cl.cc.signature.cryptodevice.CryptoDeviceConfig;
import cl.cc.utils.log.Logger;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.lang.reflect.Constructor;
import java.lang.reflect.Field;
import java.lang.reflect.InvocationTargetException;
import java.security.AuthProvider;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.ProviderException;
import java.security.Security;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Enumeration;
import java.util.LinkedHashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Objects;
import javax.crypto.BadPaddingException;
import javax.security.auth.login.FailedLoginException;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

/**
 *
 * @author CyberCastle
 */
public class CertificateProvider {

    // Pequeños hacks para anular las imposiciones de Oracle.
    static {
        // Eliminamos las restricciones en el uso de funciones criptográficas.
        UnlimitedStrengthPolicy.removeCryptographyRestrictions();
        // Permitimos el uso de proveedores de seguridad, aunque estos no
        // estén firmados digitalmente.
        UnlimitedStrengthPolicy.registerUntrustedProvider();

        // Usaremos BouncyCastle como proveedor
        Security.addProvider(new BouncyCastleProvider());
    }

    public static final Integer ADVANCED_SIGNATURE = 0;
    public static final Integer SIGNATURE_WITH_LOCAL_CERTIFICATE = 1;
    public static final Integer SIGNATURE_WITH_INSTALLED_CERTIFICATE = 2;
    private static String CRYPTODEVICE_NAME_PREFIX = "SunPKCS11-";
    private Character verifierDigit = ' ';
    private char[] certificatePassword;
    private X509Certificate certificate;
    private PrivateKey privateKey;
    private String userName;
    private String alias;
    private String userID = "";
    private KeyStore ks = null;
    private String providerName;
    private Boolean advancedSignaure = false;
    private final LinkedHashMap<String, X509Certificate> certificatesList;

    public CertificateProvider() {
        this.certificatesList = new LinkedHashMap<>();
    }

    public CertificateProvider(char[] password) {
        this();
        this.certificatePassword = password;
    }

    public void setCertificatePassword(char[] password) {
        this.certificatePassword = password;
    }

    public boolean checkTokenUser(String usr) {
        return this.userName.equals(usr);
    }

    public boolean isAdvancedSignaure() {
        return this.advancedSignaure;
    }

    public PrivateKey getPrivateKey() {
        return this.privateKey;
    }

    public X509Certificate getCertificate() {
        return this.certificate;
    }

    public KeyStore getKeyStore() {
        return this.ks;
    }

    public String getAlias() {
        return this.alias;
    }

    public String getUserName() {
        return this.userName;
    }

    public String getProviderName() {
        return this.providerName;
    }

    public Integer countCertificates() {
        return this.certificatesList.size();
    }

    public List<String> getAliasList() {
        return new LinkedList<>(this.certificatesList.keySet());
    }

    public void selectCertificateByAlias(String alias) throws CertificateProviderException {
        this.alias = alias;
        this.certificate = this.certificatesList.get(this.alias);
        this.obtainCertificateData();
    }

    public void selectCertificate(Integer number) throws CertificateProviderException {
        this.alias = (String) this.certificatesList.keySet().toArray()[number];
        this.certificate = this.certificatesList.get(this.alias);
        this.obtainCertificateData();
    }

    public String getUserID() {
        if (!this.userID.equals("")) {
            return this.userID + "-" + this.verifierDigit;
        }
        return "";
    }

    public void setSignatureType(Integer type, String CertificatePath) throws CertificateProviderException {
        if (Objects.equals(type, CertificateProvider.SIGNATURE_WITH_LOCAL_CERTIFICATE)) {
            this.localCertificateSelectToSign(CertificatePath);
        } else if (Objects.equals(type, CertificateProvider.SIGNATURE_WITH_INSTALLED_CERTIFICATE)) {
            this.installedCertificateSelectToSign();
        } else if (Objects.equals(type, CertificateProvider.ADVANCED_SIGNATURE)) {
            this.cryptoDeviceSelectToSign();
        } else {
            throw new CertificateProviderException("Signature type not supported.", "");
        }
    }

    public boolean checkCryptoDevice() throws CertificateProviderException {
        return this.initCryptoDevice(true) != null;
    }

    public void close() throws CertificateProviderException {

        // Nos deslogueamos del almacén de certificados.
        AuthProvider p = (AuthProvider) this.ks.getProvider();
        try {
            p.logout();
        } catch (Exception e) {
            // Si hay un error, lo capturamos silenciosamente.
            Logger.warn("Error al cerrrar la sesión del almacén de certificados.", e);
        }

        // Cerramos el almacén de certificados y lo removemos de la lista de proveedores.
        this.ks = null;
        this.providerName = null;
        try {
            if (this.advancedSignaure) {
                Security.removeProvider(this.providerName);
            }
        } catch (Exception e) {
            Logger.warn("Error al cerrar el almacén de certificados.", e);
        }
    }

    @SuppressWarnings("ThrowableResultIgnored")
    private void localCertificateSelectToSign(String CertificatePath) throws CertificateProviderException {
        this.advancedSignaure = false;
        try {
            this.ks = KeyStore.getInstance("PKCS12", BouncyCastleProvider.PROVIDER_NAME);
            this.providerName = BouncyCastleProvider.PROVIDER_NAME;
        } catch (KeyStoreException | NoSuchProviderException e) {
            throw new CertificateProviderException("Internal Error.", "", e);
        }
        FileInputStream fis = null;
        try {
            fis = new FileInputStream(CertificatePath);
        } catch (FileNotFoundException e) {
            throw new CertificateProviderException("El certificado es Inaccesible.", "", e);
        }
        try {
            this.ks.load(fis, this.certificatePassword);
        } catch (NoSuchAlgorithmException | CertificateException e) {
            throw new CertificateProviderException("El certificado es Inválido.", "", e);
        } catch (IOException e) {
            if (e.getCause() instanceof BadPaddingException) {
                throw new CertificateProviderException("Contraseña Incorrecta.", "", e);
            } else {
                throw new CertificateProviderException("El certificado es Inválido.", "", e);
            }
        }
        this.obtainCertificatesList();
    }

    private void installedCertificateSelectToSign() throws CertificateProviderException {
        this.advancedSignaure = false;
        String os = System.getProperty("os.name").toLowerCase();
        try {
            if (os.contains("windows")) {
                this.ks = KeyStore.getInstance("Windows-MY", "SunMSCAPI");
            } else if (os.contains("mac os x")) {
                this.ks = KeyStore.getInstance("Keychainstore", "Apple");
            } else {
                throw new CertificateProviderException("Sistema operativo no soportado", "");
            }
        } catch (KeyStoreException | NoSuchProviderException e) {
            throw new CertificateProviderException("Internal Error.", "", e);
        }
        try {
            this.ks.load(null, null);
        } catch (NoSuchAlgorithmException | CertificateException | IOException e) {
            throw new CertificateProviderException("No es posible acceder al contedor de certificados.", "", e);
        }
        this.obtainCertificatesList();
    }

    @SuppressWarnings("ThrowableResultIgnored")
    private void cryptoDeviceSelectToSign() throws CertificateProviderException {
        this.advancedSignaure = true;
        this.ks = this.initCryptoDevice(false);

        /*
         * Initializing instance of dispositivo criptográfico
         */
        try {
            this.ks.load(null, this.certificatePassword); // Loading instance of dispositivo criptográfico
        } catch (NoSuchAlgorithmException e) {
            throw new CertificateProviderException("Contraseña Incorrecta", "", e);
        } catch (CertificateException e) {
            throw new CertificateProviderException("Error al acceder al dispositivo criptográfico", "", e);
        } catch (IOException e) {
            if (e.getCause() instanceof FailedLoginException) {
                throw new CertificateProviderException("Contraseña Incorrecta", "", e);
            } else {
                throw new CertificateProviderException("Error al acceder al dispositivo criptográfico.", "", e);
            }
        }
        Logger.info("Cryptographic Device Initialized.");
        this.obtainCertificatesList();
    }

    private KeyStore initCryptoDevice(boolean OnlyCheck) throws CertificateProviderException {
        Logger.debug("Searching Cryptographic Device Driver...");
        KeyStore KSResult = null;
        CryptoDeviceConfig cryptoDevCfg = new CryptoDeviceConfig();

        // TODO: hacer alguna maravilla de código que detecte el dispositivo criptográfico
        // Por defecto dejaremos seteado el Aladdin eToken
        cryptoDevCfg.setCryptoDeviceName("eToken");

        this.providerName = CRYPTODEVICE_NAME_PREFIX + cryptoDevCfg.getCryptoDeviceName();
        Security.removeProvider(this.providerName);
        Provider p = Security.getProvider(this.providerName);
        if (p == null) {
            try {
                p = this.createSunPKCS11Provider(cryptoDevCfg);
                Logger.debug("Cryptographic Device Driver Installed");
                Security.addProvider(p);
            } catch (ProviderException e) {
                throw new CertificateProviderException("El Controlador del dispositivo criptográfico no está Instalado.", "", e);
            }
        }

        try {
            KSResult = KeyStore.getInstance("PKCS11", p);
            Logger.debug("Key Store Info: " + KSResult.getType());
        } catch (KeyStoreException e) {
            throw new CertificateProviderException("No se encuentra el dispositivo criptográfico.", "", e);
        }
        Logger.debug("Cryptographic Device Found");
        if (OnlyCheck) {
            Security.removeProvider(p.getName());
            return null;
        }
        return KSResult;
    }

    private void obtainCertificatesList() throws CertificateProviderException {
        try {
            //Obtaining certificate alias list
            Enumeration Enum = this.ks.aliases();
            while (Enum.hasMoreElements()) {
                String _alias = String.valueOf(Enum.nextElement());
                if (_alias == null || !this.ks.isKeyEntry(_alias)) {
                    Logger.warn("ERROR: No existe certificado y/o llave privada");
                } else {
                    Certificate[] _certificatesList = this.ks.getCertificateChain(_alias);

                    // Bajo este alias aparecen todos los certificados, incluyendo
                    // los certificados raíces e intermedios de la Autoridad Certificadora
                    for (Certificate _certificate : _certificatesList) {
                        if (_certificate == null) {
                            Logger.warn("ERROR: Certificado X509 no encontrado.");
                        } else {

                            // Debemos sólo identificar el certificado del usuario
                            // ignorando los de la Autoridad Certificadora.
                            X509Certificate _x509certificate = (X509Certificate) _certificate;
                            boolean[] keyUsage = _x509certificate.getKeyUsage();
                            // Original idea: http://stackoverflow.com/a/28484184
                            if (keyUsage != null && !keyUsage[5]) {
                                // User certificate
                                this.certificatesList.put(_alias, _x509certificate);
                            }
                        }
                    }
                }
            }
            if (this.certificatesList.isEmpty()) {
                throw new CertificateProviderException("Certificado X509 no encontrado", "");
            }
        } catch (KeyStoreException e) {
            throw new CertificateProviderException("Error al extraer el certificado", "", e);
        }
    }

    private void obtainCertificateData() throws CertificateProviderException {
        try {
            this.privateKey = (PrivateKey) this.ks.getKey(this.alias, this.certificatePassword);
        } catch (KeyStoreException | NoSuchAlgorithmException | UnrecoverableKeyException e) {
            throw new CertificateProviderException("El certificado es Inválido.", "", e);
        }

        //Extract User names
        String _userName = this.certificate.getSubjectDN().getName();
        int posElem = _userName.toUpperCase().indexOf("CN=");
        if (posElem >= 0) {
            String rigthTkn = _userName.substring((posElem + 3), _userName.length());
            int posComma = rigthTkn.indexOf(",");
            if (posComma >= 0) {
                String leftTkn = rigthTkn.substring(0, posComma);
                this.userName = leftTkn;
            } else {
                this.userName = rigthTkn;
            }
        } else {
            this.userName = _userName;
        }
        this.obtainUserID();
    }

    private void obtainUserID() {
        String codExtValue = "2.5.29.17";  // Rut del dueño del certificado.
        //String codExtValue="2.5.29.18";  // Rut de la Entidad Certificadora que emitio el certificado.

        byte[] str = this.certificate.getExtensionValue(codExtValue);
        if (str != null) {
            String userid = this.getPrintableString(str);
            String auxid = userid.substring(20, Math.min(32, userid.length()));
            StringBuilder id = new StringBuilder();
            int i = 0;
            for (; i < auxid.length(); i++) {  // Extrae los numeros del Rut sin el digito verificador.
                char caracter = auxid.charAt(i);
                if (Character.isDigit(caracter)) {
                    id.append(caracter);
                } else {
                    break;  // Se detiene al encontrar caracter inválido.
                }
            }
            this.userID = id.toString();
            this.verifierDigit = auxid.charAt(i + 1);
        }
    }

    private String getPrintableString(byte[] str) {
        char[] cs = new char[str.length];
        for (int i = 0; i < str.length; i++) {
            cs[i] = (char) (str[i] & 0xff);
        }
        return new String(cs);
    }

    @SuppressWarnings({"unchecked"})
    private Provider createSunPKCS11Provider(CryptoDeviceConfig cryptoDevCfg) throws CertificateProviderException {
        try {
            // Por reflexión instanciaremos un el objeto que representará al dispositivo
            // criptográfico.
            Class sunPkcs11Class = Class.forName("sun.security.pkcs11.SunPKCS11");
            Constructor pkcs11Constr = sunPkcs11Class.getConstructor(InputStream.class);
            Provider p = (Provider) pkcs11Constr.newInstance(cryptoDevCfg.getCryptoDeviceConfigStream());

            // PKCS#11 token           
            final Field tokenField = sunPkcs11Class.getDeclaredField("token");
            tokenField.setAccessible(true);

            // Obtenemos algunas características del dispositivo
            // para hacer un diganóstico en caso de error durante su inicialización
            Object token = tokenField.get(p);

            // Detectamos que se haya accedido correctamente al token. 
            // TODO: Hay que dejar más bonito este código, que la búsqueda por slot sea dinámica.
            // Para esta versión dejaremos que busque en el slot 2 (dispositivo Rainbow -SafeNet- iKey).
            if (token == null) {
                Logger.warn("No hay dispositivo en el slot 0, intentando en el slot 2.");
                cryptoDevCfg.setSlot(2);

                // Intentamos nuevamente obtener acceso al dispositivo
                p = (Provider) pkcs11Constr.newInstance(cryptoDevCfg.getCryptoDeviceConfigStream());
                token = tokenField.get(p);
                if (token == null) {
                    // No hay caso, abortamos misión.
                    throw new CertificateProviderException("No se ha podido acceder al dispositivo criptográfico.", "");
                }
            }

            // Valid property
            final Field validField = token.getClass().getDeclaredField("valid");
            validField.setAccessible(true);
            Logger.debug("¿Token válido?: " + validField.get(token).toString());

            // Removable property
            final Field removableField = token.getClass().getDeclaredField("removable");
            removableField.setAccessible(true);
            Logger.debug("¿Dispositivo removible?: " + removableField.get(token).toString());

            // WriteProtected property
            final Field writeProtectedField = token.getClass().getDeclaredField("writeProtected");
            writeProtectedField.setAccessible(true);
            Logger.debug("¿Protegido contra escritura?: " + writeProtectedField.get(token).toString());

            return p;

        } catch (ClassNotFoundException |
                NoSuchMethodException |
                InstantiationException |
                IllegalAccessException |
                IllegalArgumentException |
                InvocationTargetException |
                IOException |
                NoSuchFieldException e) {
            // Cualquier error que se produzca en este punto, impedirá que se pueda
            // inicializar el etoken.
            throw new CertificateProviderException("Error al instanciar el dispositivo criptográfico.", "", e);
        }
    }
}
