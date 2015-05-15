package cl.cc.signature.validation.certificate;

import cl.cc.utils.Utils;
import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.MalformedURLException;
import java.net.URL;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PublicKey;
import java.security.SignatureException;
import java.security.cert.CRLException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateFactory;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.DERIA5String;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.x509.CRLDistPoint;
import org.bouncycastle.asn1.x509.DistributionPoint;
import org.bouncycastle.asn1.x509.DistributionPointName;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;

/**
 *
 * @author CyberCastle
 */
public final class CertificateValidator {

    private static final String CRLFileName = "_List.crl";
    private boolean[] keyUsages;
    private X509Certificate Certificate;
    private String tmpFolderPath;
    private File tmpFolder;

    private Date validationDate;
    private Boolean clrCacheEnabled;

    public CertificateValidator() {
        this.clrCacheEnabled = true;
    }

    public CertificateValidator(X509Certificate Certificate) {
        this();
        this.setCertificate(Certificate);
    }

    public void setCertificate(X509Certificate Certificate) {
        this.Certificate = Certificate;
        this.keyUsages = this.Certificate.getKeyUsage();
    }

    public void setCLRCacheEnabled(Boolean clrCacheEnabled) {
        this.clrCacheEnabled = clrCacheEnabled;
    }

    public void setTmpFolderPath(String tmpFolderPath) {
        this.tmpFolderPath = tmpFolderPath;
    }

    public void setValidationDate(Date validationDate) {
        this.validationDate = validationDate;
    }

    //Verify that the certificate is valid
    public Boolean isValid() throws CertificateValidatorException {
        try {
            this.Certificate.checkValidity(this.validationDate);
            return true;
        } catch (CertificateExpiredException e) {
            //this.Message = "El Certificado ha expirado";
        } catch (CertificateNotYetValidException e) {
            throw new CertificateValidatorException("El Certificado no es válido", "", e);
        }
        return false;
    }

    //Verify that the certificate has been issued for Digital Signature
    public Boolean isForDigitalSignature() {
        // El certificado ha sido emitido para firmar documentos
        return this.keyUsages != null && this.keyUsages[0];
    }

    //Verify that the certificate has been issued for Digital Signature
    public Boolean isForNonRepudiation() {
        return this.keyUsages != null && this.keyUsages[1];
    }

    //Checks whether given X.509 certificate is self-signed.
    public Boolean isSelfSigned() throws CertificateException, NoSuchAlgorithmException, NoSuchProviderException {
        try {
            // Try to verify certificate signature with its own public key
            PublicKey key = this.Certificate.getPublicKey();
            this.Certificate.verify(key);
            return true;
        } catch (SignatureException | InvalidKeyException sigEx) {
            // Invalid signature --> not self-signed
            return false;
        }
    }

    /**
     * Extracts all CRL distribution point URLs from the "CRL Distribution
     * Point" extension in a X.509 certificate. If CRL distribution point
     * extension is unavailable, returns an empty list.
     */
    private List<String> getCrlDistributionPoints() throws CertificateParsingException, IOException {

        byte[] crldpExt = this.Certificate.getExtensionValue(Extension.cRLDistributionPoints.getId());
        if (crldpExt == null) {
            return new ArrayList<>();
        }

        ASN1InputStream oAsnInStream = new ASN1InputStream(new ByteArrayInputStream(crldpExt));
        DEROctetString dosCrlDP = (DEROctetString) oAsnInStream.readObject();
        byte[] crldpExtOctets = dosCrlDP.getOctets();
        ASN1InputStream oAsnInStream2 = new ASN1InputStream(new ByteArrayInputStream(crldpExtOctets));

        CRLDistPoint distPoint = CRLDistPoint.getInstance(oAsnInStream2.readObject());
        List<String> crlUrls = new ArrayList<>();
        for (DistributionPoint dp : distPoint.getDistributionPoints()) {
            DistributionPointName dpn = dp.getDistributionPoint();
            // Look for URIs in fullName
            if (dpn != null && dpn.getType() == DistributionPointName.FULL_NAME) {
                GeneralName[] genNames = GeneralNames.getInstance(dpn.getName()).getNames();
                for (GeneralName genName : genNames) {
                    if (genName.getTagNo() == GeneralName.uniformResourceIdentifier) {
                        String url = DERIA5String.getInstance(genName.getName()).getString();
                        crlUrls.add(url);
                    }
                }
            }
        }
        return crlUrls;
    }

    public Boolean isOnOSCP() throws CertificateValidatorException {
        //TODO: Implementar validación por OSCP
        return false;
    }

    //Verify that the certificate is not present in a CRL
    public Boolean isOnCRL() throws CertificateValidatorException {
        try {
            // Creamos la carpeta temporal
            this.makeTempFolder();
            // Obtenemos la lista de direcciones para descargar la lista de revocación
            List<String> crlDistributionPoints = this.getCrlDistributionPoints();

            // No hay lista de direcciones
            if (crlDistributionPoints.isEmpty()) {
                throw new CertificateValidatorException("El certificado no cuenta con la información necesaria para obtener la Lista de Certificados Revocados", "");
            }

            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            for (Integer count = 0; count < crlDistributionPoints.size(); count++) {
                String crlDistributionPoint = crlDistributionPoints.get(count);
                String crlPath = this.tmpFolderPath + this.getIssuerName() + count + CRLFileName;
                X509CRL crl = this.returnCachedCRL(crlDistributionPoint, crlPath, cf);
                if (crl.isRevoked(this.Certificate)) {
                    return true;
                }
            }

            // El cache no está habilitado, por lo que borramos la carpeta temporal
            if (!this.clrCacheEnabled) {
                Utils.deleteDirectory(this.tmpFolder);
            }
            return false;
        } catch (CertificateParsingException e) {
            throw new CertificateValidatorException("", "", e);
        } catch (IOException | CRLException | CertificateException e) {
            throw new CertificateValidatorException("", "", e);
        }
    }

    //Extrae el nombre del emisor del certificado
    private String getIssuerName() {
        String IssuerName = this.Certificate.getIssuerDN().getName();
        if (IssuerName == null) {
            return null;
        }
        int posElem = IssuerName.toUpperCase().indexOf("@");
        if (posElem >= 0) {
            String rigthTkn = IssuerName.substring((posElem + 1), IssuerName.length());
            int posComma = rigthTkn.indexOf(",");
            if (posComma >= 0) {
                String leftTkn = rigthTkn.substring(0, posComma);
                return leftTkn;
            } else {
                return rigthTkn;
            }
        }
        return IssuerName;
    }

    // Método para mantener un cache actualizado con las listas de revocación, si es que está habilitado
    private X509CRL returnCachedCRL(String location, String cachedCRLPath, CertificateFactory cf) throws CRLException, IOException {
        X509CRL crl = null;
        File crlFile = new File(cachedCRLPath);
        Boolean downloadCLR = true;
        if (crlFile.exists() && this.clrCacheEnabled) {
            // Cuando la lista existe, no la descarga
            FileInputStream crlStream = new FileInputStream(cachedCRLPath);
            crl = (X509CRL) cf.generateCRL(crlStream);
            // Y validamos que no esté vencida
            if (crl.getNextUpdate().before(this.validationDate)) {
                // Lista vencida
                crl = null;
                crlStream.close();
                crlFile.delete();
            } else {
                // Lista vigente, no se descarga
                downloadCLR = false;
            }
        }

        // ¿Hay que descargar la Lista?
        if (downloadCLR) {
            // Descargamos la lista
            this.saveUrlToFile(crlFile, location);
            try (FileInputStream crlStream = new FileInputStream(cachedCRLPath)) {
                crl = (X509CRL) cf.generateCRL(crlStream);
            }
        }

        return crl;
    }

    // Método para descargar un archivo a disco
    private void saveUrlToFile(File saveFile, String location) throws MalformedURLException, IOException {
        URL url = new URL(location);
        OutputStream out;
        try (InputStream in = url.openStream()) {
            out = new FileOutputStream(saveFile);
            byte[] buffer = new byte[1024];
            int length;
            while ((length = in.read(buffer)) > 0) {
                out.write(buffer, 0, length);
            }
        }
        out.close();
    }

    private void makeTempFolder() {
        if (this.tmpFolderPath == null) {
            this.tmpFolderPath = System.getProperty("java.io.tmpdir");
            if (!this.tmpFolderPath.endsWith(File.separator)) { //Fix for Linux
                this.tmpFolderPath += File.separator;
            }
            this.tmpFolderPath += "CRLTempDir" + File.separator;
        }

        this.tmpFolder = new File(this.tmpFolderPath);
        if (!tmpFolder.exists()) {
            this.tmpFolder.mkdir();
        }
    }
}
//OCSP url oid: 1.3.6.1.5.5.7.1.1
/*KeyUsage ::= BIT STRING {
 digitalSignature        (0),
 nonRepudiation          (1),
 keyEncipherment         (2),
 dataEncipherment        (3),
 keyAgreement            (4),
 keyCertSign             (5),
 cRLSign                 (6),
 encipherOnly            (7),
 decipherOnly            (8) }
 */
