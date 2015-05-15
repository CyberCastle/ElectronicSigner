package cl.cc.gui;

import cl.cc.signature.date.DateProvider;
import cl.cc.signature.date.DateProviderException;
import cl.cc.config.ConfigHandler;
import cl.cc.connection.http.HttpDownloadUtility;
import cl.cc.connection.http.HttpUploadUtility;
import cl.cc.signature.certificate.CertificateProvider;
import cl.cc.signature.certificate.CertificateProviderException;
import cl.cc.signature.sign.SignDocument;
import cl.cc.signature.sign.SignDocumentException;
import cl.cc.signature.sign.SignPDF;
import cl.cc.signature.sign.SignXML;
import cl.cc.signature.validation.certificate.CertificateValidator;
import cl.cc.signature.validation.certificate.CertificateValidatorException;
import cl.cc.utils.Utils;
import cl.cc.utils.log.Logger;
import java.io.File;
import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Calendar;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 *
 * @author CyberCastle
 */
public class SignEngine {

    public final static String DEFAULT_ALIAS = "default";
    public final static String DEFAULT_SERVICE = "default";
    private Boolean enableSignerList;
    private final Map<String, Exception> documentSignResult;
    private CertificateProvider certPvr;
    private String certificatePath;
    private String signerName;
    private String signerId;
    private Calendar signatureDate;
    private String serviceName;
    private String urlBase;
    private File tmpFolder;

    public SignEngine() {
        this.documentSignResult = new LinkedHashMap<>();
        this.enableSignerList = false;
        this.serviceName = DEFAULT_SERVICE;
    }

    // Define el sevicio al que pertenece el documento.
    public void setServiceName(String serviceName) {
        this.serviceName = serviceName;
    }

    public void setUrlBase(String urlBase) {
        this.urlBase = urlBase;
    }

    public void setCertificatePath(String certificatePath) {
        this.certificatePath = certificatePath;
    }

    // Permite habilitar la lista de firmantes.
    public void enableSignerList(Boolean enableSignerList) {
        this.enableSignerList = enableSignerList;
    }

    public Map<String, Exception> getDocumentSignResult() {
        return documentSignResult;
    }

    // Descarga al disco local los archivos selecionados para firmar.
    @SuppressWarnings("ThrowableResultIgnored")
    public Map<String, File> downloadFiles(Set<String> documentIds) throws SignEngineException {
        String url = this.urlBase + ConfigHandler.getProperty("url.base.download.files");
        Map<String, File> fileList = new LinkedHashMap<>();
        for (String documentId : documentIds) {
            try {
                documentId = documentId.trim();
                // Seteamos el ID del documento
                String _url = url.replace("#{idFile}", documentId);
                // Seteamos el nombre del servicio
                _url = _url.replace("#{serviceName}", this.serviceName);
                String fileName = HttpDownloadUtility.downloadFile(_url, this.tmpFolder.getAbsolutePath());
                File f = new File(this.tmpFolder.getAbsolutePath() + File.separator + fileName);
                fileList.put(documentId, f);
            } catch (IOException e) {
                // Se registra el error.
                this.documentSignResult.put(documentId, e);
                // Hay un error, por lo que abortamos misión.
                throw new SignEngineException(String.format("Error al descargar el documento %s.", documentId), "", e);
            }
        }
        return fileList;
    }

    // Método encargado de subir los archivos al servidor.
    @SuppressWarnings("ThrowableResultIgnored")
    public Map<String, File> uploadFiles(String userName, Map<String, File> fileList) throws SignEngineException {

        String url = this.urlBase + ConfigHandler.getProperty("url.base.upload.files");
        Map<String, File> _fileList = new LinkedHashMap<>();
        for (Map.Entry<String, File> fileEntry : fileList.entrySet()) {
            String documentId = fileEntry.getKey();
            File document = fileEntry.getValue();
            try {
                // El id del documento firmado es parte de la URL.
                String _url = url.replace("#{idFile}", documentId);
                HttpUploadUtility httpUpload = new HttpUploadUtility(_url, "UTF-8");

                // Nombre del firmante.
                httpUpload.addFormField("signerName", this.signerName);
                // Rut del firmante.
                httpUpload.addFormField("signerId", this.signerId);
                // Nombre del usuario.
                httpUpload.addFormField("userName", userName);
                // Nombre del servicio al que pertenece el documento.
                httpUpload.addFormField("serviceName", this.serviceName);
                // Fecha de la firma del documento.
                //TODO: Dar formato a la fecha
                httpUpload.addFormField("signatureDate", this.signatureDate.toString());

                // Archivo a subir.
                httpUpload.addFilePart("signedFile", document);

                // Subimos el archivo y obtenemos la respuesta del servidor.
                List<String> result = httpUpload.finish();

                // Evaluamos la respuesta del server.
                String response = result.get(0);
                if (!response.contains("Without Errors")) {
                    // La respuesta no es la esperada....
                    throw new IOException(response);
                }
                _fileList.put(documentId, document);
            } catch (IOException e) {
                // Se registra el error.
                this.documentSignResult.put(documentId, e);
                // Hay un error, por lo que abortamos misión.
                throw new SignEngineException(String.format("Error al subir el documento %s.", documentId), "", e);
            }
        }
        return _fileList;
    }

    // Se define la carpeta temporal en donde se guardarán los archivos.
    public void setTmpFolder(String tmpFolderPath) {
        this.tmpFolder = new File(tmpFolderPath + File.separator + Utils.generateRandomText("signer", 8));
        this.tmpFolder.mkdir();
    }

    // Método para borrar los archivos temporales creados
    public void deleteTmpFolder() {
        Utils.deleteDirectory(this.tmpFolder);
    }

    // Obtenemos la lista de certificados que tiene el almacén.
    public List<String> getCertificatesList() {
        return this.certPvr.getAliasList();
    }

    public Boolean isExtractable() {
        String pkFormat = this.certPvr.getPrivateKey().getFormat();
        Logger.debug("Formato clave privada: " + pkFormat);
        return !(pkFormat == null);
    }

    // Método encargado de firmar los documentos.
    @SuppressWarnings("ThrowableResultIgnored")
    public Map<String, File> signDocuments(String aliasCertificate, Map<String, File> fileList) throws SignEngineException {
        Map<String, File> _fileList = new LinkedHashMap<>();
        try {
            // Selección del certificado a utilizar.
            if (aliasCertificate.equals(DEFAULT_ALIAS)) {
                this.certPvr.selectCertificate(0);
            } else {
                this.certPvr.selectCertificateByAlias(aliasCertificate);
            }

            // Establecemos la fecha en el que el documento será firmado
            this.signatureDate = DateProvider.getNowCalendar();

            // Validación del certificado, antes de firmar.
            if (!this.validateCertificate(this.certPvr.getCertificate())) {
                throw new SignEngineException("Certificado inválido.", "");
            }

            // Obtenemos el nombre y el rut del firmante
            this.signerName = this.certPvr.getUserName();
            this.signerId = this.certPvr.getUserID();

            Logger.debug("Nombre Firmante: " + this.signerName);
            Logger.debug("Rut Firmante: " + this.signerId);

            // Firmado de Documentos.
            for (Map.Entry<String, File> fileEntry : fileList.entrySet()) {
                String documentId = fileEntry.getKey();
                File documentToSign = fileEntry.getValue();
                String fileExtension = this.getFileExtension(documentToSign);
                SignDocument signer = this.obtainSignerByFileExtension(fileExtension);
                signer.setCertificateProvider(this.certPvr);
                signer.setSignerList(this.enableSignerList);
                signer.setSignDate(signatureDate);

                // Se crea una referencia al que será el documento firmado.
                File documentSigned = this.getCopyFileReference(documentToSign, "signed");
                signer.setDocuments(documentToSign, documentSigned);
                try {
                    // Se firma el documento.
                    signer.sign();
                    _fileList.put(documentId, documentSigned);
                } catch (SignDocumentException e) {
                    // Registramos el error.
                    this.documentSignResult.put(documentId, e);
                    // Hay un error, por lo que abortamos misión y evitamos que se pueda subir documentos.
                    throw new SignEngineException(String.format("Error al firmar el documento %s.", documentId), "", e);
                }
            }
        } catch (CertificateProviderException e) {
            throw new SignEngineException("Error al acceder al certificado.", "", e);
        } catch (DateProviderException e) {
            throw new SignEngineException("No es posible fijar la decha de firmado.", "", e);
        }
        return _fileList;
    }

    // Cargamos el almacén de certificados. Si neceitamos recargar, llamamos a este método nuevamente.
    public void openKeyStore(Integer signType, String password) throws SignEngineException {
        // Cerramos antes el almacén de certificados, para cuando queramos recargarlo.
        this.closeKeyStore();

        try {
            // Configuración del almacén de certificados y tipo de firma.
            this.certPvr = new CertificateProvider(password.toCharArray());
            this.certPvr.setSignatureType(signType, this.certificatePath);
        } catch (CertificateProviderException e) {
            throw new SignEngineException("Error al acceder al certificado.", "", e);
        }
    }

    // Cierre del almacén de certificados.
    public void closeKeyStore() {
        if (this.certPvr != null) {
            try {
                this.certPvr.close();
            } catch (CertificateProviderException e) {
                // Ignoramos el error del almacén de certificados.
            }
        }
    }

    public boolean checkCryptoDevice() throws SignEngineException {
        try {
            return this.certPvr.checkCryptoDevice();
        } catch (CertificateProviderException e) {
            throw new SignEngineException("Error al acceder al Dispositivo Criptográfico", "", e);
        }
    }

    // Método para validar el certificado.
    private Boolean validateCertificate(X509Certificate certificate) throws SignEngineException {
        try {
            // Se validará el certificado sólo si está habilitada la opción.
            if (!ConfigHandler.getProperty("validation.certificate.before.sign").equals("yes")) {
                return true;
            }

            // Hay que ser optimista.... por defecto el certificado es válido.
            Boolean result = true;
            CertificateValidator validator = new CertificateValidator(certificate);

            // Hay que validar que al momento de firmar, el certificado esté vigente
            validator.setValidationDate(this.signatureDate.getTime());

            // Siempre validaremos que el certificado sea válido.
            result = result && validator.isValid();
            // Y que sea para firma electrónica.
            result = result && validator.isForDigitalSignature();

            // Si está habilitada la opción, validaremos que el certificado no sea auto firmado.
            if (ConfigHandler.getProperty("validation.certificate.selfsign.enabled").equals("yes")) {
                result = result && !validator.isSelfSigned();
            }

            // Si está habilitada la opción, validaremos el certificado contra una lista de revocación
            if (ConfigHandler.getProperty("validation.certificate.crl.enabled").equals("yes")) {
                result = result && !validator.isOnCRL();
            }

            // Si está habilitada la opción, validaremos el certificado contra un OSCP
            if (ConfigHandler.getProperty("validation.certificate.ocsp.enabled").equals("yes")) {
                result = result && !validator.isOnOSCP();
            }

            return result;
        } catch (CertificateValidatorException | CertificateException | NoSuchAlgorithmException | NoSuchProviderException e) {
            throw new SignEngineException("Error al validar el certificado", "", e);
        }
    }

    // Crea una referencia (sólo nombre y ruta) en base a un archivo existente, al que se le añade un sufijo.
    // La carpeta en donde se almacenará este será la misma en donde se encuentra el archivo de origen.
    private File getCopyFileReference(File origin, String sufix) {
        String fileExtension = this.getFileExtension(origin);
        // Usaremos la misma carpeta en donde se encuentra el archivo origen, por eso
        // obtenemos su ruta absoluta.
        String fileWithoutExtension = origin.getAbsolutePath().replace("." + fileExtension, "");
        String copyFileName = fileWithoutExtension + "-" + sufix + "." + fileExtension;
        return new File(copyFileName);
    }

    // Obtiene la extensión de un archivo.
    // @source: http://stackoverflow.com/questions/3571223/how-do-i-get-the-file-extension-of-a-file-in-java
    private String getFileExtension(File f) {
        String extension = "";
        String fileName = f.getName();
        int i = fileName.lastIndexOf('.');
        int p = Math.max(fileName.lastIndexOf('/'), fileName.lastIndexOf('\\'));
        if (i > p) {
            extension = fileName.substring(i + 1);
        }
        return extension;
    }

    // Dependiendo de la extensión del documento a firmar, generamos el objeto.
    private SignDocument obtainSignerByFileExtension(String fileExtension) throws SignEngineException {
        switch (fileExtension.toLowerCase()) {
            case "xml":
                return new SignXML();
            case "pdf":
                return new SignPDF();
            default:
                throw new SignEngineException("Tipo de archivo no soportado", "");
        }
    }

    public static void main(String... arg) throws Exception {
        SignEngine eng = new SignEngine();
        eng.openKeyStore(0, "pepito123");
        eng.signDocuments(DEFAULT_ALIAS, new HashMap<String, File>());
        System.out.println("¿Es extraíble?: " + eng.isExtractable());
        eng.closeKeyStore();
    }

}
