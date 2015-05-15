package cl.cc.signature.certificate;

/**
 *
 * @author CyberCastle
 */
public class CertificateProviderException extends Exception {

    private static final long serialVersionUID = -967151084199398477L;
    private final String exceptionCode;

    public String getExceptionCode() {
        return this.exceptionCode;
    }

    public CertificateProviderException(String message, String exceptionCode) {
        super(message);
        this.exceptionCode = exceptionCode;
    }

    public CertificateProviderException(String message, String exceptionCode, Exception e) {
        super(message, e);
        this.exceptionCode = exceptionCode;
    }
}
