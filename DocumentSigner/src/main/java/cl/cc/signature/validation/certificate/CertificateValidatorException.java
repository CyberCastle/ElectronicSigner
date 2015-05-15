package cl.cc.signature.validation.certificate;

/**
 *
 * @author CyberCastle
 */
public class CertificateValidatorException extends Exception {

    private static final long serialVersionUID = 3615438490740288949L;
    private final String exceptionCode;

    public String getExceptionCode() {
        return this.exceptionCode;
    }

    public CertificateValidatorException(String message, String exceptionCode) {
        super(message);
        this.exceptionCode = exceptionCode;
    }

    public CertificateValidatorException(String message, String exceptionCode, Exception e) {
        super(message, e);
        this.exceptionCode = exceptionCode;
    }
}
