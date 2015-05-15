package cl.cc.signature.sign;

/**
 *
 * @author CyberCastle
 */
public class SignDocumentException extends Exception {

    private static final long serialVersionUID = 2692829061734503935L;
    private final String exceptionCode;

    public String getExceptionCode() {
        return this.exceptionCode;
    }

    public SignDocumentException(String message, String exceptionCode) {
        super(message);
        this.exceptionCode = exceptionCode;
    }

    public SignDocumentException(String message, String exceptionCode, Exception e) {
        super(message, e);
        this.exceptionCode = exceptionCode;
    }
}
