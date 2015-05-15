package cl.cc.signature.validation.document;

/**
 *
 * @author CyberCastle
 */
public class SignedDocumentValidatorException extends Exception {

    private static final long serialVersionUID = 4901279574425248375L;
    private final String exceptionCode;

    public String getExceptionCode() {
        return this.exceptionCode;
    }

    public SignedDocumentValidatorException(String message, String exceptionCode) {
        super(message);
        this.exceptionCode = exceptionCode;
    }

    public SignedDocumentValidatorException(String message, String exceptionCode, Exception e) {
        super(message, e);
        this.exceptionCode = exceptionCode;
    }
}
