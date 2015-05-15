package cl.cc.gui;

/**
 *
 * @author CyberCastle
 */
public class SignEngineException extends Exception {

    private static final long serialVersionUID = 4270688902891551341L;
    private final String exceptionCode;

    public String getExceptionCode() {
        return this.exceptionCode;
    }

    public SignEngineException(String message, String exceptionCode) {
        super(message);
        this.exceptionCode = exceptionCode;
    }

    public SignEngineException(String message, String exceptionCode, Exception e) {
        super(message, e);
        this.exceptionCode = exceptionCode;
    }
}
