package cl.cc.signature.date;

/**
 *
 * @author CyberCastle
 */
public class DateProviderException extends Exception {

    private static final long serialVersionUID = -7604843999142716508L;

    public DateProviderException() {
    }

    public DateProviderException(Exception e) {
        super(e);
    }

    public DateProviderException(String message, Exception e) {
        super(message, e);
    }
}
