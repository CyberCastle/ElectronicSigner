package cl.cc.utils.xml;

import javax.xml.transform.ErrorListener;
import javax.xml.transform.TransformerException;
import org.xml.sax.ErrorHandler;
import org.xml.sax.SAXException;
import org.xml.sax.SAXParseException;

/**
 *
 * @author CyberCastle
 *
 */
public class XMLErrorsHandler extends Exception implements ErrorListener, ErrorHandler {

    private static final long serialVersionUID = 5604847053794888086L;

    public XMLErrorsHandler() {
    }

    public XMLErrorsHandler(Exception e) {
        super(e);
    }

    public XMLErrorsHandler(String message, Exception e) {
        super(message, e);
    }

    public XMLErrorsHandler(String message) {
        super(message);
    }

    @Override
    public void warning(TransformerException exception) {
        System.out.println("WARNING:");
        exception.printStackTrace();
    }

    @Override
    public void error(TransformerException exception) throws TransformerException {
        System.out.println("**** ErrorsProcessorHandler:");
        exception.printStackTrace();
        throw exception;
    }

    @Override
    public void fatalError(TransformerException exception) throws TransformerException {
        System.out.println("**** ErrorsProcessorHandler:");
        exception.printStackTrace();
        throw exception;
    }

    @Override
    public void warning(SAXParseException exception) throws SAXException {
        System.out.println("**** ErrorsProcessorHandler:");
        exception.printStackTrace();
        throw exception;
    }

    @Override
    public void error(SAXParseException exception) throws SAXException {
        System.out.println("**** ErrorsProcessorHandler:");
        exception.printStackTrace();
        throw exception;
    }

    @Override
    public void fatalError(SAXParseException exception) throws SAXException {
        System.out.println("**** ErrorsProcessorHandler:");
        exception.printStackTrace();
        throw exception;
    }
}
