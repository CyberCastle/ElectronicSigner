package cl.cc.utils.xml;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.StringWriter;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.transform.Source;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerException;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;
import org.w3c.dom.Document;
import org.w3c.dom.Node;
import org.xml.sax.SAXException;

/**
 *
 * @author CyberCastle
 */
public abstract class XMLUtils {

    public static Document setXMLString(String xmlString) throws XMLErrorsHandler {
        InputStream XMLStream = new ByteArrayInputStream(xmlString.getBytes());
        return XMLUtils.setXMLStream(XMLStream);
    }

    public static Document setXMLStream(InputStream xmlStream) throws XMLErrorsHandler {
        try {
            DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
            dbf.setNamespaceAware(true);
            dbf.setIgnoringElementContentWhitespace(true);
            DocumentBuilder db = dbf.newDocumentBuilder();
            db.setErrorHandler(new XMLErrorsHandler());
            Document xml = db.parse(xmlStream);
            xml.normalizeDocument();
            xml.normalize();
            return xml;
        } catch (ParserConfigurationException | SAXException | IOException ex) {
            throw new XMLErrorsHandler(ex);
        }
    }

    public static DOMSource setDOMStream(InputStream xmlStream) throws XMLErrorsHandler {
        return new DOMSource(XMLUtils.setXMLStream(xmlStream));
    }

    public static DOMSource setDOMString(String xmlString) throws XMLErrorsHandler {
        return new DOMSource(XMLUtils.setXMLString(xmlString));
    }

    public static void getXMLStream(OutputStream xmlStream, Node xml) throws XMLErrorsHandler {
        XMLUtils.xmlProcess(new StreamResult(xmlStream), xml);
    }

    public static String getXMLString(Node xml) throws XMLErrorsHandler {
        StringWriter writer = new StringWriter();
        XMLUtils.xmlProcess(new StreamResult(writer), xml);
        return writer.toString();
    }

    private static void xmlProcess(StreamResult result, Node xml) throws XMLErrorsHandler {
        try {
            xml.normalize();
            TransformerFactory transformerFactory = TransformerFactory.newInstance();
            Transformer transformer = transformerFactory.newTransformer();
            transformer.setErrorListener(new XMLErrorsHandler());
            Source source = new DOMSource(xml);
            transformer.transform(source, result);
        } catch (TransformerException ex) {
            throw new XMLErrorsHandler(ex);
        }
    }
}
