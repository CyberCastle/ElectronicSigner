package cl.cc.utils.xml;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.ArrayList;
import javax.xml.namespace.NamespaceContext;
import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpressionException;
import javax.xml.xpath.XPathFactory;
import javax.xml.xpath.XPathFactoryConfigurationException;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

/**
 *
 * @author CyberCastle
 */
public final class XMLHandler {

    private String FilePath;
    private Element XMLDocument;
    private NamespaceContext nameSpace = null;
    private XPath path;

    public XMLHandler() {
        this.path = XPathFactory.newInstance().newXPath();
    }

    public XMLHandler(Document xmlDocument) {
        this();
        this.XMLDocument = xmlDocument.getDocumentElement();
    }

    public XMLHandler(String FilePath) throws XMLErrorsHandler, FileNotFoundException {
        this();
        this.FilePath = FilePath;
        this.loadDocument();
    }

    public void setFilePath(String FilePath) {
        this.FilePath = FilePath;
    }

    public void setNamespaceContext(NamespaceContext ns) {
        this.nameSpace = ns;
    }

    public void loadDocument() throws XMLErrorsHandler {
        this.loadDocument(new File(this.FilePath));
    }

    public void loadDocument(File XMLFile) throws XMLErrorsHandler {
        try {
            this.XMLDocument = XMLUtils.setXMLStream(new FileInputStream(XMLFile)).getDocumentElement();
        } catch (FileNotFoundException ex) {
            throw new XMLErrorsHandler(ex);
        }
    }

    public void loadDocument(InputStream XMLStream) throws XMLErrorsHandler {
        this.XMLDocument = XMLUtils.setXMLStream(XMLStream).getDocumentElement();
    }

    public void loadDocument(String XMLString) throws XMLErrorsHandler {
        this.XMLDocument = XMLUtils.setXMLString(XMLString).getDocumentElement();
    }

    public void insertNode(String XPathExpression, String NodeString) throws XMLErrorsHandler {
        Document nodeDocument = XMLUtils.setXMLString(NodeString);
        this.insertNode(XPathExpression, nodeDocument.getDocumentElement());
    }

    public void insertNode(String XPathExpression, Node newNode) throws XMLErrorsHandler {
        try {
            Node targetNode = this.getNode(XPathExpression);
            Node originNode = this.getResultDocument().importNode(newNode, true);
            targetNode.appendChild(originNode);
        } catch (XPathExpressionException | XPathFactoryConfigurationException ex) {
            throw new XMLErrorsHandler(ex);
        }
    }

    public void removeNode(String XPathExpression) throws XMLErrorsHandler {
        try {
            Node node = this.getNode(XPathExpression);
            Node parentNode = node.getParentNode();
            parentNode.removeChild(node);
        } catch (XPathExpressionException | XPathFactoryConfigurationException ex) {
            throw new XMLErrorsHandler(ex);
        }
    }

    public void insertDocument(String XPathExpression, Document xml) throws XMLErrorsHandler {
        this.insertNode(XPathExpression, xml.getDocumentElement());
    }

    public void setNodeValue(String XPathExpression, String NodeValue) throws XMLErrorsHandler {
        try {
            Node node = this.getNode(XPathExpression);
            if (node == null) {
                return;
            }
            ((Element) node).setTextContent(NodeValue);
        } catch (XPathFactoryConfigurationException | XPathExpressionException ex) {
            throw new XMLErrorsHandler(ex);
        }
    }

    public void setNodeValue(String XPathExpression, Element NodeValue) throws XMLErrorsHandler {
        try {
            Node node = this.getNode(XPathExpression);
            if (node == null) {
                return;
            }
            Node newNode = this.XMLDocument.getOwnerDocument().importNode(NodeValue, true);
            node.getParentNode().appendChild(newNode);
            node.getParentNode().removeChild(node);
        } catch (XPathFactoryConfigurationException | XPathExpressionException ex) {
            throw new XMLErrorsHandler(ex);
        }
    }

    public String getNodeValue(String XPathExpression) throws XMLErrorsHandler {
        try {
            Node node = this.getNode(XPathExpression);
            if (node == null) {
                return "";
            }
            return ((Element) node).getTextContent();
        } catch (XPathFactoryConfigurationException | XPathExpressionException ex) {
            throw new XMLErrorsHandler(ex);
        }
    }

    public String getNodeName(String XPathExpression) throws XMLErrorsHandler {
        try {
            Node node = this.getNode(XPathExpression);
            if (node == null) {
                return "";
            }
            return ((Element) node).getTagName();
        } catch (XPathFactoryConfigurationException | XPathExpressionException ex) {
            throw new XMLErrorsHandler(ex);
        }
    }

    public ArrayList<String> getNodesValue(String XPathExpression) throws XMLErrorsHandler {
        try {
            ArrayList<String> Values = new ArrayList<>();
            NodeList nodes = this.getNodes(XPathExpression);

            if (nodes == null) {
                return Values;
            }

            for (int i = 0; i < nodes.getLength(); i++) {
                Values.add(((Element) nodes.item(i)).getTextContent());
            }
            return Values;
        } catch (XPathFactoryConfigurationException | XPathExpressionException ex) {
            throw new XMLErrorsHandler(ex);
        }
    }

    public ArrayList<String> getNodesName(String XPathExpression) throws XMLErrorsHandler {
        try {
            ArrayList<String> Values = new ArrayList<>();
            NodeList nodes = this.getNodes(XPathExpression);

            if (nodes == null) {
                return Values;
            }

            for (int i = 0; i < nodes.getLength(); i++) {
                Values.add(((Element) nodes.item(i)).getTagName());
            }
            return Values;
        } catch (XPathFactoryConfigurationException | XPathExpressionException ex) {
            throw new XMLErrorsHandler(ex);
        }
    }

    public Boolean hasNode(String XPathExpression) throws XMLErrorsHandler {
        try {
            if (this.nameSpace != null) {
                this.path.setNamespaceContext(this.nameSpace);
            }
            return (Boolean) this.path.evaluate(XPathExpression, this.XMLDocument, XPathConstants.BOOLEAN);
        } catch (XPathExpressionException ex) {
            throw new XMLErrorsHandler(ex);
        }
    }

    public boolean hasAttribute(String NodeName, String AttributeName) throws XMLErrorsHandler {
        try {
            Node node = this.getNode(NodeName);
            if (node == null) {
                return false;
            }
            return ((Element) node).hasAttribute(AttributeName);
        } catch (XPathFactoryConfigurationException | XPathExpressionException ex) {
            throw new XMLErrorsHandler(ex);
        }
    }

    public void setAttributeValue(String XPathExpression, String attributeName, String attributeValue) throws XMLErrorsHandler {
        try {
            Node node = this.getNode(XPathExpression);
            if (node == null) {
                return;
            }
            ((Element) node).setAttribute(attributeName, attributeValue);
        } catch (XPathFactoryConfigurationException | XPathExpressionException ex) {
            throw new XMLErrorsHandler(ex);
        }
    }

    public String getNodeAttribute(String XPathExpression, String AttributeName) throws XMLErrorsHandler {
        try {
            Node node = this.getNode(XPathExpression);
            if (node == null) {
                return "";
            }
            return ((Element) node).getAttribute(AttributeName);
        } catch (XPathFactoryConfigurationException | XPathExpressionException ex) {
            throw new XMLErrorsHandler(ex);
        }
    }

    public void setNodesAttribute(String XPathExpression, String attributeName, ArrayList<String> attributeValues) throws XMLErrorsHandler {
        try {
            NodeList nodes = this.getNodes(XPathExpression);
            if (nodes == null) {
                return;
            }
            for (int i = 0; i < nodes.getLength(); i++) {
                ((Element) nodes.item(i)).setAttribute(attributeName, attributeValues.get(i));
            }
        } catch (XPathFactoryConfigurationException | XPathExpressionException ex) {
            throw new XMLErrorsHandler(ex);
        }
    }

    public ArrayList<String> getNodesAttribute(String XPathExpression, String attributeName) throws XMLErrorsHandler {
        try {
            ArrayList<String> Values = new ArrayList<>();
            NodeList nodes = this.getNodes(XPathExpression);
            if (nodes == null) {
                return Values;
            }

            for (int i = 0; i < nodes.getLength(); i++) {
                Values.add(((Element) nodes.item(i)).getAttribute(attributeName));
            }
            return Values;
        } catch (XPathFactoryConfigurationException | XPathExpressionException ex) {
            throw new XMLErrorsHandler(ex);
        }
    }

    public int countNodes(String XPathExpression) throws XMLErrorsHandler {
        String XMLXPath = "count(" + XPathExpression + ")";
        try {
            if (this.nameSpace != null) {
                this.path.setNamespaceContext(this.nameSpace);
            }
            String cnt = this.path.evaluate(XMLXPath, this.XMLDocument, XPathConstants.NUMBER).toString();
            return Double.valueOf(cnt).intValue();
        } catch (XPathExpressionException ex) {
            throw new XMLErrorsHandler(ex);
        }
    }

    public void saveAs(String fileName) throws IOException, XMLErrorsHandler {
        try (FileOutputStream xmlout = new FileOutputStream(fileName)) {
            XMLUtils.getXMLStream(xmlout, this.XMLDocument.getOwnerDocument());
            xmlout.flush();
        }
    }

    public void save() throws IOException, XMLErrorsHandler {
        this.saveAs(this.FilePath);
    }

    public Document getResultDocument() {
        return this.XMLDocument.getOwnerDocument();
    }

    public String getResultString() throws XMLErrorsHandler {
        return XMLUtils.getXMLString(this.XMLDocument.getOwnerDocument());
    }

    public void getResultStream(OutputStream stream) throws XMLErrorsHandler {
        XMLUtils.getXMLStream(stream, this.XMLDocument.getOwnerDocument());
    }

    private Node getNode(String XPathExpression) throws XPathExpressionException, XPathFactoryConfigurationException {
        if (this.nameSpace != null) {
            this.path.setNamespaceContext(this.nameSpace);
        }
        return (Node) this.path.evaluate(XPathExpression, this.XMLDocument, XPathConstants.NODE);
    }

    private NodeList getNodes(String XPathExpression) throws XPathExpressionException, XPathFactoryConfigurationException {
        if (this.nameSpace != null) {
            this.path.setNamespaceContext(this.nameSpace);
        }
        return (NodeList) this.path.evaluate(XPathExpression, this.XMLDocument, XPathConstants.NODESET);
    }
}
