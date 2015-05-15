package cl.cc.signature.sign;

import cl.cc.signature.date.DateProvider;
import cl.cc.signature.certificate.CertificateProvider;
import cl.cc.signature.validation.certificate.CertificateValidator;
import cl.cc.signature.validation.document.SignedXMLValidator;
import cl.cc.utils.xml.XMLErrorsHandler;
import cl.cc.utils.xml.XMLUtils;
import org.apache.xml.security.Init;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.Collections;
import java.util.Calendar;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyException;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.Provider;
import javax.xml.crypto.dom.DOMStructure;
import javax.xml.crypto.dsig.CanonicalizationMethod;
import javax.xml.crypto.dsig.DigestMethod;
import javax.xml.crypto.dsig.dom.DOMSignContext;
import javax.xml.crypto.dsig.Reference;
import javax.xml.crypto.dsig.SignatureMethod;
import javax.xml.crypto.dsig.SignedInfo;
import javax.xml.crypto.dsig.Transform;
import javax.xml.crypto.dsig.XMLSignature;
import javax.xml.crypto.dsig.XMLSignatureException;
import javax.xml.crypto.dsig.XMLSignatureFactory;
import javax.xml.crypto.dsig.keyinfo.KeyInfo;
import javax.xml.crypto.dsig.keyinfo.KeyInfoFactory;
import javax.xml.crypto.dsig.keyinfo.KeyValue;
import javax.xml.crypto.dsig.keyinfo.X509Data;
import javax.xml.crypto.dsig.spec.C14NMethodParameterSpec;
import javax.xml.crypto.dsig.spec.TransformParameterSpec;
import javax.xml.crypto.dsig.spec.XPathFilterParameterSpec;
import javax.xml.crypto.MarshalException;
import javax.xml.crypto.dsig.XMLObject;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

/**
 *
 * @author CyberCastle
 */
public final class SignXML extends SignDocument {

    private String TagID;
    private String NSPrefix;
    private String XPathToSign;
    private String XmlSignerInfo;

    public SignXML() {
        super();
        this.TagID = "null";
        this.NSPrefix = "null";
        this.XPathToSign = "null";
        Init.init();
    }

    public SignXML(CertificateProvider CertManager) {
        this();
        this.provider = CertManager;
    }

    @Override
    public void setSignAttributes(boolean SignVisible, int SingType) {
        throw new NoSuchMethodError("Method not defined");
    }

    @Override
    public void setSignAttributes(String TagID, String NSPrefix, String XPathToSign, String XmlSignerInfo) {
        this.TagID = TagID;
        this.NSPrefix = NSPrefix;
        this.XPathToSign = XPathToSign;
        this.XmlSignerInfo = XmlSignerInfo;
    }

    @Override
    public void setCertificateProvider(CertificateProvider provider) {
        this.provider = provider;
    }

    @Override
    public void sign() throws SignDocumentException {
        try {
            Document xmlIn = XMLUtils.setXMLStream(new FileInputStream(this.inputFile));
            Document xmlOut = SignXML(xmlIn, this.TagID, this.NSPrefix, this.XPathToSign, this.signerList, this.XmlSignerInfo);
            try (FileOutputStream xmlOutFile = new FileOutputStream(this.outputFile)) {
                XMLUtils.getXMLStream(xmlOutFile, xmlOut);
                xmlOutFile.flush();
            }
        } catch (XMLErrorsHandler e) {
            throw new SignDocumentException("Formato del documento inválido", "", e);
        } catch (IOException e) {
            throw new SignDocumentException("Error al acceder al documento", "", e);
        }
    }

    public String signString(String xmlStr) throws SignDocumentException {
        try {
            Document xmlIn = XMLUtils.setXMLString(xmlStr);
            Document xmlOut = SignXML(xmlIn, this.TagID, this.NSPrefix, this.XPathToSign, this.signerList, this.XmlSignerInfo);
            return XMLUtils.getXMLString(xmlOut);
        } catch (XMLErrorsHandler e) {
            throw new SignDocumentException("Formato del documento inválido", "", e);
        }
    }

    private Document SignXML(Document XMLDoc, String TagID, String NSPrefix,
            String XPathToSign, boolean SignerList, String xmlSignerInfo) throws SignDocumentException {
        try {
            if (TagID.trim().equalsIgnoreCase("null")) {
                TagID = "";
            } else {
                TagID = "#" + TagID;
            }
            if (NSPrefix.trim().equalsIgnoreCase("null")) {
                NSPrefix = null;
            }
            if (XPathToSign.trim().equalsIgnoreCase("null")) {
                XPathToSign = null;
            }

            Element root = XMLDoc.getDocumentElement();

            /*
             Provider
             *This class represents a "provider" for the Java Security API, where a provider implements
             some or all parts of Java Security. Services that a provider may implement include:
             Algorithms (such as DSA, RSA, MD5 or SHA-1).
             Key generation, conversion, and management facilities (such as for algorithm-specific keys).
             */
            String providerName = System.getProperty("jsr105Provider", "org.apache.jcp.xml.dsig.internal.dom.XMLDSigRI");
            XMLSignatureFactory SignFactory = XMLSignatureFactory.getInstance("DOM", (Provider) Class.forName(providerName).newInstance());
            ArrayList<Transform> TransformList = new ArrayList<>(1);
            Transform trans;

            if (XPathToSign != null) {
                String defaultXMLNS = root.getAttribute("xmlns");
                String xPathPrefijo = getPathPrefix(XPathToSign);
                String prefijoFirma = "";
                if (NSPrefix != null) {
                    prefijoFirma = NSPrefix + ":";
                }
                if (defaultXMLNS.equals("")) {
                    trans = SignFactory.newTransform(Transform.XPATH,
                            new XPathFilterParameterSpec("not(ancestor-or-self::" + prefijoFirma + "Signature) and (" + XPathToSign + ")"));
                } else {
                    trans = SignFactory.newTransform(Transform.XPATH,
                            new XPathFilterParameterSpec("not(ancestor-or-self::" + prefijoFirma + "Signature) and (" + XPathToSign + ")",
                                    Collections.singletonMap(xPathPrefijo, defaultXMLNS)));
                }
            } else {
                trans = SignFactory.newTransform(Transform.ENVELOPED, (TransformParameterSpec) null);
            }

            TransformList.add(trans);
            Reference ref = SignFactory.newReference(TagID, SignFactory.newDigestMethod(DigestMethod.SHA1, null), TransformList, null, null);
            SignedInfo si = SignFactory.newSignedInfo(SignFactory.newCanonicalizationMethod(CanonicalizationMethod.INCLUSIVE_WITH_COMMENTS,
                    (C14NMethodParameterSpec) null), SignFactory.newSignatureMethod(SignatureMethod.RSA_SHA1, null), Collections.singletonList(ref));

            // Create a RSA KeyPair
            KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
            kpg.initialize(1024); // RSA keys are typically 1024–2048 bits long

            // Create a KeyValue containing the RSA PublicKey that was generated y certificated X509
            KeyInfoFactory kif = SignFactory.getKeyInfoFactory();
            KeyValue keyval = kif.newKeyValue(this.provider.getCertificate().getPublicKey());
            X509Data x509data = kif.newX509Data(Collections.singletonList(this.provider.getCertificate()));
            List<Object> KeysList = new ArrayList<>(2);
            KeysList.add(0, keyval);
            KeysList.add(1, x509data);

            // Create a KeyInfo and add the KeyValue to it
            KeyInfo ki = kif.newKeyInfo(KeysList.subList(0, 2));

            // Create a DOMSignContext and specify the DSA PrivateKey and
            // location of the resulting XMLSignature's parent element
            DOMSignContext dsc = new DOMSignContext(this.provider.getPrivateKey(), root);
            if (NSPrefix != null) {
                dsc.putNamespacePrefix(XMLSignature.XMLNS, NSPrefix);
            }

            //Create the XMLSignature (but don't sign it yet) and
            //Inserts some data in the signature node
            XMLSignature signature;
            if (SignerList && xmlSignerInfo != null && !xmlSignerInfo.equals("")) {
                Element Signer = parseSignerInfo(xmlSignerInfo); //writeSignerInfo(root);
                ArrayList<XMLObject> content = new ArrayList<>(1);
                content.add(SignFactory.newXMLObject(Collections.singletonList(new DOMStructure(Signer)), "SignerInfo", "text/xml", null));
                signature = SignFactory.newXMLSignature(si, ki, content, null, null);
            } else {
                signature = SignFactory.newXMLSignature(si, ki);
            }

            // Marshal, generate (and sign) the enveloped signature
            signature.sign(dsc);
            return root.getOwnerDocument();
        } catch (MarshalException | XMLSignatureException e) {
            throw new SignDocumentException("Error al firmar el documento", "", e);
        } catch (KeyException | NoSuchAlgorithmException | InvalidAlgorithmParameterException | ClassNotFoundException | InstantiationException | IllegalAccessException e) {
            throw new SignDocumentException("Error al acceder al certificado", "", e);
        }
    }

    private Element parseSignerInfo(String xmlSignerInfo) throws SignDocumentException {
        try {
            //Antes de parsear, revisar string buscano tag %USER%, %SIGNTYPE% y %DATETIME% para reemplazarlo por los datos correspondientes
            xmlSignerInfo = xmlSignerInfo.replaceAll("%USER%", this.provider.getUserName());
            xmlSignerInfo = xmlSignerInfo.replaceAll("%USERID%", this.provider.getUserID());
            xmlSignerInfo = xmlSignerInfo.replaceAll("%DATETIME%", this.getDateTime("-", ":"));
            String SignType = "Firma Simple";
            if (this.provider.isAdvancedSignaure()) {
                SignType = "Firma Avanzada";
            }
            xmlSignerInfo = xmlSignerInfo.replaceAll("%SIGNTYPE%", SignType);
            return XMLUtils.setXMLString(xmlSignerInfo).getDocumentElement();
        } catch (XMLErrorsHandler e) {
            throw new SignDocumentException("Error al añadir información del Firmante", "", e);
        }
    }

    private String getDateTime(String dateSeparator, String timeSeparator) {

        return this.signDate.get(Calendar.DAY_OF_MONTH)
                + dateSeparator + (this.signDate.get(Calendar.MONTH) + 1)
                + dateSeparator + this.signDate.get(Calendar.YEAR) + " "
                + this.signDate.get(Calendar.HOUR_OF_DAY) + timeSeparator
                + this.signDate.get(Calendar.MINUTE) + timeSeparator
                + this.signDate.get(Calendar.SECOND) + " hs.";
    }

    private String getPathPrefix(String xpath) {
        int posFL = xpath.indexOf("/");
        String prefijo = "";
        if (posFL > -1) {
            String left = xpath.substring(posFL, xpath.length());
            int pos2P = left.indexOf(":");
            int pos4P = left.indexOf("::");
            if (pos4P == -1) {
                pos4P = left.length() + 1;
            }

            if (-1 < pos2P & pos2P < pos4P) {
                prefijo = left.substring(1, pos2P);
            }
        }
        System.out.println("getPathPrefix:   " + prefijo.trim());
        return prefijo.trim();
    }
}
