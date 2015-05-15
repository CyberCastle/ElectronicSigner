package cl.cc.signature.validation.document;

import cl.cc.utils.xml.XMLErrorsHandler;
import cl.cc.utils.xml.XMLUtils;
import cl.cc.signature.validation.certificate.CertificateValidator;
import cl.cc.signature.validation.certificate.CertificateValidatorException;
import org.apache.xml.security.exceptions.XMLSecurityException;
import org.apache.xml.security.keys.KeyInfo;
import org.apache.xml.security.signature.SignedInfo;
import org.apache.xml.security.signature.XMLSignature;
import org.apache.xml.security.utils.Constants;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;

/**
 *
 * @author CyberCastle
 */
public final class SignedXMLValidator extends SignedDocumentValidator {

    private Document xmlDocument;

    public SignedXMLValidator(CertificateValidator certificateValidator) {
        super(certificateValidator);
    }

    public SignedXMLValidator(String pdfPath, CertificateValidator certificateValidator) throws SignedDocumentValidatorException {
        super(certificateValidator);
        this.setDocument(pdfPath);
    }

    public SignedXMLValidator(Document xmlDocument, CertificateValidator certificateValidator) {
        super(certificateValidator);
        this.setDocument(xmlDocument);
    }

    @Override
    public void setDocument(String xmlPath) throws SignedDocumentValidatorException {
        try {
            this.xmlDocument = XMLUtils.setXMLStream(new FileInputStream(xmlPath));
        } catch (FileNotFoundException e) {
            throw new SignedDocumentValidatorException("Error al acceder al documento", "", e);
        } catch (XMLErrorsHandler e) {
            throw new SignedDocumentValidatorException("Formato del documento inválido", "", e);
        }
    }

    public void setStrDocument(String xmlStr) throws SignedDocumentValidatorException {
        try {
            this.xmlDocument = XMLUtils.setXMLString(xmlStr);
        } catch (XMLErrorsHandler e) {
            throw new SignedDocumentValidatorException("Formato del documento inválido", "", e);
        }
    }

    @Override
    public void setDocument(Object xmlDocument) {
        this.xmlDocument = (Document) xmlDocument;
    }

    //Este método valida la firma
    @Override
    public Boolean validate() throws SignedDocumentValidatorException, CertificateValidatorException {
        try {
            NodeList SignElementsList = this.xmlDocument.getElementsByTagNameNS(Constants.SignatureSpecNS, "Signature");
            if (SignElementsList == null || SignElementsList.getLength() == 0) {
                throw new SignedDocumentValidatorException("El documento no ha sido firmado", "");
            }

            for (int i = 0; i < SignElementsList.getLength(); i++) {
                Element SignElement = (Element) SignElementsList.item(i);
                XMLSignature signature = new XMLSignature(SignElement, "invalid:uri");
                KeyInfo ki = signature.getKeyInfo();

                if (ki == null) {
                    throw new SignedDocumentValidatorException("La firma no contiene datos del Certificado Público", "");
                }

                SignedInfo si = signature.getSignedInfo();
                for (int sii = 0; sii < si.getSignedContentLength(); sii++) {
                    if (!si.getVerificationResult(sii)) {
                        // El documento a sido modificado después de ser firmado
                        return false;
                    }
                }

                //Extract the key public from signature node
                PublicKey pk = ki.getPublicKey();
                if (pk == null) {
                    throw new SignedDocumentValidatorException("La firma no contiene un certificado X.509", "");
                }

                //Verify the signature against the key public
                if (!signature.checkSignatureValue(pk)) {
                    return false;
                }

                //Extract the certificate from signature node
                X509Certificate certificate = ki.getX509Certificate();
                if (certificate == null) {
                    throw new SignedDocumentValidatorException("La firma no contiene un certificado X.509", "");
                }

                //Verify the signature against the certificate
                if (!signature.checkSignatureValue(certificate)) {
                    return false;
                }

                //Extract certificate from signature field
                this.certificateValidator.setCertificate(certificate);
                if (!this.isCertificateValid()) {
                    return false;
                }
            }
        } catch (XMLSecurityException e) {
            throw new SignedDocumentValidatorException("No ha sido posible comprobar la firma", "", e);
        }

        return true;
    }
}
