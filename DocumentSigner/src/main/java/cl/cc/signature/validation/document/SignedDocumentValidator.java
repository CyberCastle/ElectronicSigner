package cl.cc.signature.validation.document;

import cl.cc.signature.validation.certificate.CertificateValidator;
import cl.cc.signature.validation.certificate.CertificateValidatorException;

/**
 *
 * @author CyberCastle
 */
public abstract class SignedDocumentValidator {

    protected final CertificateValidator certificateValidator;

    public SignedDocumentValidator(CertificateValidator certificateValidator) {
        this.certificateValidator = certificateValidator;
    }

    public abstract Boolean validate() throws SignedDocumentValidatorException, CertificateValidatorException;

    public abstract void setDocument(String DocumentPath) throws SignedDocumentValidatorException;

    public abstract void setDocument(Object document);

    protected Boolean isCertificateValid() throws CertificateValidatorException {        
        return this.certificateValidator.isValid() || !this.certificateValidator.isOnCRL() || this.certificateValidator.isForDigitalSignature();
    }
}
