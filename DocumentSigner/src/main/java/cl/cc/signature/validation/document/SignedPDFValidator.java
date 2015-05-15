package cl.cc.signature.validation.document;

import cl.cc.signature.validation.certificate.CertificateValidator;
import cl.cc.signature.validation.certificate.CertificateValidatorException;
import com.itextpdf.text.pdf.AcroFields;
import com.itextpdf.text.pdf.PdfReader;
import com.itextpdf.text.pdf.security.PdfPKCS7;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.util.ArrayList;

/**
 *
 * @author CyberCastle
 */
public final class SignedPDFValidator extends SignedDocumentValidator {

    private PdfReader pdfDocument;

    public SignedPDFValidator(CertificateValidator certificateValidator) {
        super(certificateValidator);
    }

    public SignedPDFValidator(String pdfPath, CertificateValidator certificateValidator) throws SignedDocumentValidatorException {
        super(certificateValidator);
        this.setDocument(pdfPath);
    }

    public SignedPDFValidator(PdfReader pdfDocument, CertificateValidator certificateValidator) {
        super(certificateValidator);
        this.setDocument(pdfDocument);
    }

    @Override
    public void setDocument(String pdfPath) throws SignedDocumentValidatorException {
        try {
            this.pdfDocument = new PdfReader(pdfPath);
        } catch (IOException e) {
            throw new SignedDocumentValidatorException("Formato del documento inválido", "", e);
        }
    }

    @Override
    public void setDocument(Object pdfDocument) {
        this.pdfDocument = (PdfReader) pdfDocument;
    }

    // Este método valida la firma
    @Override
    public Boolean validate() throws SignedDocumentValidatorException, CertificateValidatorException {
        AcroFields af = this.pdfDocument.getAcroFields();

        // Search of the whole signature
        ArrayList afNamesList = af.getSignatureNames();
        if (afNamesList.isEmpty()) {
            throw new SignedDocumentValidatorException("El documento no ha sido firmado", "");
        }

        for (Object afName : afNamesList) {
            PdfPKCS7 sign = af.verifySignature((String) afName);
            try {
                if (!sign.verify()) {
                    return false;
                }
            } catch (GeneralSecurityException e) {
                throw new SignedDocumentValidatorException("No ha sido posible comprobar la firma", "", e);
            }

            //Extract certificate from signature field
            this.certificateValidator.setCertificate(sign.getSigningCertificate());
            if (!this.isCertificateValid()) {
                return false;
            }
        }
        return true;
    }
}
