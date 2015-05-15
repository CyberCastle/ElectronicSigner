package cl.cc.signature.sign;

import cl.cc.signature.certificate.CertificateProvider;
import cl.cc.signature.date.DateProvider;
import cl.cc.signature.validation.certificate.CertificateValidator;
import com.itextpdf.text.DocumentException;
import com.itextpdf.text.Rectangle;
import com.itextpdf.text.pdf.PdfReader;
import com.itextpdf.text.pdf.PdfSignatureAppearance;
import com.itextpdf.text.pdf.PdfStamper;
import com.itextpdf.text.pdf.security.BouncyCastleDigest;
import com.itextpdf.text.pdf.security.ExternalDigest;
import com.itextpdf.text.pdf.security.ExternalSignature;
import com.itextpdf.text.pdf.security.MakeSignature;
import com.itextpdf.text.pdf.security.MakeSignature.CryptoStandard;
import com.itextpdf.text.pdf.security.PrivateKeySignature;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.cert.Certificate;

/**
 *
 * @author CyberCastle
 */
public final class SignPDF extends SignDocument {

    public static final int CERTIFIED_FORM_FILLING = PdfSignatureAppearance.CERTIFIED_FORM_FILLING;
    public static final int CERTIFIED_FORM_FILLING_AND_ANNOTATIONS = PdfSignatureAppearance.CERTIFIED_FORM_FILLING_AND_ANNOTATIONS;
    public static final int CERTIFIED_NO_CHANGES_ALLOWED = PdfSignatureAppearance.CERTIFIED_NO_CHANGES_ALLOWED;
    public static final int NOT_CERTIFIED = PdfSignatureAppearance.NOT_CERTIFIED;

    private boolean SignVisible;
    private int SingType;

    public SignPDF() {
        super();
        this.SignVisible = false;
        this.SingType = PdfSignatureAppearance.CERTIFIED_NO_CHANGES_ALLOWED;
    }

    public SignPDF(CertificateProvider provider) {
        this();
        this.provider = provider;
    }

    @Override
    public void setSignAttributes(boolean SignVisible, int SingType) {
        this.SignVisible = SignVisible;
        this.SingType = SingType;
    }

    @Override
    public void setSignAttributes(String TagID, String NSPrefix, String XPathToSign, String xmlSignerInfo) {
        throw new NoSuchMethodError("Method not defined");
    }

    @Override
    public void setCertificateProvider(CertificateProvider provider) {
        this.provider = provider;
    }

    @Override
    @SuppressWarnings("MismatchedReadAndWriteOfArray")
    public void sign() throws SignDocumentException {
        try {
            PdfReader pdfr = new PdfReader(new FileInputStream(this.inputFile));
            FileOutputStream pdfout = new FileOutputStream(this.outputFile);
            PdfStamper stp = PdfStamper.createSignature(pdfr, pdfout, '\0', null, this.signerList);
            PdfSignatureAppearance sap = stp.getSignatureAppearance();

            KeyStore ks = this.provider.getKeyStore();
            Certificate[] chain = ks.getCertificateChain(this.provider.getAlias());

            switch (SingType) {
                case CERTIFIED_NO_CHANGES_ALLOWED:
                    sap.setCertificationLevel(PdfSignatureAppearance.CERTIFIED_NO_CHANGES_ALLOWED);
                    break;
                case CERTIFIED_FORM_FILLING:
                    sap.setCertificationLevel(PdfSignatureAppearance.CERTIFIED_FORM_FILLING);
                    break;
                case CERTIFIED_FORM_FILLING_AND_ANNOTATIONS:
                    sap.setCertificationLevel(PdfSignatureAppearance.CERTIFIED_FORM_FILLING_AND_ANNOTATIONS);
                    break;
                case NOT_CERTIFIED:
                    sap.setCertificationLevel(PdfSignatureAppearance.NOT_CERTIFIED);
                    break;
                default:
                    sap.setCertificationLevel(PdfSignatureAppearance.CERTIFIED_NO_CHANGES_ALLOWED);
            }

            sap.setSignDate(this.signDate);
            if (this.SignVisible) {
                sap.setVisibleSignature(new Rectangle(50, 50, 150, 100), pdfr.getNumberOfPages(), null);
            }

            sap.setLocation(this.locationSign);
            sap.setReason(this.reasonSign);

            ExternalSignature es = new PrivateKeySignature(this.provider.getPrivateKey(), "SHA-256", this.provider.getProviderName());
            ExternalDigest digest = new BouncyCastleDigest();
            MakeSignature.signDetached(sap, digest, es, chain, null, null, null, 0, CryptoStandard.CMS);

            stp.close();
            pdfout.flush();
            pdfout.close();
            pdfr.close();
        } catch (KeyStoreException e) {
            throw new SignDocumentException("Error al acceder al certificado", "", e);
        } catch (DocumentException e) {
            throw new SignDocumentException("Formato del documento inválido", "", e);
        } catch (IOException e) {
            throw new SignDocumentException("Error al acceder al documento", "", e);
        } catch (GeneralSecurityException e) {
            throw new SignDocumentException("Error al firmar el documento", "", e);
        }
    }
}
