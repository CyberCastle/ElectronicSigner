package cl.cc.signature.sign;

import cl.cc.signature.certificate.CertificateProvider;
import java.io.File;
import java.util.Calendar;

/**
 *
 * @author CyberCastle
 */
public abstract class SignDocument {

    protected CertificateProvider provider;
    protected File inputFile;
    protected File outputFile;
    protected Boolean signerList;
    protected Calendar signDate;
    protected String reasonSign;
    protected String locationSign;

    protected SignDocument() {
        this.signerList = false;
    }

    public void setDocuments(File inputFile, File outputFile) {
        this.inputFile = inputFile;
        this.outputFile = outputFile;
    }

    public void setSignerList(boolean SignerList) {
        this.signerList = SignerList;
    }

    public void setSignDate(Calendar signDate) {
        this.signDate = signDate;
    }

    public void setReasonSign(String reasonSign) {
        this.reasonSign = reasonSign;
    }

    public void setLocationSign(String locationSign) {
        this.locationSign = locationSign;
    }

    public abstract void sign() throws SignDocumentException;

    public abstract void setSignAttributes(boolean SignVisible, int SingType);

    public abstract void setSignAttributes(String TagID, String NSPrefix, String XPathToSign, String xmlSignerInfo);

    public abstract void setCertificateProvider(CertificateProvider cp);
}
