package cl.cc.signature.cryptodevice;

import cl.cc.utils.log.Logger;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.util.Properties;

/**
 *
 * @author CyberCastle
 */
public final class CryptoDeviceConfig {

    private static Properties configFile = null;
    private String cryptoDeviceName;
    private Integer slot;

    public String getCryptoDeviceName() {
        return cryptoDeviceName;
    }

    public void setCryptoDeviceName(String cryptoDeviceName) {
        this.cryptoDeviceName = cryptoDeviceName;
    }

    public Integer getSlot() {
        return slot;
    }

    public void setSlot(Integer slot) {
        this.slot = slot;
    }

    public ByteArrayInputStream getCryptoDeviceConfigStream() throws IOException {

        if (configFile == null) {
            reloadConfigFile();
        }

        String libraryPath = null;
        String os = System.getProperty("os.name").toLowerCase();
        String arch = System.getProperty("os.arch").toLowerCase();
        
        //Buscamos la librería correcta, según el sistema operativo.
        if (os.contains("windows")) { // Windows OS
            libraryPath = configFile.getProperty(this.cryptoDeviceName + ".windows.library");
        } else if (os.contains("linux") || os.contains("unix")) { // Linux OS
            if (arch.contains("amd64") || arch.contains("x64") || arch.contains("x86_64")) {
                libraryPath = configFile.getProperty(this.cryptoDeviceName + ".linux.64.library");
            } else {
                libraryPath = configFile.getProperty(this.cryptoDeviceName + ".linux.32.library");
            }
        } else if (os.contains("mac os x")) { // Apple OS X
            libraryPath = configFile.getProperty(this.cryptoDeviceName + ".macosx.library");
        }

        if(libraryPath == null) {
            throw new IOException(String.format("Driver for device %s not exist.", this.cryptoDeviceName));
        }
        
        //Emulate a config file
        String pkcs11config = String.format("name=%s\nlibrary=%s", this.cryptoDeviceName, libraryPath);
        if (this.slot != null) {
            pkcs11config = pkcs11config + String.format("\nslot=%d", this.slot);
        }

        //TODO: agregar los parámetros extras
        Logger.debug(pkcs11config);
        byte[] pkcs11configBytes = pkcs11config.getBytes();
        return new ByteArrayInputStream(pkcs11configBytes);
    }

    private void reloadConfigFile() throws IOException {
        configFile = null;
        configFile = new Properties();
        configFile.load((new CryptoDeviceConfig()).getClass().getResourceAsStream("CryptoDeviceConfig.properties"));
    }
}
