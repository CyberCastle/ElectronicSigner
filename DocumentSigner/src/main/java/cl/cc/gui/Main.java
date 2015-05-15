package cl.cc.gui;

import cl.cc.config.ConfigHandler;
import static cl.cc.gui.SignEngine.DEFAULT_ALIAS;
import cl.cc.utils.log.Logger;
import java.awt.EventQueue;
import java.io.File;
import java.lang.reflect.InvocationTargetException;
import java.security.AccessControlException;
import java.security.AccessController;
import java.security.PrivilegedAction;
import java.util.HashMap;
import java.util.LinkedHashSet;
import java.util.Map;
import java.util.Set;
import javax.swing.GroupLayout;
import javax.swing.JApplet;
import javax.swing.JScrollPane;
import javax.swing.JTextArea;
import netscape.javascript.JSException;
import netscape.javascript.JSObject;

/**
 *
 * @author CyberCastle
 */
public class Main extends JApplet {

    private static final long serialVersionUID = 5587039635215735365L;
    private final SignEngine engine;
    private JSObject jsObject;

    public Main() {
        // Inicializamos el objeto que tiene toda la lógica de firmado
        this.engine = new SignEngine();
    }

    /* Ciclo de Vida del Applet */
    @Override
    public void init() {
        /* Create and display the applet */
        try {
            EventQueue.invokeAndWait(new Runnable() {
                @Override
                public void run() {
                    initComponents();
                }
            });
        } catch (InterruptedException | InvocationTargetException ex) {
            ex.printStackTrace(System.err);
        }
        /* Inicializamos el Logger */
        Logger.setOutputLog(new Logger.OutputLog() {

            @Override
            public void print(String logMsg) {
                logTextArea.setText(logMsg);
            }
        });

        /* Habilitación la interacción con JavaScript */
        try {
            this.jsObject = JSObject.getWindow(this);
        } catch (JSException e) {
            Logger.error("No es posible inicializar LiveConnect.", e);
            Logger.error("Aplicación no funcionará correctamete");
        }

        /* Validamos que el certificado haya sido aceptado */
        try {
            String tmpPath = System.getProperty("java.io.tmpdir");
            this.engine.setTmpFolder(tmpPath);
        } catch (AccessControlException e) {
            Logger.error("El certificado de la Aplicación no ha sido aceptado. Aplicación no cargada.", e);
            this.showAlert("El certificado de la Aplicación no ha sido aceptado. Aplicación no cargada.");
        }
    }

    @Override
    public void start() {
        this.enableSigner();
    }

    @Override
    public void stop() {
        AccessController.doPrivileged(new PrivilegedAction() {
            @Override
            public Object run() {
                try {
                    // Cerramos el almacén de certificados
                    engine.closeKeyStore();
                } catch (Exception e) {
                    e.printStackTrace(System.err);
                }
                return null;
            }
        });
    }

    @Override
    public void destroy() {
        AccessController.doPrivileged(new PrivilegedAction() {
            @Override
            public Object run() {
                try {
                    // Realizamos la limpieza de rigor
                    engine.deleteTmpFolder();
                } catch (Exception e) {
                    e.printStackTrace(System.err);
                }
                return null;
            }
        });
    }
    // --

    public void setUrlBase(String urlBase) {
        this.engine.setUrlBase(urlBase);
    }

    public void setServiceName(String serviceName) {
        this.engine.setServiceName(serviceName.toLowerCase());
    }

    // Método para descargar, firmar y subir documentos.
    // Los ids de los archivos deben estar separados por coma ","
    public void sign(final String userName, final String password, final String idFiles) {
        this.openProgressDialog("Comenzando la descarga de los documentos...");

        AccessController.doPrivileged(new PrivilegedAction() {
            @Override
            @SuppressWarnings("UseSpecificCatch")
            public Object run() {

                // Captura de todos los errores no controlados (por sanidad mental).
                // Y NO, NO es feo.
                try {

                    Map<String, File> downladedDocuments;
                    Map<String, File> signedDocuments = new HashMap<>();
                    Map<String, File> uploadedDocuments = new HashMap<>();
                    try {
                        // Sanitanización de los ids
                        String[] _documentsIds = idFiles.split(",");
                        Set<String> documentsIds = new LinkedHashSet<>();
                        for (String documentsId : _documentsIds) {
                            documentsIds.add(documentsId.trim().toLowerCase());
                        }

                        // Descargando los documentos
                        downladedDocuments = engine.downloadFiles(documentsIds);
                    } catch (SignEngineException e) {
                        Logger.error("Error al descargar los documentos.", e);
                        return null;
                    }

                    // Abrimos el almacén de certificados
                    updateProgressDialogText("Leyendo el almacén de certificados...");
                    try {
                        Integer signType = Integer.parseInt(ConfigHandler.getProperty("signature.default.type"));
                        engine.openKeyStore(signType, password);
                    } catch (SignEngineException e) {
                        Logger.error("Error al acceder al cerificado, contraseña incorrecta.", e);
                        showAlert("Error al acceder al cerificado, contraseña incorrecta.");

                        // Imposible acceder, por lo que abortamos misión.
                        return null;
                    }

                    // Firmamos los documentos
                    updateProgressDialogText("Comenzando el firmado de los documentos...");
                    try {
                        signedDocuments = engine.signDocuments(SignEngine.DEFAULT_ALIAS, downladedDocuments);
                    } catch (SignEngineException e) {
                        Logger.error("Error al firmar los documentos.", e);
                    }

                    // Subimos los documentos
                    updateProgressDialogText("Comenzando la subida de los documentos...");
                    try {
                        uploadedDocuments = engine.uploadFiles(userName, signedDocuments);
                    } catch (SignEngineException e) {
                        Logger.error("Error al subir los documentos.", e);
                    }
                    closeProgressDialog(String.format("Se ha finalizado correctamente la firma de %d documentos.", uploadedDocuments.size()));

                } catch (Exception e) {
                    Logger.error("Se ha producido un error no controlado en el proceso de firma.", e);
                }
                return null;
            }
        });
    }

    // Método para verificar que el dispositivo criptográfico sea accesible
//    public Boolean checkCryptoDevice() {
//        return (Boolean) AccessController.doPrivileged(new PrivilegedAction() {
//            @Override
//            public Object run() {
//                try {
//                    return engine.checkCryptoDevice();
//                } catch (Exception e) {
//                    Logger.error("Error al acceder al dispositivo criptográfico.", e);
//                }
//                return false;
//            }
//        });
//    }
    // Método para verificar si la clave privada es extraíble.
    public Boolean pkIsExtractable(final String password) {
        return (Boolean) AccessController.doPrivileged(new PrivilegedAction() {
            @Override
            public Object run() {
                try {
                    engine.openKeyStore(0, password);
                    engine.signDocuments(DEFAULT_ALIAS, new HashMap<String, File>());
                    Boolean result = engine.isExtractable();
                    engine.closeKeyStore();
                    return result;
                } catch (Exception e) {
                    Logger.error("Error al acceder al dispositivo criptográfico.", e);
                }
                return false;
            }
        });
    }

    @SuppressWarnings("unchecked")
    private void initComponents() {//GEN-BEGIN:initComponents

        logScrollPane = new JScrollPane();
        logTextArea = new JTextArea();

        logScrollPane.setName("logScrollPane"); // NOI18N

        logTextArea.setColumns(20);
        logTextArea.setRows(5);
        logTextArea.setName("logTextArea"); // NOI18N
        logScrollPane.setViewportView(logTextArea);

        GroupLayout layout = new GroupLayout(getContentPane());
        getContentPane().setLayout(layout);
        layout.setHorizontalGroup(layout.createParallelGroup(GroupLayout.Alignment.LEADING)
            .addGroup(layout.createSequentialGroup()
                .addContainerGap()
                .addComponent(logScrollPane, GroupLayout.DEFAULT_SIZE, 650, Short.MAX_VALUE)
                .addContainerGap())
        );
        layout.setVerticalGroup(layout.createParallelGroup(GroupLayout.Alignment.LEADING)
            .addGroup(layout.createSequentialGroup()
                .addContainerGap()
                .addComponent(logScrollPane, GroupLayout.DEFAULT_SIZE, 370, Short.MAX_VALUE)
                .addContainerGap())
        );
    }//GEN-END:initComponents

    /* Máscaras para funciones JavaScript */
    private void enableSigner() {
        this.execJSCmd("enableSigner();");
    }

    private void openProgressDialog(String text) {
        this.execJSCmd(String.format("openProgressDialog('%s');", text));
    }

    private void updateProgressDialogText(String text) {
        this.execJSCmd(String.format("updateProgressDialogText('%s');", text));
    }

    private void closeProgressDialog(String text) {
        this.execJSCmd(String.format("closeProgressDialog('%s');", text));
    }

    private void showAlert(String text) {
        this.execJSCmd(String.format("showAlert('%s');", text));
    }

    private void execJSCmd(String fn) {
        if (this.jsObject != null) {
            try {
                this.jsObject.eval(fn);
            } catch (JSException e) {
                Logger.error("Error al ejecutar la rutina JS.", e);
            }
        }
    }
    // --

    // Variables declaration - do not modify//GEN-BEGIN:variables
    private JScrollPane logScrollPane;
    private JTextArea logTextArea;
    // End of variables declaration//GEN-END:variables

}
