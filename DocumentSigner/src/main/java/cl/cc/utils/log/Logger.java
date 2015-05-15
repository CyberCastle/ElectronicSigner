package cl.cc.utils.log;

import cl.cc.config.ConfigHandler;
import java.io.PrintWriter;
import java.io.StringWriter;

/**
 *
 * @author CyberCastle
 * @Desc Pequeña clase para manejar logs....
 */
public final class Logger {

    private final static StringBuffer logText;
    private static OutputLog outLog;

    static {
        logText = new StringBuffer();
    }

    private Logger() {
    }

    public static void setOutputLog(OutputLog oLog) {
        outLog = oLog;
    }

    public static void clear() {
        logText.delete(0, logText.length() - 1);
    }

    public static void info(String txt) {
        logText.append("[INFO] ").append(txt).append("\n");
        printLog();
    }

    public static void warn(String txt) {
        logText.append("[WARN] ").append(txt).append("\n");
        printLog();
    }

    public static void warn(String txt, Exception e) {
        logText.append("[WARN] ").append(txt).append(":\n");
        logText.append(e.getMessage()).append(ExceptionTraceToString(e)).append("\n");
        printLog();
    }

    public static void error(String txt) {
        logText.append("[ERROR] ").append(txt).append("\n");
        printLog();
    }

    public static void error(String txt, Exception e) {
        logText.append("[ERROR] ").append(txt).append(":\n");
        logText.append(e.getMessage()).append(ExceptionTraceToString(e)).append("\n");
        printLog();
    }

    public static void debug(String txt) {
        logText.append("[DEBUG] ").append(txt).append("\n");
        printLog();
    }

    public static void debug(String txt, Exception e) {
        logText.append("[DEBUG] ").append(txt).append(":\n");
        logText.append(e.getMessage()).append(ExceptionTraceToString(e)).append("\n");
        printLog();
    }

    private static String ExceptionTraceToString(Exception e) {
        StringWriter sw = new StringWriter();
        PrintWriter pw = new PrintWriter(sw, true);
        e.printStackTrace(pw);
        return sw.toString();
    }

    private static void printLog() {
        if (outLog != null && ConfigHandler.getProperty("logger.output.mode").equals("internal")) {
            outLog.print(logText.toString());
        } else {
            System.out.println(logText.toString());
            clear();
        }
    }

    public static abstract class OutputLog {

        public abstract void print(String logMsg);
    }
}
