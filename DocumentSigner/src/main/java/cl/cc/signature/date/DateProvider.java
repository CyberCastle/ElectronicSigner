package cl.cc.signature.date;

import cl.cc.connection.ntp.NTPClient;
import cl.cc.config.ConfigHandler;
import java.io.IOException;
import java.util.Calendar;
import java.util.Date;
import java.util.GregorianCalendar;

/**
 *
 * @author CyberCastle
 */
public final class DateProvider {

    private DateProvider() {
    }

    public static Date getNowDate() throws DateProviderException {
        Date now = new Date();
        try {
            if (ConfigHandler.getProperty("date.signature.from").equals("ntp")) {
                NTPClient ntp = new NTPClient(ConfigHandler.getProperty("ntp.server.address"),
                        Integer.parseInt(ConfigHandler.getProperty("ntp.server.port")));
                now = ntp.getCurrentTimeDate();
            }
        } catch (NumberFormatException | IOException e) {
            if (ConfigHandler.getProperty("date.signature.ntp.strict").equals("yes")) {
                throw new DateProviderException(e);
            }
        }

        return now;
    }

    public static Calendar getNowCalendar() throws DateProviderException {
        Calendar c = new GregorianCalendar();
        c.setTime(getNowDate());
        return c;
    }
}
