package cl.cc.connection.http;

import cl.cc.utils.log.Logger;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.HttpURLConnection;
import java.net.URL;

/**
 * A utility that downloads a file from a URL.
 *
 * @author www.codejava.net
 *
 */
public class HttpDownloadUtility {

    private static final int BUFFER_SIZE = 4096;

    /**
     * Downloads a file from a URL
     *
     * @param fileURL HTTP URL of the file to be downloaded
     * @param saveDir path of the directory to save the file
     * @throws IOException
     */
    public static String downloadFile(String fileURL, String saveDir) throws IOException {
        URL url = new URL(fileURL);
        HttpURLConnection httpConn = (HttpURLConnection) url.openConnection();
        int responseCode = httpConn.getResponseCode();
        String fileName = "";
        
        Logger.debug("Executing download URL: " + fileURL);
        
        // Always check HTTP response code first
        if (responseCode != HttpURLConnection.HTTP_OK) {
            httpConn.disconnect();
            throw new IOException("No file to download. Server replied HTTP code: " + responseCode);
        }

        // Ok, continuing....
        String disposition = httpConn.getHeaderField("Content-Disposition");
        String contentType = httpConn.getContentType();
        int contentLength = httpConn.getContentLength();

        if (disposition != null) {
            // extracts file name from header field
            int index = disposition.indexOf("filename=");
            if (index > 0) {
                fileName = disposition.substring(index + 10,
                        disposition.length() - 1);
            }
        } else {
            // extracts file name from URL
            fileName = fileURL.substring(fileURL.lastIndexOf("/") + 1,
                    fileURL.length());
        }

        Logger.debug("Content-Type = " + contentType);
        Logger.debug("Content-Disposition = " + disposition);
        Logger.debug("Content-Length = " + contentLength);
        Logger.debug("fileName = " + fileName);

        // Opens input stream from the HTTP connection
        try (InputStream inputStream = httpConn.getInputStream()) {
            String saveFilePath = saveDir + File.separator + fileName;

            // Opens an output stream to save into file
            try (FileOutputStream outputStream = new FileOutputStream(saveFilePath)) {
                int bytesRead;
                byte[] buffer = new byte[BUFFER_SIZE];
                while ((bytesRead = inputStream.read(buffer)) != -1) {
                    outputStream.write(buffer, 0, bytesRead);
                }
            }
        }

        Logger.info("File " + fileName + " downloaded.");
        httpConn.disconnect();
        return fileName;
    }
}
