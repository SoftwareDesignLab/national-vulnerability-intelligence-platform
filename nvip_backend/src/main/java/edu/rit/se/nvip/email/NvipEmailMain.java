package edu.rit.se.nvip.email;

import edu.rit.se.nvip.db.DatabaseHelper;
import org.apache.commons.io.IOUtils;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.jsoup.Jsoup;
import org.jsoup.nodes.Document;
import org.jsoup.nodes.Element;

import javax.mail.*;
import javax.mail.internet.InternetAddress;
import javax.mail.internet.MimeMessage;

import java.io.File;
import java.io.FileInputStream;
import java.io.StringWriter;
import java.sql.Date;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Properties;

public class NvipEmailMain {

    private static final Logger logger = LogManager.getLogger(NvipEmailMain.class.getSimpleName());
    private static final DatabaseHelper db = DatabaseHelper.getInstance();
    private static final String CVEHTML = "";

    public static void main(String[] args) {
        logger.info("Emails module started!");
        if (args.length == 0) {
            sendNotificationEmail();
        } else {
            sendNotificationEmail(args[0], args[1]);
        }
        logger.info("Email module finished!");
    }

    /**
     * Sends notification email to all emails in DB
     */
    public static void sendNotificationEmail() {
        ArrayList<String> data = db.getEmails();
        HashMap<String, String> newCves = db.getCVEByRunDate(new Date(System.currentTimeMillis()));

        if (newCves.size() > 0) {
            for (String info : data) {

                String[] userData = info.split(";!;~;#&%:;!");

                sendEmail(userData[0], userData[1], newCves);
            }
        }

    }


    /**
     * Send notification to specified email
     * @param emailAddress
     */
    public static void sendNotificationEmail(String emailAddress, String name) {
        HashMap<String, String> newCves = db.getCVEByRunDate(new Date(System.currentTimeMillis()));
        if (newCves.size() > 0) {
            sendEmail(emailAddress, name, newCves);
        }
    }


    /**
     * Reused function to send email
     * @param emailAddress
     */
    private static void sendEmail(String emailAddress, String name, HashMap<String, String> newCves) {
        try {
            logger.info("Sending notifcation to " + emailAddress);
            Properties prop = System.getProperties();
            prop.put("mail.smtp.auth", true);
            prop.put("mail.smtp.starttls.enable", "true");
            prop.put("mail.smtp.ssl.trust", "smtp.gmail.com");
            prop.put("mail.smtp.host", "smtp.gmail.com");
            prop.put("mail.smtp.port", "25");
            prop.put("mail.smtp.debug", "true");
            Session session = Session.getDefaultInstance(prop,
                    new Authenticator() {
                        @Override
                        protected PasswordAuthentication getPasswordAuthentication() {
                            return new PasswordAuthentication("username", "password");
                        }
                    });

            MimeMessage message = new MimeMessage(session);
            message.setFrom(new InternetAddress("PandaPickard@gmail.com"));
            message.addRecipient(Message.RecipientType.TO, new InternetAddress(emailAddress));
            message.setSubject("Daily CVE Notification");

            StringWriter writer = new StringWriter();
            IOUtils.copy(new FileInputStream(new File("./src/main/java/edu/rit/se/nvip/email/emailTemplate.html")), writer);

            Document doc = Jsoup.parse(writer.toString());

            Element header = doc.select(".main_header").first();
            header.appendText(" "+name);

            for (String cveId : newCves.keySet()) {
                Element cveList = doc.select(".cve_list").first();
                cveList.append("<li>\n" +
                        "                <h3 class=\"cve_id\">" + cveId + "</h3>\n" +
                        "                <p class=\"cve_description\">" + newCves.get(cveId) + "</p>\n" +
                        "                <button type=\"button\" class=\"btn btn-primary accept_cve\">ACCEPT CVE</button>\n" +
                        "                <button type=\"button\" class=\"btn btn-primary accept_cve\">REJECT CVE</button>\n" +
                        "                <button type=\"button\" class=\"btn btn-primary accept_cve\">REVIEW CVE</button>\n" +
                        "            </li>");
            }

            message.setContent(doc.toString(), "text/html");
            Transport.send(message);
            logger.info("Message sent successfully!");
        } catch (Exception e) {
            logger.error(e);
        }
    }

}
