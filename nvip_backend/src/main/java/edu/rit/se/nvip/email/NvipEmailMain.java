package edu.rit.se.nvip.email;



import edu.rit.se.nvip.db.DatabaseHelper;
import org.apache.commons.io.IOUtils;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

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

    public static void main(String[] args) {
        logger.info("Emails module started!");
        if (args.length == 0) {
            sendNotificationEmail();
        } else {
            sendNotificationEmail(args[0]);
        }
        logger.info("Email module finished!");
    }

    /**
     * Sends notification email to all emails in DB
     */
    public static void sendNotificationEmail() {
        ArrayList<String> emails = db.getEmails();
        HashMap<String, String> newCves = db.getCVEByRunDate(new Date(System.currentTimeMillis()));

        for (String email : emails) {
            sendEmail(email);
        }

    }


    /**
     * Send notification to specified email
     * @param emailAddress
     */
    public static void sendNotificationEmail(String emailAddress) {
        HashMap<String, String> newCves = db.getCVEByRunDate(new Date(System.currentTimeMillis()));
        sendEmail(emailAddress);
    }


    /**
     * Reused function to send email
     * @param emailAddress
     */
    private static void sendEmail(String emailAddress) {
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
            IOUtils.copy(new FileInputStream(new File("home.html")), writer);

            

            message.setContent(writer.toString(), "text/html");
            Transport.send(message);
            logger.info("Message sent successfully!");
        } catch (Exception e) {
            logger.error(e.getMessage());
        }
    }

}
