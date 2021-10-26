package edu.rit.se.nvip.email;

import edu.rit.se.nvip.db.DatabaseHelper;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import javax.mail.*;
import javax.mail.internet.InternetAddress;
import javax.mail.internet.MimeMessage;
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
            Properties properties = System.getProperties();
            properties.setProperty("mail.smtp.host", "localhost");
            Session session = Session.getDefaultInstance(properties);
            MimeMessage message = new MimeMessage(session);
            message.setFrom(new InternetAddress("admin@cve.live"));
            message.addRecipient(Message.RecipientType.TO, new InternetAddress(emailAddress));
            message.setSubject("Daily CVE Notification");
            message.setText("Hello There :D");
            Transport.send(message);
            logger.info("Message sent successfully!");
        } catch (Exception e) {
            logger.error(e.getMessage());
        }
    }

}
