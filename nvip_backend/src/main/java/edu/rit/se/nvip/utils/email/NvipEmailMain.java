package edu.rit.se.nvip.utils.email;

import edu.rit.se.nvip.db.DatabaseHelper;
import org.apache.commons.io.IOUtils;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.jsoup.Jsoup;
import org.jsoup.nodes.Document;
import org.jsoup.nodes.Element;

import javax.mail.*;
import javax.mail.internet.InternetAddress;
import javax.mail.internet.MimeBodyPart;
import javax.mail.internet.MimeMessage;
import javax.mail.internet.MimeMultipart;

import java.io.*;
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
        ArrayList<String> data = db.getEmailsRoleId();
        HashMap<String, String> newCves = db.getCVEByRunDate(new Date(System.currentTimeMillis()));

        if (newCves.size() > 0) {
            for (String info : data) {

                String[] userData = info.split(";!;~;#&%:;!");
                if (Integer.parseInt(userData[2]) == 1) {
                    sendEmail(userData[0], userData[1], newCves);
                }
            }
        }

    }


    /**
     * Send notification to specified email
     *
     * @param username
     */
    public static void sendNotificationEmail(String username) {
        HashMap<String, String> newCves = db.getCVEByRunDate(new Date(System.currentTimeMillis()));
        ArrayList<String> userInfo = db.getEmailRoleIdByUser(username);

        if (!userInfo.isEmpty()) {
            String[] userData = userInfo.get(0).split(";!;~;#&%:;!");
            if (newCves.size() > 0 && Integer.parseInt(userData[2]) == 1) {
                sendEmail(userData[0], userData[1], newCves);
            }
        }
    }


    /**
     * Reused function to send email
     *
     * @param emailAddress
     */
    private static void sendEmail(String emailAddress, String name, HashMap<String, String> newCves) {
        try {
            logger.info("Sending notifcation to " + emailAddress);

            //Initialize Session
            Properties prop = System.getProperties();
            prop.put("mail.smtp.auth", true);
            prop.put("mail.smtp.starttls.enable", "true");
            prop.put("mail.smtp.ssl.trust", "smtp.gmail.com");
            prop.put("mail.smtp.host", "smtp.gmail.com");
            prop.put("mail.smtp.port", "25");
            prop.put("mail.smtp.debug", "true");


            HashMap<String, String> login = getPropValues();
            Session session;

            //Check if the properties are valid, if not then do not continue
            if (!login.isEmpty()) {
                session = Session.getDefaultInstance(prop,
                        new Authenticator() {
                            @Override
                            protected PasswordAuthentication getPasswordAuthentication() {
                                return new PasswordAuthentication(login.get("email"), login.get("password"));
                            }
                        });
            } else {
                logger.error("Properties not found for email login");
                return;
            }
            //Prepare Message
            MimeMessage message = new MimeMessage(session);
            message.setFrom(new InternetAddress(login.get("email")));
            message.addRecipient(Message.RecipientType.TO, new InternetAddress(emailAddress));
            message.setSubject("Daily CVE Notification");

            MimeMultipart content = new MimeMultipart("related");

            //Prepare NVIP Logo image
            /*
            MimeBodyPart image = new MimeBodyPart();
            image.setHeader("Content-ID", "AbfKrOw");
            image.setDisposition(MimeBodyPart.INLINE);
            image.attachFile("./src/main/resources/email/emailTemplate.html");
            content.addBodyPart(image);
            */

            //Collect HTML Template
            StringWriter writer = new StringWriter();
            IOUtils.copy(new FileInputStream(new File("./src/main/resources/email/emailTemplate.html")), writer);

            Document doc = Jsoup.parse(writer.toString());

            //Add users name to email header
            Element header = doc.select(".main_header").first();
            header.appendText(" " + name);

            int i = 0;
            String location = login.get("location");

            //Apply HTML for every CVE
            for (String cveId : newCves.keySet()) {

                if (i >= 20) {
                    break;
                }

                Element cveList = doc.select(".cve_list").first();
                cveList.append("<h3 class=\"cve_id\">" + cveId + "</h3>" +
                        "   <p class=\"cve_description\">" + newCves.get(cveId) + "</p>" +
                        "   <span><table><tr><td class=\"btn btn-primary\">" +
                        "       <div class=\"review_button\">" +
                        "           <a style=\"color: #fff; text-decoration: none\" href=\"" + location + "#/review?cveid=" + cveId + "&verd=accept\">ACCEPT CVE</a>" +
                        "       </div></td></tr></table>" +
                        "   <table><tr><td class=\"btn btn-primary\">" +
                        "       <div class=\"review_button\">" +
                        "           <a style=\"color: #fff; text-decoration: none\" href=\"" + location + "#/review?cveid=" + cveId + "&verd=reject\">REJECT CVE</a>" +
                        "       </div></td></tr></table>" +
                        "   <table><tr><td class=\"btn btn-primary\">" +
                        "       <div class=\"review_button\">" +
                        "           <a style=\"color: #fff; text-decoration: none\" href=\"" + location + "#/review?cveid=" + cveId + "\">REVIEW CVE</a>" +
                        "   </div></td></tr></table></span>");
                i++;
            }

            MimeBodyPart body = new MimeBodyPart();
            body.setContent(doc.toString(), "text/html; charset=ISO-8859-1");
            content.addBodyPart(body);

            message.setContent(doc.toString(), "text/html");

            Transport.send(message);
            logger.info("Message sent successfully!");
        } catch (Exception e) {
            logger.error(e.toString());
        }
    }

    /**
     * Method used to extract email login properties from emailConfig.properties
     * @return
     * @throws IOException
     */
    private static HashMap<String, String> getPropValues() {

        HashMap<String, String> props = new HashMap<>();

        try {
            Properties properties = new Properties();
            FileInputStream input = new FileInputStream(new File("src/main/resources/nvip.properties"));
            properties.load(input);
            props.put("email", properties.getProperty("Email"));
            props.put("password", properties.getProperty("Password"));
            props.put("location", properties.getProperty("location"));
            input.close();
        } catch (Exception e) {
            logger.error(e.toString());
        }

        return props;
    }
}
