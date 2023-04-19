/**
 * Copyright 2023 Rochester Institute of Technology (RIT). Developed with
 * government support under contract 70RSAT19CB0000020 awarded by the United
 * States Department of Homeland Security.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */
package edu.rit.se.nvip.utils.email;

import edu.rit.se.nvip.db.DatabaseHelper;
import edu.rit.se.nvip.utils.MyProperties;
import edu.rit.se.nvip.utils.PropertyLoader;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.jsoup.Jsoup;
import org.jsoup.nodes.Document;
import org.jsoup.nodes.Element;

import javax.mail.*;
import javax.mail.internet.*;

import java.io.*;
import java.sql.Date;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Properties;
import java.util.stream.Collectors;

public class EmailDailyCveList {

	private static final Logger logger = LogManager.getLogger(EmailDailyCveList.class.getSimpleName());
	private static final DatabaseHelper db = DatabaseHelper.getInstance();

	public static void main(String[] args) {
		EmailDailyCveList main = new EmailDailyCveList();
		logger.info("Emails module started!");
		if (args.length == 0) {
			main.sendCveNotificationEmailToSystemAdmin();
		} else {
			main.sendNotificationEmail(args[0]);
		}
		logger.info("Email module finished!");
	}

	/**
	 * Sends notification email to all admin email addresses in DB
	 */
	public boolean sendCveNotificationEmailToSystemAdmin() {
		try {
			ArrayList<ArrayList<String>> data = db.getEmailsRoleId();
			HashMap<String, String> newCves = db.getCVEByRunDate(new Date(System.currentTimeMillis()));
			if (newCves.size() > 0) {
				for (ArrayList<String> info : data) {
					if (Integer.parseInt(info.get(2)) == 1) {
						sendEmail(info.get(0), newCves);
					}
				}
			}
			return true;
		} catch (Exception e) {
			logger.error("ERROR: Failed to prepare and send email notification\n{}", e.toString());
		}
		return false;

	}

	/**
	 * Send notification to specified email
	 *
	 * @param username
	 */
	public void sendNotificationEmail(String username) {
		HashMap<String, String> newCves = db.getCVEByRunDate(new Date(System.currentTimeMillis()));
		ArrayList<String> userInfo = db.getEmailRoleIdByUser(username);

		if (!userInfo.isEmpty()) {
			if (newCves.size() > 0 && Integer.parseInt(userInfo.get(2)) == 1) {
				sendEmail(userInfo.get(0), newCves);
			}
		}

	}

	/**
	 * Send <newCves> to <toEmail>
	 * 
	 * @param toEmail
	 * @param newCves
	 */
	private void sendEmail(String toEmail, HashMap<String, String> newCves) {
		try {
			logger.info("Sending notification to " + toEmail);

			HashMap<String, String> emailParams = getPropValues();
			String location = emailParams.get("email_url");

			MimeMultipart content = new MimeMultipart("related");

			// Collect HTML Template
			String sFileContent;
			String fileName = "email/emailTemplate.html";
			ClassLoader classLoader = getClass().getClassLoader();
			try (InputStream is = classLoader.getResourceAsStream(fileName)) {
				try (InputStreamReader isr = new InputStreamReader(is); BufferedReader reader = new BufferedReader(isr)) {
					sFileContent = reader.lines().collect(Collectors.joining(System.lineSeparator()));
				}
			}
			Document doc = Jsoup.parse(sFileContent);
			int i = 0;

			// Apply HTML for every CVE
			for (String cveId : newCves.keySet()) {
				if (i >= 10) {
					break;
				}
				Element cveList = doc.select(".cve_list").first();
				cveList.append("<h3 class=\"cve_id\">" + cveId + "</h3>" + "   <p class=\"cve_description\">" + newCves.get(cveId) + "</p>" + "   <span><table><tr><td class=\"btn btn-primary\">"
						+ "       <div class=\"review_button\">" + "           <a style=\"color: #fff; text-decoration: none\" href=\"" + location + "#/review?cveid=" + cveId
						+ "&verd=accept\">ACCEPT CVE</a>" + "       </div></td></tr></table>" + "   <table><tr><td class=\"btn btn-primary\">" + "       <div class=\"review_button\">"
						+ "           <a style=\"color: #fff; text-decoration: none\" href=\"" + location + "#/review?cveid=" + cveId + "&verd=reject\">REJECT CVE</a>"
						+ "       </div></td></tr></table>" + "   <table><tr><td class=\"btn btn-primary\">" + "       <div class=\"review_button\">"
						+ "           <a style=\"color: #fff; text-decoration: none\" href=\"" + location + "#/review?cveid=" + cveId + "\">REVIEW CVE</a>" + "   </div></td></tr></table></span>");
				i++;
			}

			MimeBodyPart body = new MimeBodyPart();
			body.setContent(doc.toString(), "text/html; charset=ISO-8859-1");
			content.addBodyPart(body);

			sendFromEmailGeneric(toEmail, "Daily CVE Notification", doc.toString(), true);
			//sendFromGMail(paramsFromConfigFile.get("email_address"), paramsFromConfigFile.get("email_password"), toEmail, "Daily CVE Notification", doc.toString(), true);
			//logger.info("Message sent to successfully!", toEmail);
		} catch (AuthenticationFailedException e) {
			logger.error("ERROR: Username or Password for sending address is incorrect, please check your password in the config file!\n{} ", e.toString());
			e.printStackTrace();
		} catch (Exception e) {
			logger.error("ERROR: Failed to send email\n{}", e.toString());
			e.printStackTrace();
		}
	}

	/**
	 * Send email via javax.mail.Transport
	 *
	 * @param from
	 * @param pass
	 * @param to
	 * @param subject
	 * @param body
	 * @param asHtml
	 */
	public static void sendFromGMail(String from, String pass, String[] to, String subject, String body, boolean asHtml) throws MessagingException {
		Properties props = System.getProperties();
		String host = "smtp.gmail.com";
		props.put("mail.smtp.starttls.enable", "true");
		// added to fix javax.net.ssl.SSLHandshakeException: PKIX path building failed:
		props.put("mail.smtp.ssl.trust", "smtp.gmail.com");

		props.put("mail.smtp.host", host);
		props.put("mail.smtp.user", from);
		props.put("mail.smtp.password", pass);
		props.put("mail.smtp.port", "587");
		props.put("mail.smtp.auth", "true");

		// added to solve javax.net.ssl.SSLHandshakeException: No appropriate protocol
		props.put("mail.smtp.starttls.required", "true");
		props.put("mail.smtp.ssl.protocols", "TLSv1.2");
		props.put("mail.smtp.socketFactory.class", "javax.net.ssl.SSLSocketFactory");

		Session session = Session.getDefaultInstance(props);
		MimeMessage message = new MimeMessage(session);

		message.setFrom(new InternetAddress(from));
		InternetAddress[] toAddress = new InternetAddress[to.length];

		// To get the array of addresses
		for (int i = 0; i < to.length; i++) {
			toAddress[i] = new InternetAddress(to[i]);
		}

		for (int i = 0; i < toAddress.length; i++) {
			message.addRecipient(Message.RecipientType.TO, toAddress[i]);
		}

		message.setSubject(subject);

		if (asHtml)
			message.setContent(body, "text/html; charset=utf-8");
		else
			message.setText(body);

		Transport transport = session.getTransport("smtp");
		transport.connect(host, from, pass);
		transport.sendMessage(message, message.getAllRecipients());
		transport.close();
		logger.info("Sent {} email(s) with title: {}", to.length, subject);

	}

	/**
	 * Method used to extract email login properties from emailConfig.properties
	 * 
	 * @return
	 * @throws IOException
	 */
	private HashMap<String, String> getPropValues() {
		HashMap<String, String> props = new HashMap<>();
		try {
			// load nvip config file
			MyProperties propertiesNvip = new MyProperties();
			propertiesNvip = new PropertyLoader().loadConfigFile(propertiesNvip);
			props.put("email_from", System.getenv("NVIP_EMAIL_FROM"));
			props.put("email_user", System.getenv("NVIP_EMAIL_USER"));
			props.put("email_password", System.getenv("NVIP_EMAIL_PASSWORD"));
			props.put("email_port", System.getenv("NVIP_EMAIL_PORT"));
			props.put("email_url", System.getenv("NVIP_EMAIL_URL"));
			props.put("email_host", System.getenv("NVIP_EMAIL_HOST"));
		} catch (Exception e) {
			logger.error("ERROR: Failed to grab properties for NVIP Email\n{}", e.toString());
			e.printStackTrace();
		}

		return props;
	}


	/**
	 * Generic email function
	 * Credentials are in props
	 */
	public void sendFromEmailGeneric(String to, String subject, String body, boolean asHtml) {
		HashMap<String, String> vars = getPropValues();
		String username = vars.get("email_user");
		String password = vars.get("email_password");

		Properties props = new Properties();
		props.put("mail.transport.protocol", "smtp");
		props.put("mail.smtp.port", vars.get("email_port"));
		props.put("mail.smtp.auth", "true");
		props.put("mail.smtp.starttls.enable", "true");
		props.put("mail.smtp.host", vars.get("email_host"));
		Authenticator auth = new Authenticator() {
			protected PasswordAuthentication getPasswordAuthentication() {
				return new PasswordAuthentication(username, password);
			}
		};
		Session session = Session.getDefaultInstance(props, auth);

		MimeMessage message = new MimeMessage(session);
		try {
			message.setFrom(new InternetAddress(vars.get("email_address")));
			message.setRecipient(Message.RecipientType.TO, new InternetAddress(to));
			message.setSubject(subject);

			if (asHtml)
				message.setContent(body, "text/html; charset=utf-8");
			else
				message.setText(body);

			Transport.send(message);
			logger.info("Sent email to {}", to);
		} catch (Exception e) {
			logger.error("ERROR: Failed to prepare email for daily notifications\n{}", e.toString());
			e.printStackTrace();
		}

	}


}
