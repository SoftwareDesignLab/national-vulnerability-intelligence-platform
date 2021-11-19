/**
 * Copyright 2021 Rochester Institute of Technology (RIT). Developed with
 * government support under contract 70RSAT19CB0000020 awarded by the United
 * States Department of Homeland Security.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the �Software�), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED �AS IS�, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
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
	 * Sends notification email to all emails in DB
	 */
	public boolean sendCveNotificationEmailToSystemAdmin() {
		try {
			ArrayList<String> data = db.getEmailsRoleId();
			HashMap<String, String> newCves = db.getCVEByRunDate(new Date(System.currentTimeMillis()));
			logger.info("Sending {} CVEs to {} users!...", newCves.size(), data.size());
			if (newCves.size() > 0) {
				for (String info : data) {

					String[] userData = info.split(";!;~;#&%:;!");
					if (Integer.parseInt(userData[2]) == 1) {
						sendEmail(userData[0], userData[1], newCves);
					}
				}
			}
			logger.info("Done sending {} CVEs to {} users!", newCves.size(), data.size());
			return true;
		} catch (NumberFormatException e) {
			logger.error("Error sending email {}", e);
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
	private void sendEmail(String emailAddress, String name, HashMap<String, String> newCves) {
		try {
			logger.info("Sending notification to " + emailAddress);

			// Initialize Session
			Properties prop = System.getProperties();
			prop.put("mail.smtp.auth", true);
			prop.put("mail.smtp.starttls.enable", "true");
			prop.put("mail.smtp.ssl.trust", "smtp.gmail.com");
			prop.put("mail.smtp.host", "smtp.gmail.com");
			prop.put("mail.smtp.port", "25");
			prop.put("mail.smtp.debug", "true");

			HashMap<String, String> login = getPropValues();
			Session session;

			// Check if the properties are valid, if not then do not continue
			if (!login.isEmpty()) {
				session = Session.getDefaultInstance(prop, new Authenticator() {
					@Override
					protected PasswordAuthentication getPasswordAuthentication() {
						return new PasswordAuthentication(login.get("email"), login.get("password"));
					}
				});
			} else {
				logger.error("Properties not found for email login");
				return;
			}
			// Prepare Message
			MimeMessage message = new MimeMessage(session);
			message.setFrom(new InternetAddress(login.get("email")));
			message.addRecipient(Message.RecipientType.TO, new InternetAddress(emailAddress));
			message.setSubject("Daily CVE Notification");

			MimeMultipart content = new MimeMultipart("related");

			// Collect HTML Template
			String sFileContent = null;
			String fileName = "email/emailTemplate.html";
			ClassLoader classLoader = getClass().getClassLoader();
			try (InputStream is = classLoader.getResourceAsStream(fileName)) {
				try (InputStreamReader isr = new InputStreamReader(is); BufferedReader reader = new BufferedReader(isr)) {
					sFileContent = reader.lines().collect(Collectors.joining(System.lineSeparator()));
				}
			}
			Document doc = Jsoup.parse(sFileContent);

			// Add users name to email header
			Element header = doc.select(".main_header").first();
			header.appendText(" " + name);

			int i = 0;
			String location = login.get("location");

			// Apply HTML for every CVE
			for (String cveId : newCves.keySet()) {

				if (i >= 20) {
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

			message.setContent(doc.toString(), "text/html");

			Transport.send(message);
			logger.info("Message sent successfully!");
		} catch (AuthenticationFailedException e) {
			logger.error("Password for Email is incorrect");
		} catch (Exception e) {
			logger.error(e.toString());
		}
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
			props.put("email", propertiesNvip.getProperty("Email"));
			props.put("password", propertiesNvip.getProperty("Password"));
			props.put("location", propertiesNvip.getProperty("location"));
		} catch (Exception e) {
			logger.error(e.toString());
		}

		return props;
	}
}
