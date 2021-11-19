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
	 * Sends notification email to all admin email addresses in DB
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
						sendEmailV2(userData[0], newCves);
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
				sendEmailV2(userData[0], newCves);
			}
		}
	}

	/**
	 * Send <newCves> to <toEmail>
	 * 
	 * @param toEmail
	 * @param newCves
	 */
	private void sendEmailV2(String toEmail, HashMap<String, String> newCves) {
		try {
			logger.info("Sending notification to " + toEmail);

			HashMap<String, String> paramsFromConfigFile = getPropValues();
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
			int i = 0;
			String location = paramsFromConfigFile.get("location");

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

			sendFromGMail(paramsFromConfigFile.get("email"), paramsFromConfigFile.get("password"), new String[] { toEmail }, "Daily CVE Notification", doc.toString(), true);
			logger.info("Message sent to successfully!", toEmail);
		} catch (AuthenticationFailedException e) {
			logger.error("Password for {} is incorrect, please check your password in the config file!", toEmail);
		} catch (Exception e) {
			logger.error(e.toString());
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
	public static void sendFromGMail(String from, String pass, String[] to, String subject, String body, boolean asHtml) {
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

		try {
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
		} catch (Exception e) {
			logger.error("Error while sending email, {}", e.toString());
			e.printStackTrace();

		}
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
			props.put("email", propertiesNvip.getProperty("Email"));
			props.put("password", propertiesNvip.getProperty("Password"));
			props.put("location", propertiesNvip.getProperty("location"));
		} catch (Exception e) {
			logger.error(e.toString());
		}

		return props;
	}
}
