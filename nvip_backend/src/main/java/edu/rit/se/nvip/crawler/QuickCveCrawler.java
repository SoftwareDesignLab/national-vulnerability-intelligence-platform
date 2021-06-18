package edu.rit.se.nvip.crawler;

import java.io.BufferedReader;
import java.io.File;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.MalformedURLException;
import java.net.SocketException;
import java.net.URL;
import java.text.DateFormat;
import java.text.SimpleDateFormat;
import java.time.LocalDate;
import java.time.temporal.IsoFields;
import java.util.ArrayList;
import java.util.Calendar;
import java.util.Date;
import java.util.List;
import java.util.Random;

import javax.net.ssl.SSLException;

import org.apache.commons.io.FileUtils;
import org.apache.commons.io.IOUtils;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.jsoup.Jsoup;
import org.jsoup.nodes.Document;
import org.jsoup.nodes.Element;
import org.jsoup.select.Elements;

import edu.rit.se.nvip.cnnvd.CnnvdCveController;
import edu.rit.se.nvip.cnnvd.CnnvdCveParser;
import edu.rit.se.nvip.cnnvd.CnnvdCveController.CnnvdPageProcessor;
import edu.rit.se.nvip.model.CnnvdVulnerability;
import edu.rit.se.nvip.model.CompositeVulnerability;
import edu.rit.se.nvip.utils.MyProperties;
import edu.rit.se.nvip.utils.PropertyLoader;
import edu.rit.se.nvip.utils.UtilHelper;

/**
 * This class scrapes most recent CVEs from a list of known sources quickly:
 * 
 * Examples: https://www.tenable.com/cve/newest
 * https://packetstormsecurity.com/files/date/yyyy-MM-dd/
 * 
 * @author axoeec
 *
 */
public class QuickCveCrawler {
	private Logger logger = LogManager.getLogger(getClass().getSimpleName());
	private static final String USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/87.0.4280.141 Safari/537.36";

	public List<CompositeVulnerability> getCVEsfromKnownSummaryPages() {

		MyProperties propertiesNvip = new MyProperties();
		propertiesNvip = new PropertyLoader().loadConfigFile(propertiesNvip);
		CveCrawler crawler = new CveCrawler(propertiesNvip);

		List<CompositeVulnerability> list = new ArrayList<>();

		// Seclists
		getSeclistsCveUpdates(crawler, list);

		// Cnnvd
		getCnnvdCveUpdates(list);

		// packet storm
		getPacketStrormCveUpdates(crawler, list);

		// Tenable
		getTenableCveUpdates(crawler, list);

		return list;
	}

	/**
	 * Scrape Packetstorm
	 * 
	 * @param crawler
	 * @param list
	 * @return
	 */
	public List<CompositeVulnerability> getPacketStrormCveUpdates(CveCrawler crawler, List<CompositeVulnerability> list) {
		try {
			String url = "https://packetstormsecurity.com/files/date/";
			DateFormat dateFormat = new SimpleDateFormat("yyyy/MM/dd");
			Calendar cal = Calendar.getInstance();
			int count = list.size();

			for (int day = 1; day < 7; day++) {
				cal.add(Calendar.DATE, -1 * day);
				String date = dateFormat.format(cal.getTime());
				String link = url + date;
				logger.info("Scraping most recent CVEs from {}", link);
				try {
					String html = getContentFromUrl(link);
					list.addAll(crawler.parseWebPage(link, html));
					Thread.sleep(1000);
				} catch (Exception e) {
					logger.error("Error scraping url {}, {}", link, e.toString());
				}
			}

			logger.info("Retrieved {} CVES from {}, Total CVEs: {}", list.size() - count, url, list.size());
		} catch (Exception e) {
			logger.error("Error scraping PacketStorm! {}", e);
		}
		return list;
	}

	/**
	 * Scrape Tenable
	 * 
	 * @param crawler
	 * @param list
	 * @return
	 */
	public List<CompositeVulnerability> getTenableCveUpdates(CveCrawler crawler, List<CompositeVulnerability> list) {
		String url = "https://www.tenable.com/cve/newest";

		try {
			int count = list.size();
			logger.info("Getting CVES from {} ", url);
			String html = getContentFromUrl(url);
			list.addAll(crawler.parseWebPage(url, html));
			logger.info("Retrieved {} CVES from {}, Total CVEs: {}", list.size() - count, url, list.size());
		} catch (Exception e) {
			logger.error("Error scraping url {}, {}", url, e.toString());
		}
		return list;
	}

	public String getContentFromUrl(String url) {
		StringBuilder response = new StringBuilder();
		BufferedReader bufferedReader = null;
		try {
			URL urlObject = new URL(url);
			HttpURLConnection httpURLConnection = (HttpURLConnection) urlObject.openConnection();
			httpURLConnection.setRequestMethod("GET");
			httpURLConnection.setRequestProperty("User-Agent", USER_AGENT);

			bufferedReader = new BufferedReader(new InputStreamReader(httpURLConnection.getInputStream()));
			String inputLine;
			while ((inputLine = bufferedReader.readLine()) != null) {
				response.append(inputLine + "\n");
			}
			bufferedReader.close();

		} catch (SSLException e) {
			logger.error(e.toString());
		} catch (SocketException e) {
			logger.error(e.toString());
		} catch (IOException e) {
			logger.error(e.toString());
		} catch (Exception e) {
			logger.error(e.toString());
		}
		return response.toString();
	}

	/**
	 * Scrape CNNVD
	 * 
	 * @param list
	 * @return
	 */
	public List<CompositeVulnerability> getCnnvdCveUpdates(List<CompositeVulnerability> list) {
		try {
			String sUrlForCveListPage = "http://www.cnnvd.org.cn/web/vulnerability/querylist.tag?pageno=$pageno$&repairLd=";
			CnnvdCveParser chinaCveParser = new CnnvdCveParser();
			String dateTimeNow = UtilHelper.longDateFormat.format(new Date());
			int count = list.size();
			Random r = new Random(100);
			// scrape first 3 pages
			for (int pageIndex = 1; pageIndex < 4; pageIndex++) {
				String pageLink = sUrlForCveListPage.replace("$pageno$", pageIndex + "");
				logger.info("Scraping CVEs from CNNVD {} ,pape # {}", pageLink, pageIndex);

				String pageStr = getContentFromUrl(pageLink);
				List<String> cveURLsInPage = chinaCveParser.getCveUrlListFromPage(pageStr);
				for (String cveURLItem : cveURLsInPage) {
					try {

						String[] cveUrlParts = cveURLItem.split("=");
						String cnnvdCveId = cveUrlParts[1];

						logger.info("Getting {} details from {}", cnnvdCveId, cveURLItem);

						String cveDetailHtml = getContentFromUrl(cveURLItem);
						// get CVE details
						CnnvdVulnerability vuln = chinaCveParser.getCveDetailsFromPage(cveDetailHtml);

						// get ref urls
						List<String> refURLs = chinaCveParser.getCveReferencesFromPage(cveDetailHtml);
						for (String refUrl : refURLs)
							vuln.addVulnerabilitySource(refUrl);

						String description = "New vulnerability from CNNVD! Details:  " + vuln.toString();
						// add vuln
						CompositeVulnerability vulnComposite = new CompositeVulnerability(0, cveURLItem, vuln.getCveId(), null, dateTimeNow, dateTimeNow, description, "cnnvd");
						list.add(vulnComposite);
						Thread.sleep(r.nextInt(100) + 1000); // random wait
					} catch (Exception e) {
						logger.error("Error while getting CVE details from {}, {} ", cveURLItem, e.toString());
					}
				}
			}

			logger.info("Done! Scraped {} CVEs from Cnnvd! ", list.size() - count);
		} catch (Exception e) {
			logger.error("Error scraping CNNVD! {}", e);

		}
		return list;

	}

	/**
	 * Seclists CVE summaries are provided for each quarter. For example:
	 * https://seclists.org/oss-sec/2021/q2 provides CVES for the second quarter of
	 * 2021.
	 * 
	 * This methods scrapes CVEs for the current quarter
	 * 
	 * @param crawler
	 * @param list
	 * @return
	 */
	public List<CompositeVulnerability> getSeclistsCveUpdates(CveCrawler crawler, List<CompositeVulnerability> list) {
		Random r = new Random(100);
		String url = "https://seclists.org/oss-sec/{x}/q{y}";

		try {
			LocalDate myLocal = LocalDate.now();
			int year = myLocal.getYear();
			int quarter = myLocal.get(IsoFields.QUARTER_OF_YEAR);

			url = url.replace("{x}", year + "");
			url = url.replace("{y}", quarter + "");

			logger.info("Getting CVES from {} ", url);
			int count = list.size();

			// summary page content
			String html = getContentFromUrl(url);
			Document doc = Jsoup.parse(html);

			// get all links in the page
			Elements elements = doc.select("a");

			// filter CVE related links
			for (Element element : elements) {
				if (element.text().contains("CVE-")) {
					String linkExt = element.attr("href");
					String pageLink = url + "/" + linkExt;

					logger.info("Scraping {}", pageLink);

					// get CVE content
					html = getContentFromUrl(pageLink);
					list.addAll(crawler.parseWebPage(pageLink, html));

					Thread.sleep(r.nextInt(10) + 40); // random delay
				}
			}

			logger.info("Retrieved {} CVES from {}, Total CVEs: {}", list.size() - count, url, list.size());
		} catch (Exception e) {
			logger.error("Error scraping url {}, {}", url, e.toString());
		}
		return list;
	}
}
