package edu.rit.se.nvip.utils;

import java.net.URL;

import org.apache.commons.io.IOUtils;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.jsoup.Jsoup;
import org.jsoup.nodes.Document;
import org.jsoup.nodes.Element;
import org.jsoup.select.Elements;

import edu.rit.se.nvip.model.CompositeVulnerability;

public class CveUtils {
	static Logger logger = LogManager.getLogger(CveUtils.class);
	final static String RESERVED_CVE = "** RESERVED ** This candidate has been reserved";
	final static String REJECTED_CVE = "** REJECT **  DO NOT USE THIS CANDIDATE NUMBER";

	public static boolean isCveReservedEtc(String vulnDescr) {
		return vulnDescr.contains(RESERVED_CVE) || vulnDescr.contains(REJECTED_CVE) || vulnDescr.startsWith("** DISPUTED **");
	}

	/**
	 * Search Mitre for a given cve id
	 * 
	 * @param cveId
	 * @return
	 */
	public static String checkCveIdAtMitre(String cveId) {
		String url = "https://cve.mitre.org/cgi-bin/cvekey.cgi?keyword=" + cveId;
		StringBuffer result = new StringBuffer();
		try {
			String body = IOUtils.toString(new URL(url));
			Document doc = Jsoup.parse(body);
			Element table = doc.select("table").get(2); // get results table

			Elements rows = table.select("tr");
			result.append(rows.size() - 1 + " items at cve.mitre.org! ");
			for (int i = 1; i < rows.size(); i++) { // first row is the col names so skip it.
				Element row = rows.get(i);
				Elements cols = row.select("td");
				result.append(cols.get(0).text() + ": " + cols.get(1).text() + " ");
			}
			result.append(" ");
			logger.info(cveId + ":" + result.toString());
		} catch (Exception e) {
			logger.error("Error while querying cve.mitre.org: " + cveId + ": " + e.toString());
			result.append("Error while querying cve.mitre.org for" + cveId + "! ");
		}
		return result.toString();
	}

	/**
	 * Search NVD for a given cve id
	 * 
	 * @param cveId
	 * @return
	 */
	public static String checkCveIdAtNvd(String cveId) {
		String sUrl = "https://nvd.nist.gov/vuln/search/results?form_type=Basic&results_type=overview&query=" + cveId + "&search_type=all";
		StringBuffer result = new StringBuffer();
		try {
			String body = IOUtils.toString(new URL(sUrl));
			Document doc = Jsoup.parse(body);
			String str = doc.select("strong[data-testid=vuln-matching-records-count]").get(0).text();
			if (str.indexOf(",") >= 0)
				str = str.replace(",", "");
			int count = Integer.parseInt(str);

			String str2 = "";
			if (count > 0)
				str2 = " Published at: " + doc.select("span[data-testid=vuln-published-on-0]").get(0).text();
			result.append(count);
			result.append(" items at nvd.org!");
			result.append(str2);
			result.append(" ");
			logger.info(cveId + ":" + result.toString());
		} catch (Exception e) {
			logger.error("Error while querying nvd.org: " + cveId + ": " + e.toString());
			result.append("Error while querying nvd.org for " + cveId + "! ");
		}

		return result.toString();
	}

}
