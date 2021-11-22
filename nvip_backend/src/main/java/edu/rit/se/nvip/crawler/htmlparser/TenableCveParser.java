/**
 * Copyright 2021 Rochester Institute of Technology (RIT). Developed with
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
package edu.rit.se.nvip.crawler.htmlparser;

import com.google.gson.Gson;
import edu.rit.se.nvip.db.DatabaseHelper;
import edu.rit.se.nvip.model.AffectedRelease;
import edu.rit.se.nvip.model.CompositeVulnerability;
import edu.rit.se.nvip.model.Product;
import edu.rit.se.nvip.productnameextractor.CpeLookUp;
import edu.rit.se.nvip.utils.UtilHelper;
import org.jsoup.Jsoup;
import org.jsoup.nodes.Document;
import org.jsoup.nodes.Element;
import org.jsoup.select.Elements;

import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Parse Teenable CVEs
 * 
 * @author axoeec
 *
 */
public class TenableCveParser extends AbstractCveParser implements CveParserInterface {

	public TenableCveParser(String domainName) {
		sourceDomainName = domainName;
	}

	@Override
	public List<CompositeVulnerability> parseWebPage(String sSourceURL, String sCVEContentHTML) {

		if (sSourceURL.contains("/cve/newest") || sSourceURL.contains("/cve/updated"))
			return getCVEsFromSummaryPage(sSourceURL, sCVEContentHTML);

		List<CompositeVulnerability> vulns = new ArrayList<>();
		String description = "";
		String cve = null;

		Document doc = Jsoup.parse(sCVEContentHTML);
		String allText = doc.text();

		HashSet<String> uniqueCves = new HashSet<>();
		Pattern pattern = Pattern.compile(regexCVEID);
		Matcher matcher = pattern.matcher(allText);

		while (matcher.find())
			uniqueCves.add(matcher.group());
		if (uniqueCves.size() == 0) {
			UtilHelper.addBadUrl(sSourceURL, "No CVE ID found");
			return vulns;
		}

		Elements descFields = doc.getElementsByAttributeValue("name", "description");
		if (descFields.size() == 1) {
			description = descFields.get(0).attr("content");
		} else {
			UtilHelper.addBadUrl(sSourceURL, "Multiple or no description fields");
		}

		String publishDate = null;
		String updateDate = null;

		Elements strongs = doc.getElementsByTag("strong");
		for (Element s : strongs) {
			if (s.text().trim().equals("Published:")) {
				publishDate = s.parent().child(1).text();
			} else if (s.text().trim().equals("Updated:")) {
				updateDate = s.parent().child(1).text();
			}
		}

		Set<String> cpes = new HashSet<>();

		Elements allA = doc.getElementsByTag("a");
		for (Element a : allA) {
			if (a.text().contains("cpe:")) {
				cpes.add(a.text());
			}
		}

		CpeLookUp loader = CpeLookUp.getInstance();
		List<Product> products = new ArrayList<>();
		for (String cpe : cpes) {
			Product p = loader.productFromCpe(cpe);
			if (p != null)
				products.add(p);
		}
		List<AffectedRelease> affectedReleases = new ArrayList<>();

		pattern = Pattern.compile(regexVersionInfo);
		matcher = pattern.matcher("");
		for (Product p : products) {
			matcher.reset(p.getDomain());
			String version = null;
			if (matcher.find())
				version = matcher.group();
			for (String c : uniqueCves) {
				AffectedRelease a = new AffectedRelease(p.getCpe(), publishDate, version);
				a.setCveId(c);
				affectedReleases.add(a);
			}
		}

		for (String c : uniqueCves) {
			CompositeVulnerability vuln = new CompositeVulnerability(0, sSourceURL, c, null, publishDate, updateDate, description, sourceDomainName);
			for (AffectedRelease a : affectedReleases) {
				vuln.addAffectedRelease(a);
			}
			vulns.add(vuln);
		}

		return vulns;
	}

	private List<CompositeVulnerability> getCVEsFromSummaryPage(String sSourceURL, String sCVEContentHTML) {
		List<CompositeVulnerability> list = new ArrayList<>();
		String description = "";
		String cve = null;

		Document doc = Jsoup.parse(sCVEContentHTML);
		List<Element> tdList = doc.getElementsByClass("cve-id");
		String dateTimeNow = UtilHelper.longDateFormat.format(new Date());

		for (Element element : tdList) {
			cve = element.getElementsByTag("a").text();
			description = element.nextElementSibling().text();
			CompositeVulnerability vuln = new CompositeVulnerability(0, sSourceURL, cve, null, dateTimeNow, dateTimeNow, description, sourceDomainName);
			list.add(vuln);
		}

		return list;

	}
}
