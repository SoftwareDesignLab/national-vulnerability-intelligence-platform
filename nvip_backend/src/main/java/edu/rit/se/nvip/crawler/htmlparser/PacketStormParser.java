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

import java.text.ParseException;
import java.util.ArrayList;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.jsoup.Jsoup;
import org.jsoup.nodes.Document;
import org.jsoup.nodes.Element;
import org.jsoup.select.Elements;

import edu.rit.se.nvip.db.DatabaseHelper;
import edu.rit.se.nvip.model.AffectedRelease;
import edu.rit.se.nvip.model.CompositeVulnerability;
import edu.rit.se.nvip.model.Product;
import edu.rit.se.nvip.productnameextractor.CpeLookUp;
import edu.rit.se.nvip.utils.UtilHelper;

/**
 * 
 * @author axoeec
 *
 */
public class PacketStormParser extends AbstractCveParser implements CveParserInterface {
	
	public PacketStormParser(String domainName) {
		sourceDomainName = domainName;
	}
	
	private Logger logger = LogManager.getLogger(getClass().getSimpleName());
	DatabaseHelper db = DatabaseHelper.getInstance();
	String lastModifiedDate = UtilHelper.longDateFormat.format(new Date());

	@Override
	public List<CompositeVulnerability> parseWebPage(String sSourceURL, String sCVEContentHTML) {
		if (sSourceURL.contains(".html")) {
			return parseSingleHTMLPage(sSourceURL, sCVEContentHTML);
		} else {
			/**
			 * 
			 * All pages have
			 * <dl class="file">
			 * and
			 * <dd class="cve">in them!
			 * 
			 */
			return parseCVEListPage(sSourceURL, sCVEContentHTML);
		}

	}

	/**
	 * parse a packetstorm pages like
	 * 
	 * https://packetstormsecurity.com/files/cve/CVE-2017-1000476
	 * https://packetstormsecurity.com/files/date/2004-01/
	 * https://packetstormsecurity.com/0307-advisories/
	 * https://packetstormsecurity.com/0309-exploits/
	 * 
	 * @param sSourceURL
	 * @param sCVEContentHTML
	 * @return
	 */
	private List<CompositeVulnerability> parseCVEListPage(String sSourceURL, String sCVEContentHTML) {

		List<CompositeVulnerability> allVulns = new ArrayList<>();
		Set<String> uniqueCves = getCVEs(sCVEContentHTML);
		if (uniqueCves.size() == 0)
			return allVulns;

		if (containsChineseChars(sCVEContentHTML))
			return allVulns;

		try {
			Document document = Jsoup.parse(sCVEContentHTML);

			String description;
			String publishDate;
			for (Element element : document.select("dl")) {

				// if no CVEs then continue!
				if (element.getElementsByClass("cve").size() == 0)
					continue;

				List<CompositeVulnerability> itemVulns = new ArrayList<>();

				// get unique CVEs in this list item
				uniqueCves = getCVEs(element.text());

				// title
				String listTitle = element.getElementsByIndexEquals(0).get(0).text();

				// get detail of the item
				Elements elements = element.getElementsByClass("detail");
				description = listTitle + "\n" + getDescription(sSourceURL, elements);
				if (description.equals(""))
					continue;

				// get date
				elements = element.getElementsByClass("datetime");
				publishDate = getDate(sSourceURL, elements);

				for (String cve : uniqueCves)
					itemVulns.add(new CompositeVulnerability(0, sSourceURL, cve, listTitle, publishDate, lastModifiedDate, description, sourceDomainName));

				allVulns.addAll(itemVulns);

			}
		} catch (Exception e) {
			logger.error("Error parsing: " + sSourceURL);
		}

		return allVulns;

	}

	/**
	 * get CVE description
	 * 
	 * @param sSourceURL
	 * @param elements
	 * @return
	 */
	private String getDescription(String sSourceURL, Elements elements) {
		String description = "";
		if (elements.isEmpty()) {
			UtilHelper.addBadUrl(sSourceURL, "No description element found");
			return null;
		} else {
			for (Element e : elements)
				description += (e.text() + "\n");
		}

		return description;
	}

	/**
	 * get CVE date
	 * 
	 * @param sSourceURL
	 * @param elements
	 * @return
	 */
	private String getDate(String sSourceURL, Elements elements) {
		String publishDate = null;
		for (Element d : elements) {
			if (d.children().isEmpty())
				continue;
			Element a = d.child(0);
			if (a.tagName().equals("a"))
				try {
					publishDate = UtilHelper.longDateFormat.format(dateFormat_MMMddCommaYYYY.parse(a.text()));
				} catch (ParseException e) {
					logger.error("No publish date found at: " + sSourceURL);
				}
		}
		return publishDate;
	}

	/**
	 * parse a packetstorm page like:
	 * https://packetstormsecurity.com/files/105405/Mandriva-Linux-Security-Advisory-2011-138.html
	 * 
	 * @param sSourceURL
	 * @param sCVEContentHTML
	 * @return
	 */
	private List<CompositeVulnerability> parseSingleHTMLPage(String sSourceURL, String sCVEContentHTML) {
		List<CompositeVulnerability> vulns = new ArrayList<>();
		Set<String> uniqueCves = getCVEs(sCVEContentHTML);
		if (uniqueCves.size() == 0)
			return vulns;

		if (containsChineseChars(sCVEContentHTML))
			return vulns;

		try {
			Document document = Jsoup.parse(sCVEContentHTML);

			String description;
			String publishDate;

			// gte description
			Elements descriptions = document.getElementsByClass("detail");
			description = getDescription(sSourceURL, descriptions);
			if (description.equals(""))
				return vulns;

			// get date
			Elements dates = document.getElementsByClass("datetime");
			publishDate = getDate(sSourceURL, dates);

			for (String cve : uniqueCves)
				vulns.add(new CompositeVulnerability(0, sSourceURL, cve, null, publishDate, lastModifiedDate, description, sourceDomainName));

			/**
			 * get version from the remaining text
			 */
			document.select("br").append("\n");

			Elements codeTags = document.getElementsByTag("code");
			String codeText = "";

			for (Element tag : codeTags)
				codeText += tag.text();

			List<AffectedRelease> affectedReleases = getAffectedReleasesFromTagTxt(codeText, publishDate);

			for (CompositeVulnerability v : vulns) {
				for (AffectedRelease a : affectedReleases) {
					AffectedRelease copy = new AffectedRelease(a);
					copy.setCveId(v.getCveId());
					v.addAffectedRelease(copy);
				}
			}
		} catch (Exception e) {
			logger.error("Error parsing: " + sSourceURL);
		}

		return vulns;

	}

	/**
	 * get affected releases from a given text
	 * 
	 * @param text
	 * @param publishDate
	 * @return
	 */
	private List<AffectedRelease> getAffectedReleasesFromTagTxt(String text, String publishDate) {

		List<String> versions = getPlatformVersions(text);
		CpeLookUp loader = CpeLookUp.getInstance();

		Map<Integer, Product> products = new HashMap<>();
		for (String v : versions) {
			Product p = loader.productFromDomain(v);
			if (p != null)
				products.put(p.getProdId(), p);
		}

		List<AffectedRelease> affectedReleases = getAffectedReleasesFromProducts(products, publishDate);
		return affectedReleases;

	}

	/**
	 * get affected releases from products
	 * 
	 * @param products
	 * @param publishDate
	 * @return
	 */
	private List<AffectedRelease> getAffectedReleasesFromProducts(Map<Integer, Product> products, String publishDate) {
		List<AffectedRelease> affectedReleases = new ArrayList<>();
		for (Product p : products.values()) {
			Pattern pattern = Pattern.compile(regexVersionInfo);
			Matcher matcher = pattern.matcher(p.getDomain());
			String version = null;
			if (matcher.find())
				version = matcher.group();
			AffectedRelease a = new AffectedRelease(p.getCpe(), publishDate, version);
			affectedReleases.add(a);
		}

		return affectedReleases;
	}

}
