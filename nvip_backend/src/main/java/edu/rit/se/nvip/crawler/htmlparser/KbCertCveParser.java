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

import java.text.DateFormat;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * 
 * @author axoeec
 *
 */
public class KbCertCveParser extends AbstractCveParser implements CveParserInterface {
	
	public KbCertCveParser(String domainName) {
		sourceDomainName = domainName;
	}

	@Override
	public List<CompositeVulnerability> parseWebPage(String sSourceURL, String sCVEContentHTML) {
		List<CompositeVulnerability> vulnerabilities = new ArrayList<>();

		Document document = Jsoup.parse(sCVEContentHTML);

		List<AffectedRelease> cpes = getVendors(document);
		String lastModifiedDate = UtilHelper.longDateFormat.format(new Date());

		String publishDate = document.head().getElementsByAttributeValue("name", "published_at").attr("content");
		try {
			Date published = UtilHelper.kbCertDateFormat.parse(publishDate);
			publishDate = UtilHelper.longDateFormat.format(published);
		} catch (ParseException pe) {
			pe.printStackTrace();
		}

		Elements myHTMLElements = document.select(":matchesOwn(" + regexAllCVERelatedContent + ")");
		String sCVEContent = myHTMLElements.text();
		String allText = document.text();

		String regexLastRevised = "(Last Revised|Updated): [0-9]+-[0-9]+-[0-9]+";
		Pattern lastRevisedPattern = Pattern.compile(regexLastRevised);
		Matcher matcher = lastRevisedPattern.matcher(allText);
		String lastModified;
		if (matcher.find()) {
			String[] splitLine = matcher.group().split(" ");
			lastModified = splitLine[splitLine.length - 1]; // format: yyyy-MM-dd
			try {
				Date date = UtilHelper.kbCertDateFormat.parse(lastModified);
				UtilHelper.longDateFormat.format(date);
			} catch (Exception e) {
				e.printStackTrace();
			}
		}

		Pattern pattern = Pattern.compile(regexCVEID);
		matcher = pattern.matcher(sCVEContent);

		String description = getSingleDescription(document);

		Set<String> uniqueIds = new HashSet<>();
		while (matcher.find())
			uniqueIds.add(matcher.group());
		Set<String> descCves = new HashSet<>();
		matcher.reset(description);
		while (matcher.find())
			descCves.add(matcher.group());

		if (uniqueIds.size() < 1) {
			return null;
		}
		/**
		 * only one cveId on the page
		 */
		else if (uniqueIds.size() == 1 || descCves.size() <= 1) {
			Iterator<String> iterator = uniqueIds.iterator();
			while (iterator.hasNext()) {
				String cveId = iterator.next();
				CompositeVulnerability vuln = new CompositeVulnerability(0, sSourceURL, cveId, null, publishDate, lastModifiedDate, description, sourceDomainName);
				vulnerabilities.add(vuln);
			}
		}
		/**
		 * multiple cveIds on the page
		 */
		else {
			String[] sentences = description.split("[\\.:]");

			String currCve = null;
			StringBuilder currDesc = new StringBuilder();

			for (String sentence : sentences) {
				sentence = sentence.trim();
				matcher.reset(sentence);
				if (matcher.find()) {
					if (currCve != null) {
						String desc = currDesc.toString();
						CompositeVulnerability vuln = new CompositeVulnerability(0, sSourceURL, currCve, null, publishDate, lastModifiedDate, desc, sourceDomainName);
						vulnerabilities.add(vuln);
					}
					currCve = matcher.group();
					currDesc = new StringBuilder();
					currDesc.append(sentence + ".  ");
				} else {
					currDesc.append(sentence + ".");
				}
			}
			String desc = currDesc.toString();
			CompositeVulnerability vuln = new CompositeVulnerability(0, sSourceURL, currCve, null, publishDate, lastModifiedDate, desc, sourceDomainName);
			vulnerabilities.add(vuln);

		}

		for (CompositeVulnerability vuln : vulnerabilities) {
			for (AffectedRelease affectedRelease : cpes) {
				AffectedRelease copy = new AffectedRelease(affectedRelease);
				copy.setCveId(vuln.getCveId());
				vuln.addAffectedRelease(copy);
			}
		}

		return vulnerabilities;
	}

	/**
	 * gets the vendor/system that is mentioned on the page
	 * 
	 * @param document javaSoup document of the page
	 * @return string of systems name
	 */
	private List<AffectedRelease> getVendors(Document document) {
		DatabaseHelper.getInstance();
		Element vendor = document.getElementById("vendorinfo");
		Elements affected = vendor.getElementsByClass("vinfo affected info");
		affected.addAll(vendor.getElementsByClass("vinfo affected")); // different classes for css

		Iterator<Element> affectedElements = affected.iterator();

		List<AffectedRelease> releases = new ArrayList<>();
		CpeLookUp loader = CpeLookUp.getInstance();

		while (affectedElements.hasNext()) {
			Element e = affectedElements.next();
			String name = e.attr("name");
			Product prod = loader.productFromDomain(name);
			if (prod == null)
				continue;
			Elements paragraphs = e.getElementsByTag("p");
			String elementText = paragraphs.text();

			Pattern pattern = Pattern.compile(regexVersionInfo);
			Matcher matcher = pattern.matcher(elementText);
			String version = null;
			if (matcher.find()) {
				version = matcher.group();
			}

			String releaseDate = null;
			for (Element p : paragraphs) {
				String pText = p.text();
				if (pText.contains("Notified") || pText.contains("Updated")) {
					pattern = Pattern.compile(regexDateFormat);
					matcher = pattern.matcher(pText);
					if (matcher.find()) {
						releaseDate = matcher.group();
						DateFormat originalFormat = new SimpleDateFormat("MMMM dd, yyyy", Locale.ENGLISH);
						try {
							Date date = originalFormat.parse(releaseDate);
							releaseDate = UtilHelper.shortDateFormat.format(date);
						} catch (ParseException pe) {
							pe.printStackTrace();
						}
						break;
					}
				}
			}

			releases.add(new AffectedRelease(prod.getCpe(), releaseDate, version));
		}

		return releases;
	}

	/**
	 * gets description text of one page, if multiple cveIds on one page this
	 * returns the descriptions for all of them in one string
	 * 
	 * @param document JavaSoup document of the page
	 * @return String of description
	 */
	private String getSingleDescription(Document document) {
		Elements h3s = document.getElementsByTag("h3");
		for (Element e : h3s) {
			if (e.text().trim().equalsIgnoreCase("description")) {
				int currIndex = e.elementSiblingIndex() + 1;
				Element parent = e.parent();
				while (parent.child(currIndex).text().trim().equals("")) {
					currIndex++;
				}
				return e.parent().child(currIndex).text();
			}
		}
		return null;
	}
}
