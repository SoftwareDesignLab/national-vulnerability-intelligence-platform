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
public class TenableSecurityParser extends AbstractCveParser implements CveParserInterface {
	
	public TenableSecurityParser(String domainName) {
		sourceDomainName = domainName;
	}
	
	@Override
	public List<CompositeVulnerability> parseWebPage(String sSourceURL, String sCVEContentHTML) {
		List<CompositeVulnerability> vulns = new ArrayList<>();
		List<Product> products = new ArrayList<>();
		boolean foundProducts = false;
		String lastModifiedDate = UtilHelper.longDateFormat.format(new Date());

		Document doc = Jsoup.parse(sCVEContentHTML);

		Pattern pattern = Pattern.compile(regexCVEID);
		Matcher matcher = pattern.matcher("");

		Set<String> uniqueCves = new HashSet<>();

		Elements as = doc.getElementsByTag("a");
		for (Element e : as) {
			matcher.reset(e.text());
			if (matcher.find()) {
				uniqueCves.add(matcher.group());
			}
		}

		String desc = "";
		Date releaseDate = null;
		Date updateDate = null;

		Elements h3s = doc.getElementsByTag("h3");
		for (Element e : h3s) {
			if (e.text().trim().equals("Synopsis")) {
				desc = e.parent().child(1).text();
			} else if (e.text().trim().equals("Advisory Timeline")) {
				Elements dates = e.parent().getElementsByClass("field-items");
				for (Element date : dates.get(0).children()) {
					if (date.text().toLowerCase().contains("release")) {
						releaseDate = getDate(date.text());
					} else {
						updateDate = getDate(date.text());
					}
				}
			} else if (e.text().toLowerCase().toLowerCase().equals("affected products")) {
				products.addAll(getProducts(e.parent().getElementsByClass("field-items").get(0)));
				foundProducts = true;
			}
		}

		String releaseDateString = null;

		if (releaseDate != null) {
			releaseDateString = UtilHelper.longDateFormat.format(releaseDate);
		}

		if (!foundProducts) {
			Elements labels = doc.getElementsByClass("field-label");
			for (Element label : labels) {
				if (label.text().toLowerCase().contains("affected products")) {
					Element prodElements = label.parent().child(1);
					products.addAll(getProducts(prodElements));
				}
			}
		}

		for (String cve : uniqueCves) {
			CompositeVulnerability vuln = new CompositeVulnerability(0, sSourceURL, cve, null, releaseDateString, lastModifiedDate, desc, sourceDomainName);
			vulns.add(vuln);
		}

		for (Product p : products) {
			Pattern versionPattern = Pattern.compile(regexVersionInfo);
			Matcher versionMatcher = versionPattern.matcher(p.getDomain());
			String version = (versionMatcher.find()) ? versionMatcher.group() : null;
			for (CompositeVulnerability vuln : vulns) {
				AffectedRelease a = new AffectedRelease(p.getCpe(), releaseDateString, version);
				a.setCveId(vuln.getCveId());
				vuln.addAffectedRelease(a);
			}
		}

		return vulns;
	}

	Date getDate(String given) {
		String yearFirst = "[0-9]{4}[-/][0-9]+[-/][0-9]+";
		String monthFirst = "[0-9]+[-/][0-9]+[-/][0-9]{4}";
		Pattern pattern = Pattern.compile(yearFirst);
		Matcher matcher = pattern.matcher(given);
		String date = null;
		boolean monthIsFirst = false;
		if (matcher.find()) {
			date = matcher.group();
		} else {
			pattern = Pattern.compile(monthFirst);
			matcher = pattern.matcher(given);
			if (matcher.find()) {
				date = matcher.group();
				monthIsFirst = true;
			}
		}
		if (date == null)
			return null;
		if (date.contains("/"))
			date = date.replace("/", "-");

		DateFormat monthFirstFormat = new SimpleDateFormat("MM-dd-yyyy", Locale.ENGLISH);
		DateFormat yearFirstFormat = new SimpleDateFormat("yyyy-MM-dd", Locale.ENGLISH);
		try {
			return monthIsFirst ? monthFirstFormat.parse(date) : yearFirstFormat.parse(date);
		} catch (ParseException e) {
			e.printStackTrace();
		}
		return null;
	}

	private List<Product> getProducts(Element e) {
		List<Product> products = new ArrayList<>();
		CpeLookUp loader = CpeLookUp.getInstance();
		for (Element child : e.children()) {
			Product currentProd = loader.productFromDomain(child.text());
			if (currentProd != null)
				products.add(currentProd);
		}

		return products;
	}

}
