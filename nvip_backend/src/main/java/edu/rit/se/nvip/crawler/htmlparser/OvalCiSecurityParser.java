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

import java.util.ArrayList;
import java.util.Date;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.jsoup.Jsoup;
import org.jsoup.nodes.Document;
import org.jsoup.nodes.Element;
import org.jsoup.select.Elements;

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
public class OvalCiSecurityParser extends AbstractCveParser implements CveParserInterface {
	
	public OvalCiSecurityParser(String domainName) {
		sourceDomainName = domainName;
	}
	
	@Override
	public List<CompositeVulnerability> parseWebPage(String sSourceURL, String sCVEContentHTML) {
		List<CompositeVulnerability> vulns = new ArrayList<>();

		Document doc = Jsoup.parse(sCVEContentHTML);
		String lastModifiedDate = UtilHelper.longDateFormat.format(new Date());

		String allText = doc.text();

		Set<String> uniqueCves = new HashSet<>();
		Pattern pattern = Pattern.compile(regexCVEID);
		Matcher matcher = pattern.matcher(allText);

		Elements listItems = doc.getElementsByTag("li");

		for (Element e : listItems) {
			matcher.reset(e.text());
			if (matcher.find())
				uniqueCves.add(matcher.group());
		}
		if (uniqueCves.size() == 0) {
			UtilHelper.addBadUrl(sSourceURL, "No CVE IDs");
		}
		if (uniqueCves.size() > 1)
			System.err.println("Multiple cves at: " + sSourceURL);

		String desc = "";

		Elements paragraphs = doc.getElementsByTag("p");
		for (Element p : paragraphs) {
			if (p.children().size() == 0) {
				desc += p.text();
			}
		}

		List<Product> products = new ArrayList<>();

		CpeLookUp loader = CpeLookUp.getInstance();
		Elements rows = doc.getElementsByClass("row");
		for (Element e : rows) {
			if (e.children().size() == 2) {
				if (e.child(0).text().trim().equals("Class:")) {
					String type = e.child(1).text();
					if (!type.toLowerCase().equals("vulnerability")) {
						System.err.println("No vulnerability at: " + sSourceURL);
						return vulns;
					}
				} else if (e.child(0).text().trim().equals("Platform(s):")) {
					listItems = e.getElementsByTag("li");
					for (Element li : listItems) {
						matcher.reset(li.text());
						if (matcher.find())
							continue;
						Product p = loader.productFromDomain(li.text());
						if (p != null)
							products.add(p);
					}
				}
			}
		}

		Pattern versionPattern = Pattern.compile(regexVersionInfo);
		Matcher versionMatcher = versionPattern.matcher("");
		List<AffectedRelease> affectedReleases = new ArrayList<>();
		for (Product p : products) {
			String version = null;
			versionMatcher.reset(p.getDomain());
			if (versionMatcher.find())
				version = versionMatcher.group();
			AffectedRelease a = new AffectedRelease(p.getCpe(), null, version);
			affectedReleases.add(a);
		}

		if (desc.length() == 0) {
			UtilHelper.addBadUrl(sSourceURL, "No description found");
		}

		for (String cve : uniqueCves) {
			CompositeVulnerability v = new CompositeVulnerability(0, sSourceURL, cve, null, null, lastModifiedDate, desc, sourceDomainName);
			for (AffectedRelease a : affectedReleases) {
				v.addAffectedRelease(a);
			}
			vulns.add(v);
		}

		return vulns;
	}
}
