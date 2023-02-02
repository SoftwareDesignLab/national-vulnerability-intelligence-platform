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

import java.text.DateFormat;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Date;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
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
 * Parse CVEs from Security Focus
 * 
 * @author axoeec
 *
 */
public class SecurityfocusCveParser extends AbstractCveParser implements CveParserInterface {

	public SecurityfocusCveParser(String domainName) {
		sourceDomainName = domainName;
	}

	@Override
	public List<CompositeVulnerability> parseWebPage(String sSourceURL, String sCVEContentHTML) {
		List<CompositeVulnerability> vulnerabilities = new ArrayList<>();
		String lastModifiedDate = UtilHelper.longDateFormat.format(new Date());
		if (sSourceURL.contains("archive"))
			return vulnerabilities;
		List<AffectedRelease> affectedReleases = new ArrayList<>();

		if (sSourceURL.endsWith("info")) {
			sSourceURL = sSourceURL.replace("/info", "");
		}

		Set<String> uniqueCves = new HashSet<>();

		Document document = Jsoup.parse(sCVEContentHTML);
		document.select("br").after("////");

		String allText = document.text();

		Pattern pattern = Pattern.compile(regexCVEID);
		Matcher matcher = pattern.matcher(allText);

		while (matcher.find())
			uniqueCves.add(matcher.group());

		String description = "";
		String publishedDate = null;
		String lastModified = null;

		Elements tableRows = document.getElementsByTag("tr");
		for (Element e : tableRows) {
			if (e.child(0).text().equals("Vulnerable:")) {
				affectedReleases = getVulnerablePlatforms(e.child(1).text());
			}
			if (e.attributes().size() > 0)
				continue;
			if (e.child(0).text().contains("Published:")) {
				publishedDate = e.child(1).text();
			} else if (e.child(0).text().contains("Updated")) {
				lastModified = e.child(1).text();
			} else if (e.child(0).text().contains("Class:")) {
				description = e.child(1).text() + "\n";
			}
		}

		DateFormat currentFormat = new SimpleDateFormat("MMM dd yyyy hh:mma", Locale.ENGLISH);
		try {
			publishedDate = UtilHelper.longDateFormat.format(currentFormat.parse(publishedDate));
		} catch (ParseException pe) {
			pe.printStackTrace();
		}
		try {
			UtilHelper.longDateFormat.format(currentFormat.parse(lastModified));
		} catch (ParseException pe) {
			pe.printStackTrace();
		}

		String discussionTab = "discuss";
		String descUrl = sSourceURL + "/" + discussionTab;
		try {
			document = Jsoup.connect(descUrl).get();
			description += document.getElementById("vulnerability").text();
		} catch (Exception e) {
		}

		for (AffectedRelease a : affectedReleases) {
			a.setReleaseDate(publishedDate);
		}

		for (String cve : uniqueCves) {
			CompositeVulnerability vuln = new CompositeVulnerability(0, sSourceURL, cve, null, publishedDate, lastModifiedDate, description, sourceDomainName);
			for (AffectedRelease affectedRelease : affectedReleases) {
				AffectedRelease copy = new AffectedRelease(affectedRelease);
				copy.setCveId(cve);
				vuln.addAffectedRelease(copy);
			}
			vulnerabilities.add(vuln);
		}

		return vulnerabilities;
	}

	public List<AffectedRelease> getVulnerablePlatforms(String products) {
		Map<Integer, AffectedRelease> affectedReleases = new HashMap<>();

		String[] prodList = products.split("////");

		CpeLookUp loader = CpeLookUp.getInstance();
		for (String prod : prodList) {
			Product product = loader.productFromDomain(prod);
			if (product == null)
				continue;

			Pattern pattern = Pattern.compile(regexVersionInfo);
			Matcher matcher = pattern.matcher(prod);
			String version = null;
			if (matcher.find())
				version = matcher.group();

			AffectedRelease affectedRelease = new AffectedRelease(product.getCpe(), null, version);
			affectedReleases.put(product.getProdId(), affectedRelease);
		}

		return new ArrayList<>(affectedReleases.values());
	}

}
