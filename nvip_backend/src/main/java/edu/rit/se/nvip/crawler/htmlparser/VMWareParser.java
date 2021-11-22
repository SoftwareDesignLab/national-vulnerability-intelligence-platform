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
import org.jsoup.select.Elements;

import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * 
 * @author axoeec
 *
 */
public class VMWareParser extends AbstractCveParser implements CveParserInterface {
	
	public VMWareParser(String domainName) {
		sourceDomainName = domainName;
	}
	
	@Override
	public List<CompositeVulnerability> parseWebPage(String sSourceURL, String sCVEContentHTML) {
		List<CompositeVulnerability> vulns = new ArrayList<>();

		SimpleDateFormat dateFormat = new SimpleDateFormat("yyyy-MM-dd");
		Date updateDate = new Date();
		String updateDateString = UtilHelper.longDateFormat.format(updateDate);

		Set<String> uniqueCves = getCVEs(sCVEContentHTML);
		if (uniqueCves.isEmpty())
			return vulns;

		Document doc = Jsoup.parse(sCVEContentHTML);

		Elements pre = doc.getElementsByTag("pre");
		String body = "";
		if (pre.size() > 1) {
			// multiple "PRE" elements
			return vulns;
		} else if (pre.size() == 0) {
			body = doc.getElementsByTag("p").text();
		} else {
			body = pre.get(0).text();
		}

		String publishDate = null;

		Pattern datePattern = Pattern.compile("\\d{4}-\\d{2}-\\d{2}");
		Matcher dateMatcher = datePattern.matcher(body);

		if (dateMatcher.find()) {
			try {
				publishDate = UtilHelper.longDateFormat.format(dateFormat.parse(dateMatcher.group()));
			} catch (ParseException e) {
				e.printStackTrace();
			}
		}

		List<String> productStrings = getPlatformVersions(body);
		List<Product> products = new ArrayList<>();

		CpeLookUp loader = CpeLookUp.getInstance();
		for (String p : productStrings) {
			Product curr = loader.productFromDomain(p);
			if (curr != null)
				products.add(curr);
		}

		List<AffectedRelease> affectedReleases = new ArrayList<>();

		for (Product p : products) {
			String version = p.getVersion();
			affectedReleases.add(new AffectedRelease(p.getCpe(), publishDate, version));
		}

		for (String cve : uniqueCves) {
			CompositeVulnerability v = new CompositeVulnerability(0, sSourceURL, cve, null, publishDate, updateDateString, body, sourceDomainName);
			for (AffectedRelease a : affectedReleases) {
				v.addAffectedRelease(a);
			}
			vulns.add(v);
		}

		return vulns;
	}
}
