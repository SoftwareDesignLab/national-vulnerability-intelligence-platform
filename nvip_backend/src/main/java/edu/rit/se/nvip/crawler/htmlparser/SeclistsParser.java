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
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.jsoup.Jsoup;
import org.jsoup.nodes.Document;

import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.*;

/**
 * 
 * Parse SecList CVEs
 * 
 * @author axoeec
 *
 * Ex:https://seclists.org/bugtraq/2016/Feb/147
 */
public class SeclistsParser extends AbstractCveParser  {
	private final Logger logger = LogManager.getLogger(getClass().getSimpleName());

	public SeclistsParser(String domainName) {
		sourceDomainName = domainName;
	}

	@Override
	public List<CompositeVulnerability> parseWebPage(String sSourceURL, String sCVEContentHTML) {
		List<CompositeVulnerability> vulns = new ArrayList<>();

		Document doc = Jsoup.parse(sCVEContentHTML);

		SimpleDateFormat dateFormat = new SimpleDateFormat("'Date:' E, dd MMM yyyy HH:mm:ss", Locale.ENGLISH);

		Set<String> uniqueCves = getCVEs(sCVEContentHTML);
		if (uniqueCves.isEmpty())
			return vulns;

		Date updateDate = new Date();
		String updateString = UtilHelper.longDateFormat.format(updateDate);
		String publishDate = null;

		String text = doc.getElementsByTag("pre").text();

		doc.select("br").append("\\n");
		doc.select("p").prepend("\\n\\n");
		String newText = doc.text().replace("\\n", "\n");

		/*
		 * date line format: Date: Fri, 17 Jun 2016 07:39:09 +0200
		 */
		for (String line : newText.split("\n")) {
			if (line.toLowerCase().trim().startsWith("date")) {
				try {
					publishDate = UtilHelper.longDateFormat.format(dateFormat.parse(line.trim()));

				} catch (ParseException e) {
					logger.error("Failed to parse date on {}, format not known!", sSourceURL);
					publishDate = null;
				}
			}
		}

		List<AffectedRelease> affectedReleases = new ArrayList<>();
		try {
			CpeLookUp loader = CpeLookUp.getInstance();
			List<String> platformStrings = getPlatformVersions(text);

			for (String s : platformStrings) {
				Product p = loader.productFromDomain(s);

				if (p != null) {
					affectedReleases.add(new AffectedRelease(p.getCpe(), publishDate, p.getVersion()));
				}
			}
		} catch (Exception e) {
			logger.error("Error while parsing affected releases at url {}", sSourceURL);
		}

		for (String cve : uniqueCves) {
			CompositeVulnerability v = new CompositeVulnerability(0, sSourceURL, cve, "", publishDate, updateString, text, sourceDomainName);
			vulns.add(v);
			for (AffectedRelease a : affectedReleases)
				v.addAffectedRelease(a);
		}

		return vulns;
	}
}
