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
import org.jsoup.select.Elements;

import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.*;

/**
 * 
 * Parse SecList CVEs
 * 
 * @author axoeec
 *
 */
public class SeclistsParser extends AbstractCveParser implements CveParserInterface {
	private Logger logger = LogManager.getLogger(getClass().getSimpleName());

	public SeclistsParser(String domainName) {
		sourceDomainName = domainName;
	}

	/*
	 * this attribute is for reading the text on the site into different lists,
	 * based on how the line starts it will either be classified as description,
	 * versions, or empty, the line is added to different attributes accordingly
	 */
	private enum Modes {
		DESCRIPTION, VERSIONS, EMPTY
	}

	@Override
	public List<CompositeVulnerability> parseWebPage(String sSourceURL, String sCVEContentHTML) {
		List<CompositeVulnerability> vulns = new ArrayList<>();

		Document doc = Jsoup.parse(sCVEContentHTML);

		SimpleDateFormat dateFormat = new SimpleDateFormat("'Date:' E, dd MMM yyyy HH:mm:ss", Locale.ENGLISH);

		Set<String> uniqueCves = getCVEs(sCVEContentHTML);
		if (uniqueCves.isEmpty())
			return vulns;

		String desc = "";
		String versionString = "";
		Date updateDate = new Date();
		String updateString = UtilHelper.longDateFormat.format(updateDate);
		String publishDate = null;

		String text = doc.text();
		String[] lines = text.split("\n");

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

		/*
		 * determine what the line is, reset on newline most seclists sources have
		 * sections that say description:/versions:
		 */
		Modes mode = Modes.EMPTY;
		for (String line : lines) {
			try {
				line = line.trim();
				if (line.isEmpty()) {
					mode = Modes.EMPTY;
					continue;
				}

				if (line.toLowerCase().contains("description") || line.toLowerCase().contains("mitigations")) {
					mode = Modes.DESCRIPTION;
					continue;
				} else if (line.toLowerCase().contains("version")) {
					mode = Modes.VERSIONS;
					continue;
				}
				/*
				 * add the line to description or version string according to the type of the
				 * line by default it is added to description to account for non-standard
				 * formats
				 */
				switch (mode) {
				case EMPTY:
				case DESCRIPTION:
					desc += line + "  ";
					break;
				case VERSIONS:
					versionString += line + "\n";
					break;
				}
			} catch (Exception e) {
				logger.error("Error while parsing descriptions/versions at url: {}", sSourceURL);
			}
		}

		List<AffectedRelease> affectedReleases = new ArrayList<>();
		try {
			CpeLookUp loader = CpeLookUp.getInstance();
			List<String> platformStrings = getPlatformVersions(versionString);

			for (String s : platformStrings) {
				Product p = loader.productFromDomain(s);

				if (p != null) {
					affectedReleases.add(new AffectedRelease(p.getCpe(), publishDate, p.getVersion()));
				}
			}
		} catch (Exception e) {
			logger.error("Error while parsing affected releases at url {}", sSourceURL);
		}

		/*
		 * get everything as description if there are no lines added earlier
		 */
		if (desc.isEmpty()) {
			Elements pres = doc.getElementsByTag("pre");
			if (pres.size() == 1) {
				desc = pres.get(0).text();
			}
		}

		for (String cve : uniqueCves) {
			CompositeVulnerability v = new CompositeVulnerability(0, sSourceURL, cve, "", publishDate, updateString, desc, sourceDomainName);
			vulns.add(v);
			for (AffectedRelease a : affectedReleases)
				v.addAffectedRelease(a);
		}

		return vulns;
	}
}
