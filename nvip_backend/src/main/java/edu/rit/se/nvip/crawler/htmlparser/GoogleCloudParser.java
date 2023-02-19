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

import edu.rit.se.nvip.model.CompositeVulnerability;
import org.jsoup.Jsoup;
import org.jsoup.nodes.Document;
import org.jsoup.select.Elements;
import org.jsoup.nodes.Element;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import java.util.*;


/**
    Parse Google Cloud Support Bulletin
    (ex. https://cloud.google.com/support/bulletins)
    @author aep7128
 */

public class GoogleCloudParser extends AbstractCveParser  {

	public GoogleCloudParser(String domainName) {
		sourceDomainName = domainName;
	}

    @Override
	public List<CompositeVulnerability> parseWebPage(String sSourceURL, String sCVEContentHTML) {
		List<CompositeVulnerability> vulns = new ArrayList<>();

        Set<String> uniqueCves = getCVEs(sCVEContentHTML);
        if (uniqueCves.size() == 0)
            return vulns;

		Document doc = Jsoup.parse(sCVEContentHTML);
        Pattern pattern = Pattern.compile(regexCVEID);
        Elements bulletin = doc.getElementsByClass("bulletins");

        if (bulletin.size() == 1) {
            Elements bulletinItems = bulletin.get(0).children();

            ArrayList<String> cves = new ArrayList<>();
            String description = "";
            String publishedDate = "";
            String lastModifiedDate = "";

            for (Element item: bulletinItems) {
                if (item.tagName().equals("p")) {
                    String[] lines = item.text().split("\n");
                    for (String line: lines) {
                        if (line.contains("Published")) {
                            publishedDate = line.split(" ")[1];
                        } else if (line.contains("Updated:")) {
                            lastModifiedDate = line.split(" ")[1];
                        }
                    }

                    if (lastModifiedDate.isEmpty()) {
                        lastModifiedDate = publishedDate;
                    }

                } else if (item.className().contains("devsite-table-wrapper")) {
                    Elements bodyContents = item.select("tr > td");
                    if (bodyContents.size() == 3) {
                        description = bodyContents.get(0).text();

                        for (Element note: bodyContents.get(2).select("li")) {
                            Matcher matcher = pattern.matcher(note.text());
                            if (matcher.find()) {
                                cves.add(note.text());
                            }
                        }
                    }

                    for (String cve: cves) {
                        vulns.add(new CompositeVulnerability(0, sSourceURL, cve, null, publishedDate, lastModifiedDate, description, sourceDomainName));
                    }
                    cves = new ArrayList<>();
                    description = "";
                    publishedDate = "";
                    lastModifiedDate = "";

                }
            }


        }

        return vulns;

    }

}