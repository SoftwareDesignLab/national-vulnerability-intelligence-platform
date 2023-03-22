/**
 * Copyright 2023 Rochester Institute of Technology (RIT). Developed with
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
import org.jsoup.nodes.Element;
import org.jsoup.select.Elements;

import java.util.ArrayList;
import java.util.List;

public class SnykParser extends AbstractCveParser {

    /**
     * Parse advisories listed to security.snyk.io/vuln/3
     * @param domainName - snyk domain
     */
    public SnykParser(String domainName) { sourceDomainName = domainName; }

    @Override
    public List<CompositeVulnerability> parseWebPage(String sSourceURL, String sCVEContentHTML) {

        List<CompositeVulnerability> vulnList = new ArrayList<>();

        Document doc = Jsoup.parse(sCVEContentHTML);

        // extract cve id from top info bar near title
        Element vulnInfo = doc.select("div.vuln-info-block").first();
        if (vulnInfo != null) {
            if  (vulnInfo.text().contains("CVE-")) {
                String cveId = "";
                String[] infoTexts = vulnInfo.text().split(" ");
                for (String s : infoTexts) {
                    if (s.contains("CVE-")) cveId = s;
                }

                // get publish date from bottom right info box
                Elements cardBodies = doc.select("div.vue--card__body");
                // the second card body
                Element dateBox = cardBodies.get(1);
                Element pubDate = dateBox.children().select("li:contains(Published)").first();
                String publishedDate = "";
                if (pubDate != null)
                    publishedDate = pubDate.text().split("published")[1].trim();

                // get description from 'Overview' and 'Details' paragraphs
                StringBuilder description = new StringBuilder();
                Elements descHeaders = doc.select("h2:contains(Overview), h2:contains(Details)");
                for (Element header : descHeaders) {
                    Element next = header.nextElementSibling();
                    if (next != null)
                        description.append(next.text());
                }
                vulnList.add(new CompositeVulnerability(
                        0, sSourceURL, cveId, null, publishedDate, publishedDate, description.toString(), sourceDomainName
                ));
            }
        }

        return vulnList;
    }
}
