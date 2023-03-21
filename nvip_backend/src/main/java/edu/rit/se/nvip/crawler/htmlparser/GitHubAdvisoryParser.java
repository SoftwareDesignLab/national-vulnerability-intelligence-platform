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
import java.util.Objects;

public class GitHubAdvisoryParser extends AbstractCveParser {

    /**
     * Parse advisories listed to github.com/advisories
     * @param domainName - github domain
     */
    public GitHubAdvisoryParser(String domainName) { sourceDomainName = domainName; }

    @Override
    public List<CompositeVulnerability> parseWebPage(String sSourceURL, String sCVEContentHTML) {

        List<CompositeVulnerability> vulnList = new ArrayList<>();

        Document doc = Jsoup.parse(sCVEContentHTML);

        // first get CVE ID in right hand section
        Element cveIDHeader = doc.select("h3:contains(CVE ID)").first();
        String cveId = "";
        if (cveIDHeader != null)
            cveId = Objects.requireNonNull(cveIDHeader.nextElementSibling()).text();
        // if "No known CVE" or CVE section nonexistent, return empty list
        if (cveId.equals("") || cveId.contains("No known CVE")) return vulnList;

        // get description
        StringBuilder description = new StringBuilder();
        // grab p text until reaching a header. if impact header, skip
        Element descriptionElement = doc.select("div.markdown-body").first();
        if (descriptionElement != null) {
            for (Element child : descriptionElement.children()) {
                if (child.tagName().contains("h") && !child.text().contains("Impact")) break;
                else if (child.tagName().contains("h") && child.text().contains("Impact")) continue;
                description.append(child.text());
            }
        }

        // get publish and modified dates in top subhead description
        String publishDate = "";
        String lastModifiedDate = "";
        Element subhead = doc.select("div.Subhead-description").first();
        if (subhead != null) {
            Elements dates = subhead.select("relative-time");
            // non-formatted original dates found in 'title' attribute of our relative-date tags found
            if (dates.size() > 0) {
                publishDate = dates.get(0).attr("title");
                if (dates.size() > 1)
                    lastModifiedDate = dates.get(1).attr("title");
            }
        }

        vulnList.add(new CompositeVulnerability(
           0, sSourceURL, cveId, null, publishDate, lastModifiedDate, description.toString(), sourceDomainName
        ));

        return vulnList;
    }
}
