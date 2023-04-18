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

import java.util.ArrayList;
import java.util.List;

public class AliasRoboParser extends AbstractCveParser {

    /**
     * Parse advisories listed to github.com/aliasrobotics/RVD/issues
     * @param domainName - github alias domain
     */
    public AliasRoboParser(String domainName) { sourceDomainName = domainName; }

    @Override
    public List<CompositeVulnerability> parseWebPage(String sSourceURL, String sCVEContentHTML) {

        List<CompositeVulnerability> vulnList = new ArrayList<>();

        Document doc = Jsoup.parse(sCVEContentHTML);

        // grab labels from sidebar
        Element sidebar = doc.select("div.Layout-sidebar").first();
        if (sidebar == null) return vulnList;
        Element labelHeader = sidebar.children().select("div.discussion-sidebar-heading:contains(Labels)").first();
        if (labelHeader == null) return vulnList;
        Element labels = labelHeader.nextElementSibling();
        // if labels contains vulnerability label, continue
        if (labels == null) return vulnList;
        List<String> eachLabel = labels.children().select("span").eachText();
        if (!eachLabel.contains("vulnerability")) return vulnList;

        // get publish date from top 'opened' date
        String publishDate = "";
        Element header = doc.select("div#partial-discussion-header").first();
        if (header != null) {
            Element date = header.children().select("relative-time").first();
            if (date != null)
                publishDate = date.attr("title");
        }

        // get last modified date from bottommost github feed date
        String lastModifiedDate = "";
        // get CVE id from "cve": or cve:
        String cveId = "";
        // get description from "description": or description:
        String description = "";

        // get element relating to discussion where we can find last date and full vuln comment
        Element discussionEl = doc.select("div.js-discussion").first();

        if (discussionEl != null) {
            Element lastDate = discussionEl.children().select("relative-time").last();
            if (lastDate != null)
                lastModifiedDate = lastDate.attr("title");
            Element textBlockEl = discussionEl.children().select("td").first();
            if (textBlockEl != null) {
                String textBlock = textBlockEl.text();

                // if we are in JSON notation
                String cveSplit;
                if (textBlock.contains("{")) {
                    cveSplit = textBlock.split("\"cve\":")[1];
                    cveId = cveSplit.split(",")[0];
                    cveId = cveId.replace("\"", "");
                    cveId = cveId.trim();

                    String descSplit = textBlock.split("\"description\":")[1];
                    description = descSplit.split(",")[0];
                }
                // otherwise we are in YAML notation
                else {
                    cveSplit = textBlock
                            .split("cve: ")[1]
                            .replace("\r", "");
                    cveId = cveSplit.split("\n")[0];

                    String descSplit = textBlock
                            .split("description: ")[1]
                            .replace("\r", "");
                    description = descSplit.split("\n")[0];
                }
                description = description.replace("\"", "");
                description = description.trim();
            }
        }
        else
            lastModifiedDate = publishDate;

        vulnList.add(new CompositeVulnerability(
                0, sSourceURL, cveId, null, publishDate, lastModifiedDate, description, sourceDomainName
        ));

        return vulnList;
    }
}
