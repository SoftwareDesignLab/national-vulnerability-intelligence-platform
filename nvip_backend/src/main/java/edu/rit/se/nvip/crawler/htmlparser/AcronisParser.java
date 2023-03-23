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
import java.util.HashSet;
import java.util.List;

public class AcronisParser extends AbstractCveParser {

    /**
     * Parse advisories listed to security-advisory.acronis.com/advisories
     * @param domainName - acronis domain
     */
    public AcronisParser(String domainName) { sourceDomainName = domainName; }

    @Override
    public List<CompositeVulnerability> parseWebPage(String sSourceURL, String sCVEContentHTML) {

        List<CompositeVulnerability> vulnList = new ArrayList<>();

        Document doc = Jsoup.parse(sCVEContentHTML);

        // check for CVE contained in either top tags or description section
        HashSet<String> cves = new HashSet<>();
        // top tags
        Elements tags = doc.select("div.tag-cloud").first().children().select("span.el-tag__text");
        for (Element tag : tags) {
            if (tag.text().contains("CVE-"))
                cves.add(tag.text());
        }

        String description = "";
        // if a description is present, check for CVE-, add to description
        Elements descHeaders = doc.select("h1:contains(Description)");
        if (descHeaders.size() > 0) {
            Element para = descHeaders.first().nextElementSibling();
            if (para != null) {
                String paraText = para.text();
                description += paraText;
                if (paraText.contains("CVE-")) {
                    String[] paraSplit = paraText.split(" ");
                    for (String s : paraSplit) {
                        if (s.contains("CVE-"))
                            cves.add(s.replace(".", ""));
                    }
                }
            }
        }

        // add title to our description (a lot of these pages don't have a description to begin with)
        Element titleEl = doc.select("div.article-summary").first();
        if (titleEl != null)
            description += titleEl.text();

        // get publish date from top 'article-date' div tag
        Element dateEl = doc.select("div.article-date").first();
        String publishDate = "";
        if (dateEl != null)
            publishDate = dateEl.text();

        // get last updated from bottom section
        String lastModifiedDate = "";
        Element lastUpdate = doc.select("section:contains(Last up)").first();
        if (lastUpdate != null) {
            String dateSplit = lastUpdate.text().split("update:")[1];
            lastModifiedDate = dateSplit.split("at")[0].trim();
        }
        else
            lastModifiedDate = publishDate;

        for (String cve : cves)
            vulnList.add(new CompositeVulnerability(
                    0, sSourceURL, cve, null, publishDate, lastModifiedDate, description, sourceDomainName
            ));

        return vulnList;
    }
}
