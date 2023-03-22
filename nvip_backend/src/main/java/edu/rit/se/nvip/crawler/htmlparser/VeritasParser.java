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
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class VeritasParser extends AbstractCveParser {

    /**
     * Parse advisories listed to veritas.com/content/support/en_US/security/
     * @param domainName - veritas domain
     */
    public VeritasParser(String domainName) { sourceDomainName = domainName; }

    @Override
    public List<CompositeVulnerability> parseWebPage(String sSourceURL, String sCVEContentHTML) {

        List<CompositeVulnerability> vulnList = new ArrayList<>();

        Document doc = Jsoup.parse(sCVEContentHTML);

        // parse issues section for CVEs
        Element issuesHeader = doc.select("h3:contains(Issues)").first();
        // if no issues section, this page does not have cves
        if (issuesHeader == null) return vulnList;
        // parse each issue in CVE section - contained in unordered list tags
        Elements cveElements = new Elements();
        Element next = issuesHeader.nextElementSibling();
        while (next != null) {
            if (next.tagName().contains("h") && next.text().contains("Notes"))
                break;
            if (next.tagName().contains("ul"))
                cveElements.add(next);
            next = next.nextElementSibling();
        }

        // get each CVE from each ul
        ArrayList<String> cves = new ArrayList<>();
        for (Element cveEl: cveElements) {
            Element idEl = cveEl.children().select("li:contains(CVE-)").first();
            if (idEl == null) continue;
            cves.add(
                    idEl.text().split("ID: ")[1].trim()
            );
        }

        // have our description be Summary + Notes sections
        String description = "";
        Element summaryHeader = doc.select("h3:contains(Summary)").first();
        if (summaryHeader != null) {
            Element summaryPara = summaryHeader.nextElementSibling();
            if (summaryPara != null)
                description += summaryPara.text();
        }

        Element notesHeader = doc.select("h3:contains(Notes)").first();
        if (notesHeader != null) {
            Element notesPara = notesHeader.nextElementSibling();
            if (notesPara != null )
                description += notesPara.text();
        }

        // get dates from revision history
        // publish date is first date 'Initial Public Release'
        // last update date is last date in revision history list
        // watch out for things like 'End of September 2022'
        String publishDate = "";
        String lastModifiedDate = "";
        Element revHistoryHeader = doc.select("h3:contains(Revision History)").first();
        if (revHistoryHeader != null) {
            revHistoryHeader = revHistoryHeader.nextElementSibling();
            if (revHistoryHeader != null) {
                Elements revChildren = revHistoryHeader.children();
                Elements revList = revChildren.select("li");
                Pattern pattern = Pattern.compile("(January|February|March|April|May|June|July|August|September|October|November|December)[ ]?(0[1-9]|[1-2][0-9]|3[0-1])?[,]?[ ](20)[0-9]{2}");
                Element pubEl = revList.first();
                if (pubEl != null) {
                    Matcher pubMatcher = pattern.matcher(pubEl.text());
                    if (pubMatcher.find())
                        publishDate = lastModifiedDate = pubMatcher.group(0);
                }
                Element lastEl = revList.last();
                if (lastEl != null) {
                    Matcher updateMatcher = pattern.matcher(lastEl.text());
                    if (updateMatcher.find())
                        lastModifiedDate = updateMatcher.group(0);
                }
            }
        }

        for (String cve : cves)
            vulnList.add(new CompositeVulnerability(
                    0, sSourceURL, cve, null, publishDate, lastModifiedDate, description, sourceDomainName
            ));

        return vulnList;
    }
}
