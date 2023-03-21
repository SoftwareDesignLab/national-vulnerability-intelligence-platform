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

public class IntelParser extends AbstractCveParser {

    /**
     * Parse advisories listed to intel.com/content/www/us/en/security-center/default.html
     * Ex: <a href="https://www.intel.com/content/www/us/en/security-center/advisory/intel-sa-00714.html">...</a>
     * @param domainName - intel domain
     */
    public IntelParser(String domainName) { sourceDomainName = domainName; }

    @Override
    public List<CompositeVulnerability> parseWebPage(String sSourceURL, String sCVEContentHTML) {

        List<CompositeVulnerability> vulnList = new ArrayList<>();

        Document doc = Jsoup.parse(sCVEContentHTML);

        // get the top table
        Element advTable = doc.select("table").first();
        // get publish date from table
        Element release = Objects.requireNonNull(advTable).children().select("td:contains(release)").first();
        Element publishEl = Objects.requireNonNull(release).nextElementSibling();
        String publishDate = Objects.requireNonNull(publishEl).text();
        // get last modified date from table
        Element revised = advTable.children().select("td:contains(revised)").first();
        Element lastModifiedEl = Objects.requireNonNull(revised).nextElementSibling();
        String lastModifiedDate = Objects.requireNonNull(lastModifiedEl).text();

        // looks to follow the format:
        // CVEID
        // Description
        // CVSS Base Score
        // CVSS Vector

        // extract foreach CVEID
        Elements cves = doc.select("p:contains(CVEID:)");
        for (Element cve : cves) {
            String line = cve.text();
            String cveID = line.split(": ")[1];
            Element next = cve.nextElementSibling();
            String description = Objects.requireNonNull(next).text();
            description = description.split(": ")[1];
            vulnList.add(new CompositeVulnerability(
                0, sSourceURL, cveID, null, publishDate, lastModifiedDate, description, sourceDomainName
            ));
        }

        return vulnList;
    }
}
