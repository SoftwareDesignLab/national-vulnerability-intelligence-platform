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
import java.util.Objects;

public class TibcoParser extends AbstractCveParser {

    /**
     * Parse advisorites listed to Tibco.com/services/support/advisories
     * Ex: <a href="https://www.tibco.com/support/advisories/2023/02/tibco-security-advisory-february-22-2023-tibco-businessconnect-cve-2022-41567">...</a>
     * @param domainName - tibco domain
     */
    public TibcoParser(String domainName) { sourceDomainName = domainName; }

    @Override
    public List<CompositeVulnerability> parseWebPage(String sSourceURL, String sCVEContentHTML) {

        List<CompositeVulnerability> vulnList = new ArrayList<>();

        Document doc = Jsoup.parse(sCVEContentHTML);

        // get dates from "Original release date:" and "Last revised"
        Element para = doc.select("p:contains(Original release)").first();
        String html = Objects.requireNonNull(para).html();
        String[] lines = html.split("<br>");
        String publishDate = lines[0].split("date: ")[1].trim();
        // if "Last revised" is "---" or empty, use the date from "original release"
        String[] modLine = lines[1].split("revised:");
        String lastModifiedDate = modLine[1].trim();
        if (lastModifiedDate.contains("---") || lastModifiedDate.equals(""))
            lastModifiedDate = publishDate;

        // get CVE id contained in a tag in the above para
        Element cve = para.children().select("a:contains(CVE-)").first();
        if (cve == null) return vulnList;
        String cveId = cve.text();

        // get Description text under h4 Description header
        String description;
        Element descHeader = doc.select("h4:contains(Description)").first();
        if (descHeader == null) description = "";
        else description = Objects.requireNonNull(
                Objects.requireNonNull(
                        descHeader.nextElementSibling()).nextElementSibling()).text();

        vulnList.add(new CompositeVulnerability(
                0, sSourceURL, cveId, null, publishDate, lastModifiedDate, description, sourceDomainName
        ));

        return vulnList;
    }
}
