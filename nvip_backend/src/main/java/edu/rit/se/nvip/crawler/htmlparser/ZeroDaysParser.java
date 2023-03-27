package edu.rit.se.nvip.crawler.htmlparser;

import edu.rit.se.nvip.model.CompositeVulnerability;
import org.jsoup.Jsoup;
import org.jsoup.nodes.Document;
import org.jsoup.nodes.Element;

import java.util.ArrayList;
import java.util.List;

public class ZeroDaysParser extends AbstractCveParser {

    /**
     * Parse advisories listed to cybersecurityworks.com/zerodays-vulnerability-list/
     * @param domainName - zero days domain
     */
    public ZeroDaysParser(String domainName) { sourceDomainName = domainName; }

    @Override
    public List<CompositeVulnerability> parseWebPage(String sSourceURL, String sCVEContentHTML) {

        List<CompositeVulnerability> vulnList = new ArrayList<>();
        Document doc = Jsoup.parse(sCVEContentHTML);

        Element rightColumn = doc.select("div.second-half").first();
        if (rightColumn == null) return vulnList;

        // get CVE ID from right column
        Element cveEl = rightColumn.children().select("li:contains(CVE Number)").first();
        if (cveEl == null) return vulnList;
        Element cveIdEl = cveEl.children().select("span").first();
        if (cveIdEl == null) return vulnList;
        String cve = cveIdEl.text();

        // get publish date from top row
        String publishDate = "";
        Element dateHeader = doc.select("h4:contains(Date)").first();
        if (dateHeader != null) {
            Element dateEl = dateHeader.nextElementSibling();
            if (dateEl != null)
                publishDate = dateEl.text();
        }

        // get description in p tags under Description header
        Element descHeader = doc.select("h3:contains(Description)").first();
//        String description = doc
        StringBuilder description = new StringBuilder();
        if (descHeader != null) {
            Element nextDesc = descHeader.nextElementSibling();
            while (nextDesc != null) {
                description.append(nextDesc.text());
                nextDesc = nextDesc.nextElementSibling();
            }
        }

        // get last modified date from last date in timeline on the bottom
        String lastModifiedDate = publishDate;
        Element timeline = doc.select("div#timeline").last();
        if (timeline != null) {
            Element lastDate = timeline.children().select("li").last();
            if (lastDate != null)
                lastModifiedDate = lastDate.children().select("strong").text().replace(":", "");
        }

        vulnList.add(new CompositeVulnerability(
                0, sSourceURL, cve, null, publishDate, lastModifiedDate, description.toString(), sourceDomainName
        ));

        return vulnList;
    }
}
