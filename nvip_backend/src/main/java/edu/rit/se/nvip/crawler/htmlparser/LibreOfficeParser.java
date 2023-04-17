package edu.rit.se.nvip.crawler.htmlparser;

import edu.rit.se.nvip.model.CompositeVulnerability;
import org.jsoup.Jsoup;
import org.jsoup.nodes.Document;
import org.jsoup.nodes.Element;

import java.util.ArrayList;
import java.util.List;

public class LibreOfficeParser extends AbstractCveParser {

    /**
     * Parse advisories listed to libreoffice.org/about-us/security/advisories/
     * @param domainName - LibreOffice domain
     */
    public LibreOfficeParser(String domainName) { sourceDomainName = domainName; }

    @Override
    public List<CompositeVulnerability> parseWebPage(String sSourceURL, String sCVEContentHTML) {

        List<CompositeVulnerability> vulnList = new ArrayList<>();
        Document doc = Jsoup.parse(sCVEContentHTML);

        // get CVE from title h3 tag
        Element cveEl = doc.select("h3:contains(CVE-)").first();
        if (cveEl == null) return vulnList; // no CVEs found, return empty list, we aren't on a CVE page
        String cve = cveEl.text();
        // get date from Announced:
        String date = "";
        Element dateElement = doc.select("p:contains(Announced:)").first();
        if (dateElement != null)
            date = dateElement.text().replace("Announced: ", "");

        // get description under Description: tag
        String description = "";
        Element descriptionHeaderElement = doc.select("p:contains(Description:)").first();
        if (descriptionHeaderElement != null) {
            Element descriptionElement = descriptionHeaderElement.nextElementSibling();
            if (descriptionElement != null)
                description = descriptionElement.text();
        }
        // add to vulns list
        vulnList.add(new CompositeVulnerability(
                0, sSourceURL, cve, null, date, date, description, sourceDomainName
        ));

        return vulnList;
    }
}
