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
        // get publish date from Announced:
        String publishDate = "";
        Element dateElement = doc.select("p:contains(Announced:)").first();
        if (dateElement != null)
            publishDate = getCVEDate(dateElement.text());

        // get last modified date from Updated: if it exists
        String lastModifiedDate = publishDate;
        Element updateDateElement = doc.select("p:contains(Updated:)").first();
        if (updateDateElement != null)
            lastModifiedDate = getCVEDate(updateDateElement.text());

        // get description under Description: tag
        String description = "";
        Element descriptionElement = doc.select("p:contains(Description:)").first();
        // sometimes this element is contained with the "Fixed in:" p tag and sometimes it is contained with the
        // description itself and sometimes it is in with the entire text
        // so we can just grab the entire text and split by "Description:"
        String[] descSplit = doc.text().split("Description:");
        if (descSplit.length > 1) {
            // go until Credits: or until References: or if neither exist just go until the end
            description = descSplit[1];
            String[] creditSplit = description.split("Credits:");
            String[] referenceSplit = description.split("References:");
            if (creditSplit.length > 1 || referenceSplit.length > 1) {
                if (creditSplit.length > 1) description = creditSplit[0];
                else description = referenceSplit[0];
            }
        }
        // as a fail safe take the entire article as description - these are usually short
        else
            description = doc.text();
        // add to vulns list
        vulnList.add(new CompositeVulnerability(
                0, sSourceURL, cve, null, publishDate, lastModifiedDate, description, sourceDomainName
        ));

        return vulnList;
    }
}
