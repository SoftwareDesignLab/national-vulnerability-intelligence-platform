package edu.rit.se.nvip.crawler.htmlparser;

import edu.rit.se.nvip.model.CompositeVulnerability;
import org.jsoup.Jsoup;
import org.jsoup.nodes.Document;
import org.jsoup.nodes.Element;

import java.util.ArrayList;
import java.util.List;
import java.util.Set;

public class DotCMSParser extends AbstractCveParser {

    /**
     * Parse advisories listed to dotcms.com/docs/latest/known-security-issues
     * @param domainName - dotCMS domain
     */
    public DotCMSParser(String domainName) { sourceDomainName = domainName; }

    @Override
    public List<CompositeVulnerability> parseWebPage(String sSourceURL, String sCVEContentHTML) {

        List<CompositeVulnerability> vulnList = new ArrayList<>();
        Document doc = Jsoup.parse(sCVEContentHTML);

        // get CVES from references part of page
        Element referencesHeader = doc.select("th:contains(References)").first();
        if (referencesHeader == null) return vulnList;
        Element referencesTD = referencesHeader.nextElementSibling();
        if (referencesTD == null) return vulnList;
        Set<String> cves = getCVEs(referencesTD.text());
        // if no cves, return empty list
        if (cves.size() == 0) return vulnList;

        // get date from date row of table
        String date = "";
        Element dateHeader = doc.select("th:contains(Date:)").first();
        if (dateHeader != null) {
            Element dateTD = dateHeader.nextElementSibling();
            if (dateTD != null) {
                date = dateTD.text();
            }
        }

        // get description from description row of table
        String description = "";
        Element descriptionHeader = doc.select("th:contains(Description:)").first();
        if (descriptionHeader != null) {
            Element descriptionTD = descriptionHeader.nextElementSibling();
            if (descriptionTD != null) {
                description = descriptionTD.text();
            }
        }

        for (String cve : cves)
            vulnList.add(new CompositeVulnerability(
                    0, sSourceURL, cve, null, date, date, description, sourceDomainName
            ));

        return vulnList;
    }
}
