package edu.rit.se.nvip.crawler.htmlparser;

import edu.rit.se.nvip.model.CompositeVulnerability;
import org.jsoup.Jsoup;
import org.jsoup.nodes.Document;
import org.jsoup.nodes.Element;
import org.jsoup.select.Elements;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Set;

public class AsustorParser extends AbstractCveParser {

    /**
     * Parse advisories listed to asustor.com/security/security_advisory
     * @param domainName - asustor.com domain,
     *                   like: asustor.com/security/security_advisory_detail?id=20 for example
     */
    public AsustorParser(String domainName) {
        sourceDomainName = domainName;
    }

    @Override
    public List<CompositeVulnerability> parseWebPage(String sSourceURL, String sCVEContentHTML) {

        List<CompositeVulnerability> vulnList = new ArrayList<>();
        Document doc = Jsoup.parse(sCVEContentHTML);

        // get CVEs in ul under Detail h3 tag
        Element cveListHeader = doc.select("h3:contains(Detail)").first();
        if (cveListHeader == null) return vulnList;
        Element cveList = cveListHeader.nextElementSibling();
        if (cveList == null) return vulnList;
        Set<String> cves = getCVEs(cveList.text());
        // if no CVEs found in detail list, return
        if (cves.isEmpty()) return vulnList;

        // get publish date and last updated from "Revision" table down below
        String publishDate = "";
        String lastUpdatedDate = "";
        Element revisionHeader = doc.select("h4:contains(Revision)").first();
        if (revisionHeader != null) {
            Element revisionTable = revisionHeader.nextElementSibling();
            if (revisionTable != null) {
                Element publishRow = revisionTable.children().select("tr").get(1);
                Element lastUpdatedRow = revisionTable.children().select("tr").last();
                if (publishRow != null) {
                    publishDate = publishRow.children().get(1).text();
                    if (lastUpdatedRow != null) {
                        lastUpdatedDate = lastUpdatedRow.children().get(1).text();
                    }
                    else lastUpdatedDate = publishDate;
                }
            }
        }

        // parse description foreach CVE under Detail section
        // descriptions in the form of:
        // • CVE-XXXX-XXXX
        //   • Severity: XXXX
        //   • Description text XXXX
        // combine severity with description text
        HashMap<String, String> descriptions = new HashMap<>();
        // get the first ul after Detail h3
        Element detailHeader = doc.select("h3:contains(Detail)").first();
        if (detailHeader != null) {
            Element descList = detailHeader.nextElementSibling();
            // ensure it is ul
            while (descList != null && !descList.tagName().equals("ul"))
                descList = descList.nextElementSibling();
            if (descList != null) {
                Elements descListItems = descList.children().select("li");
                for (Element cveDescEl : descListItems) {
                    String cve = cveDescEl.children().select(":contains(CVE-)").text();
                    Elements cveDescBullets = cveDescEl.children().select("li");
                    StringBuilder thisDesc = new StringBuilder();
                    for (Element bullet : cveDescBullets) {
                        thisDesc.append(bullet.text());
                    }
                    descriptions.put(cve, thisDesc.toString());
                }
            }
        }

        // create CompositeVulnerability foreach CVE and add to vulnList
        for (String cve : cves) {
            String description = descriptions.get(cve);
            CompositeVulnerability vuln = new CompositeVulnerability(
                    0, sSourceURL, cve, null, publishDate, lastUpdatedDate, description, sourceDomainName
            );
            vulnList.add(vuln);
        }

        return vulnList;
    }
}
