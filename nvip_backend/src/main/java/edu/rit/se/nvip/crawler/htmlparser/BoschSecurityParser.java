package edu.rit.se.nvip.crawler.htmlparser;

import edu.rit.se.nvip.model.CompositeVulnerability;
import org.jsoup.Jsoup;
import org.jsoup.nodes.Document;
import org.jsoup.nodes.Element;
import org.jsoup.select.Elements;

import java.util.ArrayList;
import java.util.List;
import java.util.Objects;

/**
 * Web Parser for Bosch Security Advisory Boards
 * @author aep7128
 */
public class BoschSecurityParser extends AbstractCveParser{


    public BoschSecurityParser(String domainName) {
        sourceDomainName = domainName;
    }

    /**
     * Parse Bosch Security Advisory
     * (ex. https://psirt.bosch.com/security-advisories/bosch-sa-247053-bt.html)
     * (ex. https://psirt.bosch.com/security-advisories/bosch-sa-464066-bt.html)
     * TODO: Grab CWEs for each CVE
     * @param sSourceURL
     * @param sCVEContentHTML
     * @return
     */
    @Override
    public List<CompositeVulnerability> parseWebPage(String sSourceURL, String sCVEContentHTML) {

        List<CompositeVulnerability> vulns = new ArrayList<>();

        Document doc = Jsoup.parse(sCVEContentHTML);

        Elements dates = Objects.requireNonNull(Objects.requireNonNull(doc.getElementById("advisory-information")).nextElementSibling()).children();

        String publishDate = dates.get(2).children().get(1).text().substring(10).trim();
        String updateDate = dates.get(3).children().get(1).text().substring(13).trim();

        Elements headers = doc.getElementsByTag("h3");
        for (Element header: headers) {
            if (header.id().contains("cve-")) {
                String cveId = header.id().toUpperCase();
                String description = Objects.requireNonNull(header.nextElementSibling()).text().substring(17);

                vulns.add(new CompositeVulnerability(0, sSourceURL, cveId, null, publishDate, updateDate, description, sourceDomainName));
            }
        }

        return vulns;
    }
}
