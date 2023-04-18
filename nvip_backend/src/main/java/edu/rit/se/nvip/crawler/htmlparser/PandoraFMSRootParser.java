package edu.rit.se.nvip.crawler.htmlparser;

import edu.rit.se.nvip.model.CompositeVulnerability;
import org.jsoup.Jsoup;
import org.jsoup.nodes.Document;
import org.jsoup.nodes.Element;
import org.jsoup.select.Elements;

import java.util.ArrayList;
import java.util.List;

public class PandoraFMSRootParser extends AbstractCveParser {

    /**
     * Parse advisories listed to pandorafms.com/en/security/common-vulnerabilities-and-exposures/
     * @param domainName - pandorafms domain
     */
    public PandoraFMSRootParser(String domainName) { sourceDomainName = domainName; }

    @Override
    public List<CompositeVulnerability> parseWebPage(String sSourceURL, String sCVEContentHTML) {

        List<CompositeVulnerability> vulnList = new ArrayList<>();
        Document doc = Jsoup.parse(sCVEContentHTML);

        // get rows in table
        Elements rows = doc.select("tbody").select("tr");
        for(Element row : rows) {
            Elements cells = row.children().select("td");
            if (cells.size() < 3) continue; // skip if not enough columns (shouldn't happen)
            // get CVE from first column
            String cve = cells.get(0).text();
            // get description from 'Vulnerability details' in second column
            String description = cells.get(1).text();
            // get Publication date from third column
            String publishDate = cells.get(2).text();
            // add to vulns list
            vulnList.add(new CompositeVulnerability(
                    0, sSourceURL, cve, null, publishDate, publishDate, description, sourceDomainName
            ));
        }


        return vulnList;
    }
}
