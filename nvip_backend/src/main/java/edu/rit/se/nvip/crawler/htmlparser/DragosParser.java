package edu.rit.se.nvip.crawler.htmlparser;

import edu.rit.se.nvip.model.CompositeVulnerability;
import org.jsoup.Jsoup;
import org.jsoup.nodes.Document;
import org.jsoup.nodes.Element;

import java.util.ArrayList;
import java.util.List;

public class DragosParser extends AbstractCveParser {

    /**
     * Parse advisories listed to dragos.com/advisories
     * @param domainName dragos domain
     */
    public DragosParser(String domainName) { sourceDomainName = domainName; }

    @Override
    public List<CompositeVulnerability> parseWebPage(String sSourceURL, String sCVEContentHTML) {

        List<CompositeVulnerability> vulnList = new ArrayList<>();
        Document doc = Jsoup.parse(sCVEContentHTML);

        Element cveColumn = doc.select("p.sa-title-sm:contains(CVE)").first();
        if (cveColumn == null) return vulnList;
        // get all elements after CVE ID in column
        // if empty or says N/A return empty list
        Element nextInColumn = cveColumn.nextElementSibling();
        if (nextInColumn == null || nextInColumn.text().contains("N/A")) return vulnList;
        ArrayList<String> cves = new ArrayList<>();
        while (nextInColumn != null) {
            cves.add(nextInColumn.text().trim());
            nextInColumn = nextInColumn.nextElementSibling();
        }

        // no desc on these pages, have the desc be the page title
        String title = "";
        Element titleEl = doc.select("h1.advisory_intro__title").first();
        if (titleEl != null)
            title = titleEl.text();

        String date = "";
        Element dateEl = doc.select(":matchesOwn([0-9]+[-/][0-9]+[-/][0-9]+)").first();
        if (dateEl != null)
            date = dateEl.text();

        for (String cve : cves)
            vulnList.add(new CompositeVulnerability(
                    0, sSourceURL, cve, null, date, date, title, sourceDomainName
            ));

        return vulnList;
    }
}
