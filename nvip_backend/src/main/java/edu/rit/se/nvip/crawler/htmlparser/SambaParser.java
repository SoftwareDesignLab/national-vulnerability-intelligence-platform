package edu.rit.se.nvip.crawler.htmlparser;

import edu.rit.se.nvip.model.CompositeVulnerability;
import org.jsoup.Jsoup;
import org.jsoup.nodes.Document;
import org.jsoup.nodes.Element;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

public class SambaParser extends AbstractCveParser {

    /**
     * Parse advisories in announcements column
     * listed to samba.org/samba/history/security.html
     * @param domainName - Samba domain
     */
    public SambaParser(String domainName) { sourceDomainName = domainName; }

    @Override
    public List<CompositeVulnerability> parseWebPage(String sSourceURL, String sCVEContentHTML) {

        // ignore links to patch files
        if (sSourceURL.contains(".patch")) return null;

        // otherwise parse a page linked under "Announcements"
        List<CompositeVulnerability> vulnList = new ArrayList<>();
        Document doc = Jsoup.parse(sCVEContentHTML);

        // each page has a title h2 with the rest being text
        Element titleEl = doc.select("h2").first();
        if (titleEl == null) return vulnList; // no CVEs found, return empty list, we aren't on a CVE page
        String cve = titleEl.text().replace(".html:", "").trim();

        Element textEl = doc.select("pre").first();
        if (textEl == null) return vulnList;
        String pageText = textEl.text();
        pageText = pageText.replace("\r", "");

        // grab description between ===Description=== and ===Patch Availability===
        StringBuilder description = new StringBuilder();
        String[] lines = pageText.split("\n");
        // get idx of Description and + 1 to skip the ======= after it...
        // go until we reach another =======
        int descIdx = Arrays.asList(lines).indexOf("Description");
        for (int i = descIdx + 2; i < lines.length; i++) {
            if (lines[i].startsWith("======")) break;
            description.append(lines[i]).append(" ");
        }

        // dates are not found on these individual pages, only the root
        // we would need a way to grab those too

        // for now just add to list
        vulnList.add(new CompositeVulnerability(
                0, sSourceURL, cve, null, "", "", description.toString(), sourceDomainName
        ));

        return vulnList;
    }
}
