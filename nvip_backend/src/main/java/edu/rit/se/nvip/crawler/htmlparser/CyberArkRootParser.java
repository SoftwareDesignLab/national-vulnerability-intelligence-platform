package edu.rit.se.nvip.crawler.htmlparser;

import edu.rit.se.nvip.crawler.QuickCveCrawler;
import edu.rit.se.nvip.model.CompositeVulnerability;
import org.jsoup.Jsoup;
import org.jsoup.nodes.Document;
import org.jsoup.nodes.Element;
import org.jsoup.select.Elements;

import java.util.ArrayList;
import java.util.List;

public class CyberArkRootParser extends AbstractCveParser {

    /**
     * Parse bulletin table in ampere product security page
     * @param rootDomain - labs.cyberark.com/cyberark-labs-security-advisories/
     */
    public CyberArkRootParser(String rootDomain) { sourceDomainName = rootDomain; }

    /**
     * Takes in tr element, locates td associated with given string and grabs what
     * is inside that cell
     * @return - text inside cell
     */
    private String getCellValue(Element row, String colIdentifier) {
        // each cell contains a span that references the column it is in
        Element cell = row.children().select("td:contains(" + colIdentifier + ")").first();
        if (cell == null) return "";
        String cellText = cell.text();
        String[] valueSplit = cellText.split(colIdentifier);
        // 1 or less in split means there is no value inside this table cell
        if (valueSplit.length > 1)
            return valueSplit[1].trim();
        return "";
    }

    /**
     * parse root CyberArk vuln web page table
     * @param sSourceURL - labs.cyberark.com/cyberark-labs-security-advisories/
     * @param sCVEContentHTML - parsed html of source url
     * @return - CVE list from bulletin table
     */
    @Override
    public List<CompositeVulnerability> parseWebPage(String sSourceURL, String sCVEContentHTML) {

        List<CompositeVulnerability> vulnList = new ArrayList<>();
        Document doc = Jsoup.parse(sCVEContentHTML);

        // table columns are the following:
        // Year, ID, CVE, Vendor, Product, CWE, Researcher, Read More, Date

        // get table rows
        Element table = doc.select("table#tableOne").first();
        if (table == null) return vulnList;
        Element tableBody = table.children().select("tbody").first();
        if (tableBody == null) return vulnList;
        Elements rows = tableBody.children();

        for (Element row : rows) {
            // get CVE ID from row
            String cveId = getCellValue(row, "CVE:");
            // get date from row
            String date = getCellValue(row, "Date:");
            // have our description be a combination of
            // Vendor, Product, and CWE columns
            String vendor = getCellValue(row, "Vendor:");
            String product = getCellValue(row, "Product:");
            String cwe = getCellValue(row, "Vulnerability Type / CWE:");
            String description = vendor + " " + product + " " + cwe;

            vulnList.add(new CompositeVulnerability(
                    0, sSourceURL, cveId, null, date, date, description, sourceDomainName
            ));
        }

        return vulnList;
    }

}
