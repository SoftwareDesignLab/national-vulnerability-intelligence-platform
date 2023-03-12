package edu.rit.se.nvip.mitre.capec;

import edu.rit.se.nvip.model.CompositeVulnerability;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Set;

import edu.rit.se.nvip.crawler.QuickCveCrawler;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.jsoup.Jsoup;
import org.jsoup.nodes.Document;
import org.jsoup.nodes.Element;
import org.jsoup.select.Elements;

public class CapecParser {

    private String url;
    private String html;

    private Logger logger = LogManager.getLogger(getClass().getSimpleName());

    /**
     * Link -> HTML and parse HTML for CAPEC enums, output list of Capec
     * @param page - capec.mitre.org 'Comprehensive CAPEC DICTIONARY'
     */
    public CapecParser() {
        // This page contains all:
        // 559 Attack Patterns
        // 21 Categories
        // 13 Views
        // for a total of : 593
        this.url = "https://capec.mitre.org/data/slices/2000.html";

    }

    public static void main (String[] args) {
        CapecParser c = new CapecParser();
        List<Capec> capecList = c.parseWebPage();
    }

    private Element getExpandBlock(Elements children) {
        return children.select("div.expandblock").first();
    }

    /**
     * Extracts text from an expandblock
     * in a CAPEC description child div
     */
    private String getBlockTextSimple(Elements capecChildren, String id) {
        Element thisBlock = capecChildren.select("div#" + id).first();
        if (thisBlock != null)
            return getExpandBlock(thisBlock.children()).text();
        return "";
    }

    /**
     * Extracts two column table from an
     * expandbock dropdown in a CAPEC Description
     */
    private HashMap<String, String> getBlockTable(Elements capecChildren, String id, String headerName) {
        HashMap<String, String> table = new HashMap<>();
        Element taxEl = capecChildren.select("div#" + id).first();
        if (taxEl != null) {
            Elements rows = taxEl.children().select("tr");
            for (Element row : rows) {
                // skip past the table header
                if (row.text().contains(headerName)) continue;
                String key = row.child(0).text();
                String val = row.child(1).text();
                table.put(key, val);
            }
        }

        return table;
    }

    public List<Capec> parseWebPage() {

        QuickCveCrawler q = new QuickCveCrawler();
        String html = q.getContentFromUrl(this.url);
        logger.info("Parsing page: {}", this.url);

        List<Capec> capecs = new ArrayList<>();

        Document doc = Jsoup.parse(html);

        Elements capecDescriptions = doc.select("div#CAPECDefinition");
        for (Element capecDesc : capecDescriptions) {
            Element capecHeader = capecDesc.previousElementSibling();
            if (capecHeader != null) {
                String header = capecHeader.text();
                // ignore Categories and Views, look for Attack Patterns
                if (!header.contains("VIEW") && !header.contains("CATEGORY")) {
                    logger.info("CAPEC Found: {}", header);
                    Elements capecChildren = capecDesc.children();

                    // get ID and Abstraction from title div
                    Element titleEl = capecChildren.select("div.title").first();
                    String titleText = titleEl.text();
                    String[] titleTextSplit = titleText.split("Abstraction: ");
                    String abstraction = titleTextSplit[1];
                    String id = titleTextSplit[0].split(": ")[1];


                    // get description
                    String description = getBlockTextSimple(capecChildren, "Description");
                    // if extended description add it to description
                    description += getBlockTextSimple(capecChildren, "Extended_Description");

                    // get likelihood of attack
                    String likelihood = getBlockTextSimple(capecChildren, "Likelihood_Of_Attack");

                    // get typical severity
                    String severity = getBlockTextSimple(capecChildren, "Typical_Severity");

                    // get relationships
                    ArrayList<CapecRelationship> relationships = new ArrayList<>();
                    Element relatEl = capecChildren.select("div#Relationships").first();
                    Element relTable = null;
                    if (relatEl != null)
                        relTable = relatEl.children().select("table").first();
                    if (relTable != null && relTable.text().contains("Nature")) {
                        Elements rows = relTable.children().select("tr");
                        for (Element row : rows) {
                            // skip past the table header
                            if (row.text().contains("Nature")) continue;
                            String nature = row.child(0).text();
                            String type = row.child(1).select("img").first().attr("alt");
                            if (type.equals("View")) continue;
                            String rowID = row.child(2).text();
                            String name = row.child(3).text();
                            relationships.add(new CapecRelationship(
                                    nature, type, rowID, name
                            ));
                        }
                    }


                    // get execution flow
                    //TODO:

                    // get prerequisites
                    ArrayList<String> prereqs = new ArrayList<>();
                    Element prereqEl = capecChildren.select("div#Prerequisites").first();
                    if (prereqEl != null) {
                        Element preReqBlock = getExpandBlock(prereqEl.children());
                        // get prereq entries from table element
                        Elements tdEls = preReqBlock.children().select("td");
                        prereqs = new ArrayList<>(tdEls.eachText());
                    }

                    // get skills required
                    //TODO:

                    // get resources required
                    String resources = getBlockTextSimple(capecChildren, "Resources_Required");

                    // get mitigations
                    String mitigations = getBlockTextSimple(capecChildren, "Mitigations");

                    // get example instances
                    String examples = getBlockTextSimple(capecChildren, "Example_Instances");

                    // get related weaknesses mapping
                    HashMap<String, String> weaknesses = getBlockTable(capecChildren, "Related_Weaknesses", "CWE-ID");

                    // get taxonomy mappings
                    HashMap<String, String> tax = getBlockTable(capecChildren, "Taxonomy_Mappings", "Entry ID");

                    String text = "";

                }
            }
        }
        return capecs;
    }
}
