package edu.rit.se.nvip.mitre.capec;

import java.util.*;

import edu.rit.se.nvip.crawler.QuickCveCrawler;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.jsoup.Jsoup;
import org.jsoup.nodes.Document;
import org.jsoup.nodes.Element;
import org.jsoup.select.Elements;

public class CapecParser {

    // comprehensive dictionary url from capec.mitre.org
    private final String url;

    // logger
    private final Logger logger = LogManager.getLogger(getClass().getSimpleName());

    // map capecs to their abstraction and relationships
    private static final Map<String, CapecType> ABSTRACTIONS;
    static {
        ABSTRACTIONS = new HashMap<>();
        ABSTRACTIONS.put("Standard", CapecType.STANDARD);
        ABSTRACTIONS.put("Detailed", CapecType.DETAILED);
        ABSTRACTIONS.put("Meta", CapecType.META);
    }

    /**
     * Link -> HTML and parse HTML for CAPEC enums, output list of Capec
     */
    public CapecParser() {
        // This page contains all:
        // 559 Attack Patterns
        // 21 Categories
        // 13 Views
        // for a total of : 593
        this.url = "https://capec.mitre.org/data/slices/2000.html";

    }

    /**
     * return a dropdown block from a dropdowns children
     * @param children - child elements in dropdown
     * @return - the dropdown block wanted
     */
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
                if (row.text().contains(headerName) || row.childrenSize() < 2) continue;
                String key = row.child(0).text();
                String val = row.child(1).text();
                table.put(key, val);
            }
        }
        return table;
    }

    /**
     * Pull list of strings from a given block dropdown
     * @param capecChildren - list of dropdowns
     * @param id - the dropdown we are looking for
     * @return - list of strings gathered from dropdown
     */
    private ArrayList<String> getBlockList(Elements capecChildren, String id) {

        ArrayList<String> list = new ArrayList<>();
        Element skillsEl = capecChildren.select("div#" + id).first();
        if (skillsEl != null) {
            Element block = getExpandBlock(skillsEl.children());
            // get td entries from table element
            Elements tdEls = block.children().select("td");
            list = new ArrayList<>(tdEls.eachText());
        }

        return list;
    }

    /**
     * Parse comprehensive list of CAPECs from capec.mitre.org
     * to be used for automatic CAPEC characterization
     * @param q - crawler to get content from url
     * @return - list of Capec objects encapsulating all the info pulled from each CAPEC
     */
    public ArrayList<Capec> parseWebPage(QuickCveCrawler q) {

        String html = q.getContentFromUrl(this.url);
        logger.info("Parsing page: {}", this.url);
        ArrayList<Capec> capecs = new ArrayList<>();
        Document doc = Jsoup.parse(html);

        // get each CAPEC instance on the page and loop through each
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
                    if (titleEl == null) continue;
                    String titleText = titleEl.text();
                    String[] titleTextSplit = titleText.split("Abstraction: ");
                    CapecType abstraction = ABSTRACTIONS.get(titleTextSplit[1]);
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
                            String type = "";
                            Element typeImg = row.child(1).select("img").first();
                            if (typeImg != null) type = typeImg.attr("alt");
                            if (type.equals("View")) continue;
                            String rowID = row.child(2).text();
                            String name = row.child(3).text();
                            relationships.add(new CapecRelationship(
                                    nature, type, rowID, name
                            ));
                        }
                    }

                    // get prerequisites
                    ArrayList<String> prereqs = getBlockList(capecChildren, "Prerequisites");

                    // get skills required
                    ArrayList<String> skills = getBlockList(capecChildren, "Skills_Required");

                    // get resources required
                    String resources = getBlockTextSimple(capecChildren, "Resources_Required");

                    // get consequences table
                    HashMap<String, ArrayList<String>> cons = new HashMap<>();
                    Element consEl = capecChildren.select("div#Consequences").first();
                    if (consEl != null) {
                        Elements rows = consEl.select("tr");
                        for (Element row : rows) {
                            // skip header
                            if (row.text().contains("Scope")) continue;
                            // for each scope add an entry with that impact
                            Elements scopes = row.child(0).children().select("div");
                            for (Element scope : scopes) {
                                String scopeText = scope.text();
                                if (cons.containsKey(scopeText)) {
                                    cons.get(scopeText).add(row.child(1).text());
                                }
                                else
                                    cons.put(
                                            scope.text(),
                                            new ArrayList<>(Collections.singletonList(row.child(1).text()))
                                    );
                            }
                        }
                    }

                    // get mitigations
                    String mitigations = getBlockTextSimple(capecChildren, "Mitigations");

                    // get example instances
                    String examples = getBlockTextSimple(capecChildren, "Example_Instances");

                    // get related weaknesses mapping
                    HashMap<String, String> weaknesses = getBlockTable(capecChildren, "Related_Weaknesses", "CWE-ID");

                    // get taxonomy mappings
                    HashMap<String, String> tax = getBlockTable(capecChildren, "Taxonomy_Mappings", "Entry ID");

                    capecs.add(new Capec(
                            id, abstraction, description, likelihood, severity, relationships,
                            prereqs, skills, resources, cons, mitigations, examples, weaknesses, tax
                    ));
                }
            }
        }
        return capecs;
    }
}
