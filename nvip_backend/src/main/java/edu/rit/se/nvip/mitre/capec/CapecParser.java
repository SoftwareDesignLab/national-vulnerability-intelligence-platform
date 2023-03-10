package edu.rit.se.nvip.mitre.capec;

import edu.rit.se.nvip.model.CompositeVulnerability;

import java.util.ArrayList;
import java.util.List;
import java.util.Set;

import edu.rit.se.nvip.crawler.QuickCveCrawler;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.jsoup.Jsoup;
import org.jsoup.nodes.Document;
import org.jsoup.select.Elements;

public class CapecParser {

    private String url;
    private String html;

    private Logger logger = LogManager.getLogger(getClass().getSimpleName());

    /**
     * Link -> HTML and parse HTML for CAPEC enums, output list of Capec
     * @param page - capec.mitre page url
     * Example: <a href="https://capec.mitre.org/data/slices/1000.html">...</a>
     */
    public CapecParser(String page) {
        this.url = page;

    }

    public static void main (String[] args) {
        CapecParser c = new CapecParser("https://capec.mitre.org/data/slices/1000.html");
        List<Capec> capecList = c.parseWebPage();
    }

    public List<Capec> parseWebPage() {

        QuickCveCrawler q = new QuickCveCrawler();
        String html = q.getContentFromUrl(this.url);
        logger.info("Parsing page: {}", this.url);

        List<Capec> capecs = new ArrayList<>();

        Document doc = Jsoup.parse(html);

        Elements capecDescriptions = doc.select("div#CAPECDefinition");

        return capecs;
    }
}
