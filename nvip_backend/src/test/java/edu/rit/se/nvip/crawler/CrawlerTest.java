package edu.rit.se.nvip.crawler;

import edu.rit.se.nvip.model.CompositeVulnerability;
import edu.rit.se.nvip.utils.MyProperties;
import edu.rit.se.nvip.utils.PropertyLoader;
import edu.uci.ics.crawler4j.crawler.Page;
import edu.uci.ics.crawler4j.parser.ParseData;
import edu.uci.ics.crawler4j.url.WebURL;
import org.junit.Test;

import java.util.HashMap;
import java.util.Set;

import static junit.framework.TestCase.assertTrue;

public class CrawlerTest {

    @Test
    public void pageVisitTest() {
        MyProperties properties = new MyProperties();
        properties = new PropertyLoader().loadConfigFile(properties);

        CveCrawler crawler = new CveCrawler(properties);
        /*WebURL url = new WebURL();
        url.setURL("https://lists.apache.org/");

        Page testPage = new Page(url);

        crawler.visit(testPage);
        HashMap<String, CompositeVulnerability> vulns = crawler.getMyLocalData();

        System.out.println(vulns);

        assertTrue(vulns.size() > 0);
*/
    }

}
