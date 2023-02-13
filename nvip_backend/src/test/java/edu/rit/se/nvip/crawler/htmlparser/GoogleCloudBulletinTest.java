package edu.rit.se.nvip.crawler.htmlparser;


import edu.rit.se.nvip.crawler.CveCrawler;
import edu.rit.se.nvip.model.CompositeVulnerability;
import edu.rit.se.nvip.utils.MyProperties;
import edu.rit.se.nvip.utils.PropertyLoader;
import org.apache.commons.io.FileUtils;
import org.junit.Test;

import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.List;

/**
 * Test for Google Cloud Bulletin Parser
 * @author aep7128
 */
public class GoogleCloudBulletinTest extends AbstractParserTest {

    @Test
    public void testGoogleCloudsecurityBulletinParser() throws IOException {

        MyProperties propertiesNvip = new MyProperties();
        propertiesNvip = new PropertyLoader().loadConfigFile(propertiesNvip);

        CveCrawler crawler = new CveCrawler(propertiesNvip);
        String html = FileUtils.readFileToString(new File("src/test/resources/test-bosch-security.html"), StandardCharsets.US_ASCII);
        List<CompositeVulnerability> list = crawler.parseWebPage("https://psirt.bosch.com/security-advisories/bosch-sa-247053-bt.html", html);

    }

}
