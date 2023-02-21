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

import static junit.framework.TestCase.assertEquals;

/**
 * Test for Bosch Security Parser
 * @author aep7128
 */
public class BoschSecurityParserTest {

    @Test
    public void testBoschSecurityParser() throws IOException {

        MyProperties propertiesNvip = new MyProperties();
        propertiesNvip = new PropertyLoader().loadConfigFile(propertiesNvip);

        CveCrawler crawler = new CveCrawler(propertiesNvip);
        String html = FileUtils.readFileToString(new File("src/test/resources/test-bosch-security.html"), StandardCharsets.US_ASCII);
        List<CompositeVulnerability> list = crawler.parseWebPage("https://psirt.bosch.com/security-advisories/bosch-sa-247053-bt.html", html);

        assertEquals(105, list.size());

        CompositeVulnerability vuln1 = list.get(0);
        CompositeVulnerability vuln2 = list.get(1);

        assertEquals("CVE-2006-5701", vuln1.getCveId());
        assertEquals("CVE-2006-5757", vuln2.getCveId());

        assertEquals("Double free vulnerability in squashfs module in the Linux kernel 2.6.x, as used in Fedora Core 5 and possibly other distributions, allows local users to cause a denial of service by mounting a crafted squashfs filesystem.",
                vuln1.getDescription());
        assertEquals("Race condition in the __find_get_block_slow function in the ISO9660 filesystem in Linux 2.6.18 and possibly other versions allows local users to cause a denial of service (infinite loop) by mounting a crafted ISO9660 filesystem containing malformed data structures.",
                vuln2.getDescription());
        assertEquals("23 Nov 2022", vuln1.getPublishDate());
        assertEquals("23 Nov 2022", vuln1.getLastModifiedDate());

    }
}
