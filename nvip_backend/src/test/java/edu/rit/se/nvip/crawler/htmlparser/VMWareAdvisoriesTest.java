package edu.rit.se.nvip.crawler.htmlparser;

import edu.rit.se.nvip.crawler.CveCrawler;
import edu.rit.se.nvip.model.CompositeVulnerability;
import edu.rit.se.nvip.utils.MyProperties;
import edu.rit.se.nvip.utils.PropertyLoader;
import edu.rit.se.nvip.utils.UtilHelper;
import org.apache.commons.io.IOUtils;
import org.junit.Test;

import java.io.IOException;
import java.net.URL;
import java.util.List;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

public class VMWareAdvisoriesTest {

    @Test
    public void testVMWareAdvisories() throws IOException {
        String url = "https://www.vmware.com/security/advisories/VMSA-2014-0012.html";
        String html = IOUtils.toString(new URL(url));

        MyProperties propertiesNvip = new MyProperties();
        propertiesNvip = new PropertyLoader().loadConfigFile(propertiesNvip);

        List<CompositeVulnerability> list = new CveCrawler(propertiesNvip).parseWebPage(url, html);

        assertEquals( list.size(), 8);

        url = "https://www.vmware.com/security/advisories/VMSA-2019-0014.html";
        html = IOUtils.toString(new URL(url));
        list = new CveCrawler(propertiesNvip).parseWebPage(url, html);

        assertEquals( list.size(), 2);

    }

}
