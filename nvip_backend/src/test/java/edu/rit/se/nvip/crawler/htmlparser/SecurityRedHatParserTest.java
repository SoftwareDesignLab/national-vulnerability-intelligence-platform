package edu.rit.se.nvip.crawler.htmlparser;

import edu.rit.se.nvip.model.CompositeVulnerability;
import org.junit.Test;

import java.util.List;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;

/**
 * Test For Redhat Security Bulletin Parser
 */
public class SecurityRedHatParserTest extends AbstractParserTest{

    String TEST_DESCRIPTION_SECURITY = "A flaw was found in PHP. This issue occurs due to an uncaught integer overflow in PDO::quote() of PDO_SQLite returning an improperly quoted string. With the implementation of sqlite3_snprintf(), it is possible to force the function to return a single apostrophe if the function is called on user-supplied input without any length restrictions in place.";

    @Test
    public void testSecurityRedHat() {
        String html = safeReadHtml("src/test/resources/test-redhat-security.html");
        List<CompositeVulnerability> list = new SecurityRedHatParser("redhat").parseWebPage("redhat", html);
        assertEquals(10, list.size());
        CompositeVulnerability vuln = getVulnerability(list, "CVE-2022-31631");
        assertNotNull(vuln);
        assertEquals(TEST_DESCRIPTION_SECURITY, vuln.getDescription());
    }
}