/**
 * Copyright 2023 Rochester Institute of Technology (RIT). Developed with
 * government support under contract 70RSAT19CB0000020 awarded by the United
 * States Department of Homeland Security.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */
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