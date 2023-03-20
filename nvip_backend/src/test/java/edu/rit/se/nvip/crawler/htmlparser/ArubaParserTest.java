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

import java.util.ArrayList;
import java.util.List;
import static junit.framework.TestCase.assertNotNull;
import static junit.framework.TestCase.assertEquals;
import static junit.framework.TestCase.assertTrue;
import static junit.framework.TestCase.assertFalse;

public class ArubaParserTest extends AbstractParserTest {

    @Test
    public void testArubaSingle() {
        String html = safeReadHtml("src/test/resources/test-aruba-single.html");
        List<CompositeVulnerability> list = crawler.parseWebPage(
                "https://www.arubanetworks.com/assets/alert/ARUBA-PSA-2022-011.txt",
                html
        );
        assertEquals(1, list.size());
        CompositeVulnerability vuln = getVulnerability(list, "CVE-2022-23678");
        assertNotNull(vuln);
        assertTrue(vuln.getDescription().contains("A vulnerability exists in the Aruba VIA client for Microsoft"));
        assertEquals("2022-Jul-26", vuln.getPublishDate());
        assertEquals("2022-Aug-19", vuln.getLastModifiedDate());
    }


    @Test
    public void testArubaMultiple() {
        String html = safeReadHtml("src/test/resources/test-aruba-multiple.html");
        List<CompositeVulnerability> list = crawler.parseWebPage(
                "https://www.arubanetworks.com/assets/alert/ARUBA-PSA-2023-003.txt",
                html
        );
        assertEquals(8, list.size());
        CompositeVulnerability vuln = getVulnerability(list, "CVE-2023-25591");
        assertNotNull(vuln);
        assertTrue(vuln.getDescription().contains("further privileges on the ClearPass instance"));
        assertFalse(vuln.getDescription().contains("execute arbitrary script code in a victim's"));
        assertEquals("2023-Mar-14", vuln.getPublishDate());
        assertEquals("2023-Mar-14", vuln.getLastModifiedDate());
    }

    @Test
    public void testSplitDetailsSection() {
        ArubaParser arubaParser = new ArubaParser("arubanetworks");
        String cve = "CVE-2023-25589";
        String details = "=\n" +
                "\n" +
                "  Unauthenticated Arbitrary User Creation Leads to Complete\n" +
                "  System Compromise\n" +
                "  (CVE-2023-25589)\n" +
                "  ---------------------------------------------------------------------\n" +
                "    A vulnerability in the web-based management interface of\n" +
                "    ClearPass Policy Manager could allow an unauthenticated\n" +
                "    remote attacker to create arbitrary users on the platform.\n" +
                "    A successful exploit allows an attacker to achieve total\n" +
                "    cluster compromise.\n" +
                "\n" +
                "    Internal references: ATLCP-229\n" +
                "    Severity: Critical\n" +
                "    CVSSv3 Overall Score: 9.8\n" +
                "    CVSS Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H\n" +
                "\n" +
                "    Discovery: This vulnerability was discovered and reported by\n" +
                "    Daniel Jensen (@dozernz) via Aruba's Bug Bounty Program.\n" +
                "\n" +
                "\n" +
                "  Local Privilege Escalation in ClearPass OnGuard Linux Agent\n" +
                "  (CVE-2023-25590)\n" +
                "  ---------------------------------------------------------------------\n" +
                "    A vulnerability in the ClearPass OnGuard Linux agent could\n" +
                "    allow malicious users on a Linux instance to elevate their\n" +
                "    user privileges to those of a higher role. A successful\n" +
                "    exploit allows malicious users to execute arbitrary code\n" +
                "    with root level privileges on the Linux instance.\n" +
                "\n" +
                "    Internal references: ATLCP-235\n" +
                "    Severity: High\n" +
                "    CVSSv3 Overall Score: 7.8\n" +
                "    CVSS Vector: CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H\n" +
                "\n" +
                "    Discovery: This vulnerability was discovered and reported\n" +
                "    by Luke Young (bugcrowd.com/bored_engineer) via Aruba's Bug\n" +
                "    Bounty Program.";
        List<String> detailsSections = arubaParser.omitEmptyStrings(details.split("---------"));
        String thisCveDetails = arubaParser.splitDetailsSection(detailsSections, cve);
        assertTrue(thisCveDetails.contains("ClearPass Policy Manager could allow an unauthenticated"));
        assertFalse(thisCveDetails.contains("allow malicious users on a Linux instance to elevate their"));

    }
}
