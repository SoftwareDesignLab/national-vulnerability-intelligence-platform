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

import static junit.framework.TestCase.*;

public class AtlassianParserTest extends AbstractParserTest {

    @Test
    public void testAtlassianSingleNoDesc() {
        String html = safeReadHtml("src/test/resources/test-atlassian-single.html");
        List<CompositeVulnerability> list = crawler.parseWebPage(
                "https://confluence.atlassian.com/bitbucketserver/bitbucket-server-and-data-center-advisory-2022-08-24-1155489835.html",
                html
        );
        assertEquals(1, list.size());
        CompositeVulnerability vuln = list.get(0);
        assertEquals("CVE-2022-36804", vuln.getCveId());
        assertTrue(vuln.getDescription().contains("command injection vulnerability in multiple API endpoints"));
        assertFalse(vuln.getDescription().contains("evaluate its applicability to your own IT environment"));
        assertEquals("24 Aug 2022 10 AM PDT", vuln.getPublishDate());
        assertEquals("Aug 24, 2022", vuln.getLastModifiedDate());

    }

    @Test
    public void testAtlassianMultipleNoDesc() {
        String html = safeReadHtml("src/test/resources/test-atlassian-multiple.html");
        List<CompositeVulnerability> list = crawler.parseWebPage(
                "https://confluence.atlassian.com/security/multiple-products-security-advisory-git-buffer-overflow-cve-2022-41903-cve-2022-23521-1189805967.html",
                html
        );
        assertEquals(2, list.size());
        CompositeVulnerability vuln1 = list.get(0);
        CompositeVulnerability vuln2 = list.get(1);
        assertEquals("CVE-2022-41903", vuln1.getCveId());
        assertEquals("CVE-2022-23521", vuln2.getCveId());
        String desc1 = "command that invokes the commit formatting machinery";
        String desc2 = "a huge number of attributes for a single pattern";
        assertTrue(vuln1.getDescription().contains(desc1));
        assertFalse(vuln1.getDescription().contains(desc2));
        assertTrue(vuln2.getDescription().contains(desc2));
        assertFalse(vuln2.getDescription().contains(desc1));
        assertEquals("15 Feb 2023 10:00 AM PDT", vuln1.getPublishDate());
        assertEquals("Feb 17, 2023", vuln2.getLastModifiedDate());
    }

    @Test
    public void testAtlassianSingleWithDesc() {
        String html = safeReadHtml("src/test/resources/test-atlassian-single-desc.html");
        List<CompositeVulnerability> list = crawler.parseWebPage(
                "https://confluence.atlassian.com/doc/confluence-security-advisory-2019-12-18-982324349.html",
                html
        );
        assertEquals(1, list.size());
        CompositeVulnerability vuln = list.get(0);
        assertEquals("CVE-2019-15006", vuln.getCveId());
        assertTrue(vuln.getDescription().contains("An attacker could perform the described attack by denying their victim access"));
        assertEquals("18 Dec 2019 10:00 AM PST", vuln.getPublishDate());
        assertEquals("Jan 8, 2020", vuln.getLastModifiedDate());
    }

    @Test
    public void testAtlassianMultipleWithDesc() {
        String html = safeReadHtml("src/test/resources/test-atlassian-multiple-desc.html");
        List<CompositeVulnerability> list = crawler.parseWebPage(
                "https://confluence.atlassian.com/bitbucketserver/bitbucket-server-security-advisory-2020-01-15-985498238.html",
                html
        );
        assertEquals(3, list.size());
        CompositeVulnerability vuln1 = list.get(0);
        CompositeVulnerability vuln2 = list.get(1);
        CompositeVulnerability vuln3 = list.get(2);
        assertEquals("CVE-2019-15010", vuln1.getCveId());
        assertEquals("CVE-2019-20097", vuln2.getCveId());
        assertEquals("CVE-2019-15012", vuln3.getCveId());
        // make sure each vuln picked up their respective description
        String desc1 = "A remote attacker with user level permissions can exploit this vulnerability";
        String desc2 = "A remote attacker with permission to clone and push files to a repository";
        String desc3 = "A remote attacker with write permission on a repository can write";
        assertTrue(vuln1.getDescription().contains(desc1));
        assertFalse(vuln1.getDescription().contains(desc2));
        assertFalse(vuln1.getDescription().contains(desc3));
        assertTrue(vuln2.getDescription().contains(desc2));
        assertFalse(vuln2.getDescription().contains(desc1));
        assertFalse(vuln2.getDescription().contains(desc3));
        assertTrue(vuln3.getDescription().contains(desc3));
        assertFalse(vuln3.getDescription().contains(desc1));
        assertFalse(vuln3.getDescription().contains(desc2));
        assertEquals("15 Jan 2020 10 AM PDT", vuln1.getPublishDate());
        assertEquals("Jan 28, 2020", vuln2.getLastModifiedDate());
    }
}