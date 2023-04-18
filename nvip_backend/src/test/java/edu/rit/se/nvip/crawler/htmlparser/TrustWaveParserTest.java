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

import edu.rit.se.nvip.crawler.QuickCveCrawler;
import edu.rit.se.nvip.model.CompositeVulnerability;
import org.junit.Test;

import java.util.List;

import static junit.framework.TestCase.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

public class TrustWaveParserTest extends AbstractParserTest {

    /**
     * 1 CVE on a blog post test
     */
    @Test
    public void testTrustWaveSingle() {
        // QuickCveCrawler q = new QuickCveCrawler();
        // String html = q.getContentFromUrl("https://www.trustwave.com/en-us/resources/blogs/spiderlabs-blog/cve-2022-37461-two-reflected-xss-vulnerabilities-in-canon-medicals-vitrea-view/");
        String html = safeReadHtml("src/test/resources/test-trustwave-single.html");
        List<CompositeVulnerability> list = crawler.parseWebPage(
                "https://www.trustwave.com/en-us/resources/blogs/spiderlabs-blog/cve-2022-37461-two-reflected-xss-vulnerabilities-in-canon-medicals-vitrea-view/",
                html
        );
        assertEquals(1, list.size());
        CompositeVulnerability vuln = list.get(0);
        assertEquals("CVE-2022-37461", vuln.getCveId());
        assertEquals("September 29, 2022", vuln.getPublishDate());
        assertEquals("September 29, 2022", vuln.getLastModifiedDate());
        assertTrue(vuln.getDescription().contains("Sensitive information and credentials for various services integrated"));
    }

    /**
     * Multiple CVEs on a blog post test
     */
    @Test
    public void testTrustWaveDouble() {
        String html = safeReadHtml("src/test/resources/test-trustwave-double.html");
        List<CompositeVulnerability> list = crawler.parseWebPage(
                "https://www.trustwave.com/en-us/resources/blogs/spiderlabs-blog/denial-of-service-and-rce-in-openssl-30-cve-2022-3786-and-cve-2022-3602/",
                html
        );
        assertEquals(2, list.size());
        CompositeVulnerability vuln = list.get(0);
        CompositeVulnerability vuln2 = list.get(1);
        assertEquals("CVE-2022-3602", vuln.getCveId());
        assertEquals("CVE-2022-3786", vuln2.getCveId());
        assertEquals("November 04, 2022", vuln.getPublishDate());
        assertEquals("November 04, 2022", vuln.getLastModifiedDate());
        String desc1 = "overflow four attacker-controlled bytes on the stack";
        String desc2 = "overflow an arbitrary number of bytes containing the";
        assertTrue(vuln.getDescription().contains(desc1));
        assertFalse(vuln.getDescription().contains(desc2));
        assertTrue(vuln2.getDescription().contains(desc2));
        assertFalse(vuln2.getDescription().contains(desc1));
    }

    /**
     *  3 CVEs on a blog post, with different formatting
     */
    @Test
    public void testTrustWaveTriple() {
        String html = safeReadHtml("src/test/resources/test-trustwave-triple.html");
        List<CompositeVulnerability> list = crawler.parseWebPage(
                "https://www.trustwave.com/en-us/resources/blogs/spiderlabs-blog/oracle-sbc-multiple-security-vulnerabilities-leading-to-unauthorized-access-and-denial-of-service/",
                html
        );
        assertEquals(3, list.size());
        CompositeVulnerability vuln = list.get(0);
        CompositeVulnerability vuln2 = list.get(1);
        CompositeVulnerability vuln3 = list.get(2);
        assertEquals("CVE-2022-21381", vuln.getCveId());
        assertEquals("CVE-2022-21382", vuln2.getCveId());
        assertEquals("CVE-2022-21383", vuln3.getCveId());
        assertEquals("August 23, 2022", vuln.getPublishDate());
        assertEquals("August 23, 2022", vuln.getLastModifiedDate());
        String desc1 = "authenticated low privileged user to download arbitrary files";
        String desc2 = "user attempts to download the configuration file from the server";
        String desc3 = "user selects a file and clicks download, the application will send";
        assertTrue(vuln.getDescription().contains(desc1));
        assertFalse(vuln.getDescription().contains(desc2));
        assertFalse(vuln.getDescription().contains(desc3));
        assertTrue(vuln2.getDescription().contains(desc2));
        assertFalse(vuln2.getDescription().contains(desc1));
        assertFalse(vuln2.getDescription().contains(desc3));
        assertTrue(vuln3.getDescription().contains(desc3));
        assertFalse(vuln3.getDescription().contains(desc1));
        assertFalse(vuln3.getDescription().contains(desc2));
    }

    /**
     * No vuln on post even though 'CVE' is mentioned
     */
    @Test
    public void testTrustWaveNoCVE() {
        String html = safeReadHtml("src/test/resources/test-trustwave-no.html");
        List<CompositeVulnerability> list = crawler.parseWebPage(
                "https://www.trustwave.com/en-us/resources/blogs/spiderlabs-blog/network-map-nmap-meets-chatgpt/",
                html
        );
        assertEquals(0, list.size());
    }

    /**
     * Vulnerability text mentioned, CVEs in 'Related SpiderLabs Blogs' section,
     * but no actual CVE for this post
     */
    @Test
    public void testTrustWaveNoCVE2() {
        String html = safeReadHtml("src/test/resources/test-trustwave-no2.html");
        List<CompositeVulnerability> list = crawler.parseWebPage(
                "https://www.trustwave.com/en-us/resources/blogs/spiderlabs-blog/vulnerability-causing-deletion-of-all-users-in-crushftp-admin-area/",
                html
        );
        assertEquals(0, list.size());
    }

}
