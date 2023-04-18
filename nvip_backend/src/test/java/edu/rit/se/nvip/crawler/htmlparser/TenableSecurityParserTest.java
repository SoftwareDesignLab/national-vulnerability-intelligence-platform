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

import static junit.framework.TestCase.*;

public class TenableSecurityParserTest extends AbstractParserTest {

    @Test
    public void testTenableSecurityParser0() {
        String html = safeReadHtml("src/test/resources/test-tenable-security.html");
        List<CompositeVulnerability> list = new TenableSecurityParser("tenable").parseWebPage("tenable", html);
        assertEquals(1, list.size());
        CompositeVulnerability vuln = list.get(0);
        assertEquals("CVE-2023-0587", vuln.getCveId());
        assertEquals("2023/01/30 00:00:00", vuln.getPublishDate());
        assertTrue(vuln.getDescription().contains("A file upload vulnerability in exists in Trend Micro Apex One"));
        assertFalse(vuln.getDescription().contains("View More Research Advisories"));
    }

    @Test
    public void testTenableSecurityParser1() {
        String html = safeReadHtml("src/test/resources/test-tenable-security-2.html");
        List<CompositeVulnerability> list = new TenableSecurityParser("tenable").parseWebPage("tenable", html);
        assertEquals(1, list.size());
        CompositeVulnerability vuln = list.get(0);
        assertEquals("CVE-2022-4390", vuln.getCveId());
        assertEquals("2022/12/02 00:00:00", vuln.getPublishDate());
        assertEquals("2022/12/09 00:00:00", vuln.getLastModifiedDate());
        assertTrue(vuln.getDescription().contains("A network misconfiguration is present"));
        assertFalse(vuln.getDescription().contains("View More Research Advisories"));
    }

    @Test
    public void testTenableSecurityParserMultiple() {
        QuickCveCrawler q = new QuickCveCrawler();
        String html = q.getContentFromUrl("https://www.tenable.com/security/tns-2015-03");
        List<CompositeVulnerability> list = new TenableSecurityParser("tenable").parseWebPage("tenable", html);
        assertEquals(4, list.size());
        CompositeVulnerability vuln = getVulnerability(list, "CVE-2014-3570");
        assertNotNull(vuln);
        assertEquals("2015/02/03 00:00:00", vuln.getPublishDate());
        assertEquals("2017/02/28 00:00:00", vuln.getLastModifiedDate());
        assertTrue(vuln.getDescription().contains("OpenSSL contains a flaw in the dtls1_buffer_record"));
    }

    @Test
    public void testTenableSecurityParserMultiple2() {
        QuickCveCrawler q = new QuickCveCrawler();
        String html = q.getContentFromUrl("https://www.tenable.com/security/tns-2015-04");
        List<CompositeVulnerability> list = new TenableSecurityParser("tenable").parseWebPage("tenable", html);
        assertEquals(9, list.size());
        CompositeVulnerability vuln = getVulnerability(list, "CVE-2015-0204");
        assertNotNull(vuln);
        assertEquals("2015/03/30 00:00:00", vuln.getPublishDate());
        assertEquals("2017/02/28 00:00:00", vuln.getLastModifiedDate());
        assertTrue(vuln.getDescription().contains("OpenSSL contains an invalid read flaw in"));
    }

}