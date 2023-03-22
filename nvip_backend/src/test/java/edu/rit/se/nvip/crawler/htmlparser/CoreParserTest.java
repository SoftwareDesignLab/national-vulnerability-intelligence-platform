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

import static junit.framework.TestCase.assertEquals;
import static org.junit.Assert.assertTrue;

public class CoreParserTest extends AbstractParserTest {

    @Test
    public void testCoreSingle() {
        String html = safeReadHtml("src/test/resources/test-core-single.html");
        List<CompositeVulnerability> list = crawler.parseWebPage(
                "https://www.coresecurity.com/core-labs/advisories/cisco-anyconnect-posture-hostscan-security-service-bypass",
                html
        );
        assertEquals(1, list.size());
        CompositeVulnerability vuln = list.get(0);
        assertEquals("CVE-2021-1567", vuln.getCveId());
        assertEquals("2021-06-16", vuln.getPublishDate());
        assertEquals("2021-06-16", vuln.getLastModifiedDate());
        assertTrue(vuln.getDescription().contains("AnyConnect Posture Module uses the HostScan"));
        assertTrue(vuln.getDescription().contains("accepting commands given in a certain packet format"));
    }

    @Test
    public void testCoreMultiple() {
        String html = safeReadHtml("src/test/resources/test-core-multiple.html");
        List<CompositeVulnerability> list = crawler.parseWebPage(
                "https://www.coresecurity.com/core-labs/advisories/pydio-cells-204-multiple-vulnerabilities",
                html
        );
        assertEquals(7, list.size());
        CompositeVulnerability vuln = list.get(2);
        assertEquals("CVE-2020-12853", vuln.getCveId());
        assertEquals("2020-05-28", vuln.getPublishDate());
        assertEquals("2020-05-28", vuln.getLastModifiedDate());
        assertTrue(vuln.getDescription().contains("The attacker could leverage a public file share link to gain"));
        assertTrue(vuln.getDescription().contains("A malicious user can either upload or create a new file"));
    }

}
