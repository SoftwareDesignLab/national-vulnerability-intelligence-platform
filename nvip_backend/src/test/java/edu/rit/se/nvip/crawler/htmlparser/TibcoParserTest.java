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
import static junit.framework.TestCase.assertEquals;

public class TibcoParserTest extends AbstractParserTest{

    @Test
    public void testTibco() {
        String html = safeReadHtml("src/test/resources/test-tibco.html");
        List<CompositeVulnerability> list = crawler.parseWebPage(
                "https://www.tibco.com/support/advisories/2023/02/tibco-security-advisory-february-22-2023-tibco-businessconnect-cve-2022-41567",
                html
        );
        assertEquals(1, list.size());
        CompositeVulnerability vuln = list.get(0);
        assertEquals("CVE-2022-41567", vuln.getCveId());
        assertTrue(vuln.getDescription().contains("attacker with network access to execute a cross-site scripting"));
        assertFalse(vuln.getDescription().contains("The information on this page is being provided to you on an \"AS IS\" and \"AS-AVAILABLE\" basis"));
        assertEquals("February 22, 2023", vuln.getPublishDate());
    }

}
