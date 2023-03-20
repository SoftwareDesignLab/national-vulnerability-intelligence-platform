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

public class JenkinsParserTest extends AbstractParserTest {

    @Test
    public void testJenkinsParserSimple() {
        String html = safeReadHtml("src/test/resources/test-jenkins-simple.html");
        List<CompositeVulnerability> list = crawler.parseWebPage(
                "https://www.jenkins.io/security/advisory/2023-02-09/",
                html
        );
        assertEquals(2, list.size());
        CompositeVulnerability vuln1 = list.get(0);
        CompositeVulnerability vuln2 = list.get(1);
        assertEquals("CVE-2022-23521", vuln1.getCveId());
        assertEquals("CVE-2022-41903", vuln2.getCveId());
        assertTrue(vuln1.getDescription().contains("Affected Jenkins controller and agent images"));
        assertEquals("2023-02-09", vuln1.getPublishDate());
    }

    @Test
    public void testJenkinsParserComplex() {
        String html = safeReadHtml("src/test/resources/test-jenkins-complex.html");
        List<CompositeVulnerability> list = crawler.parseWebPage(
                "https://www.jenkins.io/security/advisory/2022-06-30/",
                html
        );
        assertEquals(42, list.size());
        CompositeVulnerability vuln40 = list.get(39);
        assertNotNull(vuln40);
        assertEquals("CVE-2022-34816", vuln40.getCveId());
        assertTrue(vuln40.getDescription().contains("on the Jenkins controller as part of its configuration"));
        assertEquals("2022-06-30", vuln40.getPublishDate());
    }

}
