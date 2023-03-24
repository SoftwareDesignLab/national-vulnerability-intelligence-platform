/**
 * Copyright 2023 Rochester Institute of Technology (RIT). Developed with
 * government support under contract 70RSAT19CB0000020 awarded by the United
 * States Department of Homeland Security.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the �Software�), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED �AS IS�, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */
package model;

import static org.junit.Assert.assertEquals;

import org.junit.Test;

public class CvssScoreTest {

    @Test
    public void testGetCveId() {
        CvssScore score = new CvssScore("CVE-2023-26303", "MEDIUM", .5, "8.6", .5);
        assertEquals("CVE-2023-26303", score.getCveId());
    }

    @Test
    public void testSetCveId() {
        CvssScore score = new CvssScore("CVE-2023-26303", "MEDIUM", .5, "8.6", .5);
        score.setCveId("CVE-2022-26303");
        assertEquals("CVE-2022-26303", score.getCveId());
    }

    @Test
    public void testGetBaseSeverity() {
        CvssScore score = new CvssScore("CVE-2023-26303", "MEDIUM", .5, "8.6", .5);
        assertEquals("MEDIUM", score.getBaseSeverity());
    }

    @Test
    public void testSetBaseSeverity() {
        CvssScore score = new CvssScore("CVE-2023-26303", "MEDIUM", .5, "8.6", .5);
        score.setBaseSeverity("LOW");
        assertEquals("LOW", score.getBaseSeverity());
    }

    @Test
    public void testGetSeverityConfidence() {
        CvssScore score = new CvssScore("CVE-2023-26303", "MEDIUM", .5, "8.6", .5);
        assertEquals(.5, score.getSeverityConfidence(), 0);
    }

    @Test
    public void testSetSeverityConfidence() {
        CvssScore score = new CvssScore("CVE-2023-26303", "MEDIUM", .5, "8.6", .5);
        score.setSeverityConfidence(1);
        assertEquals(1, score.getSeverityConfidence(), 0);
    }

    @Test
    public void testGetImpactScore() {
        CvssScore score = new CvssScore("CVE-2023-26303", "MEDIUM", .5, "8.6", .5);
        assertEquals("8.6", score.getImpactScore());
    }

    @Test
    public void testSetImpactScore() {
        CvssScore score = new CvssScore("CVE-2023-26303", "MEDIUM", .5, "8.6", .5);
        score.setImpactScore("8.9");
        assertEquals("8.9", score.getImpactScore());
    }

    @Test
    public void testGetImpactConfidence() {
        CvssScore score = new CvssScore("CVE-2023-26303", "MEDIUM", .5, "8.6", .5);
        assertEquals(.5, score.getImpactConfidence(), 0);
    }

    @Test
    public void testSetImpactConfidence() {
        CvssScore score = new CvssScore("CVE-2023-26303", "MEDIUM", .5, "8.6", .5);
        score.setImpactConfidence(1);
        assertEquals(1, score.getImpactConfidence(), 0);
    }
}