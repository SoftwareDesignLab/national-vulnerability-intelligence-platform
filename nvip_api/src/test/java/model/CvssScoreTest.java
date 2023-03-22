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