package model;

import org.junit.Assert;

import org.junit.Test;

public class CvssScoreTest {

    @Test
    public void testGetCveId() {
        CvssScore score = new CvssScore("CVE-2023-26303", "MEDIUM", .5, "8.6", .5);
        Assert.assertEquals("CVE-2023-26303", score.getCveId());
    }

    @Test
    public void testSetCveId() {
    }

    @Test
    public void testGetBaseSeverity() {
    }

    @Test
    public void testSetBaseSeverity() {
    }

    @Test
    public void testGetSeverityConfidence() {
    }

    @Test
    public void testSetSeverityConfidence() {
    }

    @Test
    public void testGetImpactScore() {
    }

    @Test
    public void testSetImpactScore() {
    }

    @Test
    public void testGetImpactConfidence() {
    }

    @Test
    public void testSetImpactConfidence() {
    }
}