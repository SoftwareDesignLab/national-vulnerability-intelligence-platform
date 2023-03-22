package model;

import static org.junit.Assert.assertEquals;

import org.json.JSONObject;
import org.junit.Test;
public class CVSSupdateTest{

    @Test
    public void testGetCvss_severity_id() {
        JSONObject object = new JSONObject();
        object.put("cvss_severity_id", 12345);
        object.put("severity_confidence", 0.5);
        object.put("impact_score", 8.9);
        object.put("impact_confidence", 0.5);
        CVSSupdate update = new CVSSupdate(object);
        assertEquals(12345, update.getCvss_severity_id());
    }

    @Test
    public void testSetCvss_severity_id() {
        JSONObject object = new JSONObject();
        object.put("cvss_severity_id", 12345);
        object.put("severity_confidence", 0.5);
        object.put("impact_score", 8.9);
        object.put("impact_confidence", 0.5);
        CVSSupdate update = new CVSSupdate(object);
        update.setCvss_severity_id(54321);
        assertEquals(54321, update.getCvss_severity_id());
    }

    @Test
    public void testGetSeverity_confidence() {
        JSONObject object = new JSONObject();
        object.put("cvss_severity_id", 12345);
        object.put("severity_confidence", 0.5);
        object.put("impact_score", 8.9);
        object.put("impact_confidence", 0.5);
        CVSSupdate update = new CVSSupdate(object);
        assertEquals(0.5, update.getSeverity_confidence(), 0);
    }

    @Test
    public void testSetSeverity_confidence() {
        JSONObject object = new JSONObject();
        object.put("cvss_severity_id", 12345);
        object.put("severity_confidence", 0.5);
        object.put("impact_score", 8.9);
        object.put("impact_confidence", 0.5);
        CVSSupdate update = new CVSSupdate(object);
        update.setSeverity_confidence(1.0);
        assertEquals(1.0, update.getSeverity_confidence(), 0);
    }

    @Test
    public void testGetImpact_score() {
        JSONObject object = new JSONObject();
        object.put("cvss_severity_id", 12345);
        object.put("severity_confidence", 0.5);
        object.put("impact_score", 8.9);
        object.put("impact_confidence", 0.5);
        CVSSupdate update = new CVSSupdate(object);
        assertEquals(8.9, update.getImpact_score(), 0);
    }

    @Test
    public void testSetImpact_score() {
        JSONObject object = new JSONObject();
        object.put("cvss_severity_id", 12345);
        object.put("severity_confidence", 0.5);
        object.put("impact_score", 8.9);
        object.put("impact_confidence", 0.5);
        CVSSupdate update = new CVSSupdate(object);
        update.setImpact_score(9.1);
        assertEquals(9.1, update.getImpact_score(), 0);
    }

    @Test
    public void testGetImpact_confidence() {
        JSONObject object = new JSONObject();
        object.put("cvss_severity_id", 12345);
        object.put("severity_confidence", 0.5);
        object.put("impact_score", 8.9);
        object.put("impact_confidence", 0.5);
        CVSSupdate update = new CVSSupdate(object);
        assertEquals(0.5, update.getImpact_confidence(), 0);
    }

    @Test
    public void testSetImpact_confidence() {
        JSONObject object = new JSONObject();
        object.put("cvss_severity_id", 12345);
        object.put("severity_confidence", 0.5);
        object.put("impact_score", 8.9);
        object.put("impact_confidence", 0.5);
        CVSSupdate update = new CVSSupdate(object);
        update.setImpact_confidence(1.0);
        assertEquals(1.0, update.getImpact_confidence(), 0);
    }
}