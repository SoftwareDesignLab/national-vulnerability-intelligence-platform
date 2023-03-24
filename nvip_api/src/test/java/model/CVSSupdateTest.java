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