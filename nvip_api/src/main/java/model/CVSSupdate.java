/**
 * Copyright 2021 Rochester Institute of Technology (RIT). Developed with
 * government support under contract 70RSAT19CB0000020 awarded by the United
 * States Department of Homeland Security.
 * 
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the “Software”), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 * 
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 * 
 * THE SOFTWARE IS PROVIDED “AS IS”, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */
package model;

import org.json.JSONObject;

public class CVSSupdate {
	
	private int cvss_severity_id;
	private double severity_confidence,	impact_score, impact_confidence;
	
	public CVSSupdate(JSONObject cvssUpdateJSON) {
				
		cvss_severity_id = cvssUpdateJSON.getInt("cvss_severity_id");
		severity_confidence = cvssUpdateJSON.getDouble("severity_confidence");
		impact_score = cvssUpdateJSON.getDouble("impact_score");
		impact_confidence = cvssUpdateJSON.getDouble("impact_confidence");
		
	}
	
	public int getCvss_severity_id() {
		return cvss_severity_id;
	}
	public void setCvss_severity_id(int cvss_severity_id) {
		this.cvss_severity_id = cvss_severity_id;
	}
	public double getSeverity_confidence() {
		return severity_confidence;
	}
	public void setSeverity_confidence(double severity_confidence) {
		this.severity_confidence = severity_confidence;
	}
	public double getImpact_score() {
		return impact_score;
	}
	public void setImpact_score(double impact_score) {
		this.impact_score = impact_score;
	}
	public double getImpact_confidence() {
		return impact_confidence;
	}
	public void setImpact_confidence(double impact_confidence) {
		this.impact_confidence = impact_confidence;
	}
	
	

}
