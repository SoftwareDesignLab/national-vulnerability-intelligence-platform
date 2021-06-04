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

public class CvssScore {
	private String cveId = null;
	private String baseSeverity = null;
	private double severityConfidence = 0;
	private String impactScore = null;
	private double impactConfidence = 0;

	public CvssScore(String cveId, String baseSeverity, double severityConfidence, String impactScore, double impactConfidence) {
		this.cveId = cveId;
		this.baseSeverity = baseSeverity;
		this.severityConfidence = severityConfidence;
		this.impactScore = impactScore;
		this.impactConfidence = impactConfidence;
	}

	public String getCveId() {
		return cveId;
	}

	public void setCveId(String cveId) {
		this.cveId = cveId;
	}

	public String getBaseSeverity() {
		return baseSeverity;
	}

	public void setBaseSeverity(String baseSeverity) {
		this.baseSeverity = baseSeverity;
	}

	public double getSeverityConfidence() {
		return severityConfidence;
	}

	public void setSeverityConfidence(double severityConfidence) {
		this.severityConfidence = severityConfidence;
	}

	public String getImpactScore() {
		return impactScore;
	}

	public void setImpactScore(String impactScore) {
		this.impactScore = impactScore;
	}

	public double getImpactConfidence() {
		return impactConfidence;
	}

	public void setImpactConfidence(double impactConfidence) {
		this.impactConfidence = impactConfidence;
	}

	@Override
	public String toString() {
		return "CvssScore [cveId=" + cveId + ", baseSeverity=" + baseSeverity + ", severityConfidence="
				+ severityConfidence + ", impactScore=" + impactScore + ", impactConfidence=" + impactConfidence + "]";
	}
}
