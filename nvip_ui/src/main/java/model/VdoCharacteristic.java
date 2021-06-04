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

public class VdoCharacteristic {
	private String cveId = null;
	private String vdoLabel = null;
	private double vdoConfidence = 0;
	private String vdoNounGroup = null;

	public VdoCharacteristic(String cveId, String vdoLabel, double vdoConfidence, String vdoNounGroup) {
		super();
		this.cveId = cveId;
		this.vdoLabel = vdoLabel;
		this.vdoConfidence = vdoConfidence;
		this.vdoNounGroup = vdoNounGroup;
	}

	public String getCveId() {
		return cveId;
	}

	public void setCveId(String cveId) {
		this.cveId = cveId;
	}

	public String getVdoLabel() {
		return vdoLabel;
	}

	public void setVdoLabel(String vdoLabel) {
		this.vdoLabel = vdoLabel;
	}

	public double getVdoConfidence() {
		return vdoConfidence;
	}

	public void setVdoConfidence(double vdoConfidence) {
		this.vdoConfidence = vdoConfidence;
	}
	
	public String getVdoNounGroup() {
		return vdoNounGroup;
	}

	public void setVdoNounGroup(String vdoNounGroup) {
		this.vdoNounGroup = vdoNounGroup;
	}

	@Override
	public String toString() {
		return "VdoCharacteristic [cveId=" + cveId + ", vdoLabel=" + vdoLabel + ", vdoConfidence=" + vdoConfidence + "]";
	}
}
