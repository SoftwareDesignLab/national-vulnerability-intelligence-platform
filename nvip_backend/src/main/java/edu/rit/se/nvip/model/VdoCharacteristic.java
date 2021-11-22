/**
 * Copyright 2021 Rochester Institute of Technology (RIT). Developed with
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
package edu.rit.se.nvip.model;

/**
 * 
 * @author axoeec
 *
 */
public class VdoCharacteristic {
	private String cveId = null;
	private int vdoLabelId = 0;
	private double vdoConfidence = 0;
	private int vdoNounGroupId = 0;

	public VdoCharacteristic(String cveId, int vdoLabelId, double vdoConfidence, int vdoNounGroupId) {
		super();
		this.cveId = cveId;
		this.vdoLabelId = vdoLabelId;
		this.vdoConfidence = vdoConfidence;
		this.vdoNounGroupId = vdoNounGroupId;
	}

	public String getCveId() {
		return cveId;
	}

	public void setCveId(String cveId) {
		this.cveId = cveId;
	}

	public double getVdoConfidence() {
		return vdoConfidence;
	}

	public void setVdoConfidence(double vdoConfidence) {
		this.vdoConfidence = vdoConfidence;
	}

	public int getVdoLabelId() {
		return vdoLabelId;
	}

	public void setVdoLabelId(int vdoLabelId) {
		this.vdoLabelId = vdoLabelId;
	}

	public int getVdoNounGroupId() {
		return vdoNounGroupId;
	}

	public void setVdoNounGroupId(int vdoNounGroupId) {
		this.vdoNounGroupId = vdoNounGroupId;
	}

	@Override
	public String toString() {
		return "VdoCharacteristic [cveId=" + cveId + ", vdoLabel=" + vdoLabelId + ", vdoConfidence=" + vdoConfidence + "]";
	}

}
