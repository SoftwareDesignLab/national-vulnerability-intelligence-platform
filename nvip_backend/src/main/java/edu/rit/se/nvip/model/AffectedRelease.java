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
public class AffectedRelease {

	private final int id;
	private String cveId;
	private final String cpe;
	private String releaseDate;
	private String version;

	public AffectedRelease(int id, String cveId, String cpe, String releaseDate, String version) {
		this.id = id;
		this.cveId = cveId;
		this.cpe = cpe;
		this.releaseDate = releaseDate;
		this.version = version;
	}

	public AffectedRelease(String cpe, String releaseDate, String version) {
		this.id = 0;
		this.cveId = null;
		this.cpe = cpe;
		this.releaseDate = releaseDate;
		this.version = version;
	}

	public AffectedRelease(AffectedRelease a) {
		this.id = a.id;
		this.cveId = a.cveId;
		this.cpe = a.cpe;
		this.releaseDate = a.releaseDate;
		this.version = a.version;
	}

	public int getId() {
		return id;
	}

	public String getCveId() {
		return cveId;
	}

	public String getCpe() {
		return cpe;
	}

	public String getReleaseDate() {
		return releaseDate;
	}

	public String getVersion() {
		return version;
	}

	public void setVersion(String version) {
		this.version = version;
	}

	public void setCveId(String cveId) {
		this.cveId = cveId;
	}

	public void setReleaseDate(String releaseDate) {
		this.releaseDate = releaseDate;
	}

	@Override
	public boolean equals(Object obj) {
		if (!(obj instanceof AffectedRelease))
			return false;
		AffectedRelease other = (AffectedRelease) obj;
		return other.cveId.equals(this.cveId) && other.cpe.equals(this.cpe);

	}

	@Override
	public String toString() {
		return "AffectedRelease [cveId=" + cveId + ", cpe=" + cpe + ", releaseDate=" + releaseDate + ", version=" + version + "]";
	}

}
