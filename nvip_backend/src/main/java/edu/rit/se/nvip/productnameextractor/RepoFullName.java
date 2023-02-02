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

package edu.rit.se.nvip.productnameextractor;

import java.io.Serializable;

/**
 * contains information about a repository but without tags (lightversion of the )
 * 
 * @author Igor Khokhlov
 *
 */
class RepoFullName implements Serializable{

	private final String cpeName;
	private final String fullName;
	private String url;
	private final String cpeID;
	private final String htmlUrl;

	public RepoFullName(String cpeName, String fullName, String cpeID, String htmlUrl) {
		super();
		this.cpeName = cpeName;
		this.fullName = fullName;
		this.cpeID = cpeID;
		this.htmlUrl = htmlUrl;
	}

	public String getCpeName() {
		return cpeName;
	}

	public String getFullName() {
		return fullName;
	}

	public String getUrl() {
		return url;
	}

	public void setUrl(String url) {
		this.url = url;
	}

	public String getCpeID() {
		return cpeID;
	}

	public String getHtmlUrl() {
		return htmlUrl;
	}

	public boolean isExactMatch() {
		return false;
	}

	@Override
	public int hashCode() {
		final int prime = 31;
		int result = 1;
		result = prime * result + ((cpeID == null) ? 0 : cpeID.hashCode());
		return result;
	}

	@Override
	public boolean equals(Object obj) {
		if (this == obj)
			return true;
		if (obj == null)
			return false;
		if (getClass() != obj.getClass())
			return false;
		RepoFullName other = (RepoFullName) obj;
		if (cpeID == null) {
			return other.cpeID == null;
		} else return cpeID.equals(other.cpeID);
	}
}