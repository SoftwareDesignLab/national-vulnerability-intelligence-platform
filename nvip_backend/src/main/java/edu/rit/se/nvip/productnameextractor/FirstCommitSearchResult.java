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

/**
 * This class is for results of searching of the first commit
 * 
 * @author Igor Khokhlov
 *
 */

public class FirstCommitSearchResult {
	
	private String repositoryURL, repositoryName, cpeName, cpeID, repositoryHTMLurl;
	private String tagURL, tagName, tagNodeID, tagSHA;
	private boolean exactMatch = false;
	
	public FirstCommitSearchResult(String repositoryURL, String repositoryName, String cpeName, String cpeID,
			String repositoryHTMLurl) {
		super();
		this.repositoryURL = repositoryURL;
		this.repositoryName = repositoryName;
		this.cpeName = cpeName;
		this.cpeID = cpeID;
		this.repositoryHTMLurl = repositoryHTMLurl;
	}

	public FirstCommitSearchResult(String repositoryURL, String repositoryName, String cpeName, String cpeID,
			String repositoryHTMLurl, String tagURL, String tagName, String tagNodeID, String tagSHA,
			boolean exactMatch) {
		super();
		this.repositoryURL = repositoryURL;
		this.repositoryName = repositoryName;
		this.cpeName = cpeName;
		this.cpeID = cpeID;
		this.repositoryHTMLurl = repositoryHTMLurl;
		this.tagURL = tagURL;
		this.tagName = tagName;
		this.tagNodeID = tagNodeID;
		this.tagSHA = tagSHA;
		this.exactMatch = exactMatch;
	}
	
	public void fillFromTag(RepoTag tag) {
		this.tagURL = tag.getUrl();
		this.tagName = tag.getName();
		this.tagNodeID = tag.getNodeID();
		this.tagSHA = tag.getSha();
	}

	public String getRepositoryURL() {
		return repositoryURL;
	}

	public void setRepositoryURL(String repositoryURL) {
		this.repositoryURL = repositoryURL;
	}

	public String getRepositoryName() {
		return repositoryName;
	}

	public void setRepositoryName(String repositoryName) {
		this.repositoryName = repositoryName;
	}

	public String getCpeName() {
		return cpeName;
	}

	public void setCpeName(String cpeName) {
		this.cpeName = cpeName;
	}

	public String getCpeID() {
		return cpeID;
	}

	public void setCpeID(String cpeID) {
		this.cpeID = cpeID;
	}

	public String getRepositoryHTMLurl() {
		return repositoryHTMLurl;
	}

	public void setRepositoryHTMLurl(String repositoryHTMLurl) {
		this.repositoryHTMLurl = repositoryHTMLurl;
	}

	public String getTagURL() {
		return tagURL;
	}

	public void setTagURL(String tagURL) {
		this.tagURL = tagURL;
	}

	public String getTagName() {
		return tagName;
	}

	public void setTagName(String tagName) {
		this.tagName = tagName;
	}

	public String getTagNodeID() {
		return tagNodeID;
	}

	public void setTagNodeID(String tagNodeID) {
		this.tagNodeID = tagNodeID;
	}

	public String getTagSHA() {
		return tagSHA;
	}

	public void setTagSHA(String tagSHA) {
		this.tagSHA = tagSHA;
	}

	public boolean isExactMatch() {
		return exactMatch;
	}

	public void setExactMatch(boolean exactMatch) {
		this.exactMatch = exactMatch;
	}
	
	

}
