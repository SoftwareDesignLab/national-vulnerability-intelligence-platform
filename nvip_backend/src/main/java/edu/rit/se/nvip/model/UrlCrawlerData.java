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

import java.util.HashMap;

/**
 * 
 * Wrapper class for UrlCrwler
 * 
 * @author axoeec
 *
 */
public class UrlCrawlerData {
	/**
	 * Crawled URLs that include a CVEID (can be at depth>=0)
	 */
	private HashMap<String, Integer> hashMapLegitimateSourceURLs = new HashMap<String, Integer>();

	/**
	 * URLs that are forbidden (depth >=0). NVIP sources that have the same base URL
	 * with those should be marked, to have an adaptive crawler process
	 */
	private HashMap<String, Integer> hashMapForbiddenSourceURLs = new HashMap<String, Integer>();

	/**
	 * NVIP URLs (depth=0) with status code != HTTP_OK. Those URLs should be removed
	 * from the NVIP URL sources!
	 */
	private HashMap<String, Integer> hashMapSourceURLsNotOk = new HashMap<String, Integer>();

	public UrlCrawlerData(HashMap<String, Integer> hashMapSourceURLs, HashMap<String, Integer> hashMapForbiddenSourceURLs, HashMap<String, Integer> hashMapSourceURLsNotOk) {
		this.hashMapLegitimateSourceURLs = hashMapSourceURLs;
		this.hashMapForbiddenSourceURLs = hashMapForbiddenSourceURLs;
		this.hashMapSourceURLsNotOk = hashMapSourceURLsNotOk;
	}

	public HashMap<String, Integer> getHashMapLegitimateSourceURLs() {
		return hashMapLegitimateSourceURLs;
	}

	public void setHashMapLegitimateSourceURLs(HashMap<String, Integer> hashMapLegitimateSourceURLs) {
		this.hashMapLegitimateSourceURLs = hashMapLegitimateSourceURLs;
	}

	public HashMap<String, Integer> getHashMapForbiddenSourceURLs() {
		return hashMapForbiddenSourceURLs;
	}

	public void setHashMapForbiddenSourceURLs(HashMap<String, Integer> hashMapForbiddenSourceURLs) {
		this.hashMapForbiddenSourceURLs = hashMapForbiddenSourceURLs;
	}

	public HashMap<String, Integer> getHashMapSourceURLsNotOk() {
		return hashMapSourceURLsNotOk;
	}

	public void setHashMapSourceURLsNotOk(HashMap<String, Integer> hashMapSourceURLsNotOk) {
		this.hashMapSourceURLsNotOk = hashMapSourceURLsNotOk;
	}

}
