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

import edu.rit.se.nvip.crawler.htmlparser.CveParserInterface;

import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * 
 * @author axoeec
 *
 */
public class Product {
	private final String domain;
	private final String cpe;
	private final int prodId;

	public Product(String domain, String cpe, int prodId) {
		this.domain = domain;
		this.cpe = cpe;
		this.prodId = prodId;
	}

	public Product(String domain, String cpe) {
		this.prodId = 0;
		this.domain = domain;
		this.cpe = cpe;
	}

	public String getDomain() {
		return domain;
	}

	public String getCpe() {
		return cpe;
	}

	public int getProdId() {
		return prodId;
	}

	public String getVersion() {
		Pattern pattern = Pattern.compile(CveParserInterface.regexVersionInfo);
		Matcher matcher = pattern.matcher(this.domain);
		if (matcher.find())
			return matcher.group();
		return "";
	}

	@Override
	public String toString() {
		return this.domain;
	}

	@Override
	public int hashCode() {
		return this.cpe.hashCode();
	}

	@Override
	public boolean equals(Object obj) {
		if (obj instanceof Product) {
			return this.cpe.equals(((Product) obj).cpe);
		}
		return false;
	}
}
