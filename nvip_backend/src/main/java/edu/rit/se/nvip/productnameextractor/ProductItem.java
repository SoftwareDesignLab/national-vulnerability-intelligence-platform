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

import java.util.ArrayList;

/**
 * ProductItem class for affected product name and its versions
 * 
 * @author Igor Khokhlov
 *
 */

public class ProductItem{
	
	private String name;
	private ArrayList<String> versions = new ArrayList<>();
	
	/**
	 * Class constructor
	 */
	public ProductItem(String name) {
		super();
		this.name = name;
	}
	
	/**
	 * Returns list of versions
	 * @return ArrayList<String> of versions
	 */
	public ArrayList<String> getVersions() {
		return versions;
	}

	/**
	 * Sets List of versions
	 * @param versions<String> versions
	 */
	public void setVersions(ArrayList<String> versions) {
		this.versions = versions;
	}
	
	/**
	 * Adds version to the list
	 * @param version version
	 */
	public void addVersion(String version) {
		versions.add(version);
	}

	/**
	 * Returns product name
	 * @return String name
	 */
	public String getName() {
		return name;
	}
	
	/**
	 * Sets product name
	 * @param name name
	 */
	public void setName(String name) {
		this.name = name;
	}
	
	@Override
	public String toString() {
	
		StringBuilder toPrint = new StringBuilder("SN: " + this.name);
		if (versions.size()>0) {
			toPrint.append(". SV: ");
			for (String version : versions) {
				toPrint.append(" ").append(version);
			}
		}
			
		return toPrint.toString();
	}
	
	

}
