/**
 * Copyright 2023 Rochester Institute of Technology (RIT). Developed with
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
package edu.rit.se.nvip.cvereconcile;

/**
 * @author axoeec
 *
 */
public class CveReconcilerFactory implements AbstractCveReconcilerFactory<Object> {

	public static final String SIMPLE = "SIMPLE";
	public static final String STANFORD_SIMPLE_NLP = "STANFORD_SIMPLE_NLP";
	public static final String STANFORD_CORE_NLP = "STANFORD_CORE_NLP";
	public static final String APACHE_OPEN_NLP = "APACHE_OPEN_NLP";

	@Override
	public AbstractCveReconciler createReconciler(String type) {

		if (type.equals(SIMPLE)) {
			return new CveReconcilerSimple();
		} else if (type.equals(STANFORD_SIMPLE_NLP)) {
			return new CveReconcilerStanfordSimpleNLP();
		} else if (type.equals(STANFORD_CORE_NLP)) {
			return new CveReconcilerStanfordCoreNLP();
		} else if (type.equals(APACHE_OPEN_NLP)) {
			return new CveReconcilerApacheOpenNLP();
		}

		return new CveReconcilerSimple();
	}

}
