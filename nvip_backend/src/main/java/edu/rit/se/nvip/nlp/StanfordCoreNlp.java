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
package edu.rit.se.nvip.nlp;

import java.util.List;
import java.util.Properties;
import java.util.stream.Collectors;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import edu.stanford.nlp.pipeline.CoreDocument;
import edu.stanford.nlp.pipeline.StanfordCoreNLP;

/**
 * 
 * This class uses Stanford CoreNLP package to perform Named Entity Recognition
 * (NER) on CVE descriptions provided as an ArrayList
 * 
 * @author axoeec
 *
 */
public class StanfordCoreNlp {
	static Logger logger = LogManager.getLogger(StanfordCoreNlp.class);
	StanfordCoreNLP pipeline;

	/**
	 * initialize StanfordCoreNLP pipeline
	 */
	public StanfordCoreNlp() {
		// set up pipeline properties
		Properties props = new Properties();
		props.setProperty("annotators", "tokenize,ssplit,pos,lemma,ner");
		props.setProperty("ner.useSUTime", "false");
		props.setProperty("ner.applyNumericClassifiers", "false");

		// set up pipeline once in the Constructor!
		pipeline = new StanfordCoreNLP(props);

	}

	/**
	 * Annotate descriptions in a list, where the description is the second entry of
	 * each list item in <listCVEData>
	 * 
	 * @param listCVEData list of IDs and Descriptions
	 * @return
	 */
	public List<String[]> annotateCVEList(List<String[]> listCVEData) {
		int i = 0;
		for (String[] entry : listCVEData) {
			entry[1] = getAnnotations(entry[1]); // replace description with annotation
			i++;

			// print info to show progress
			if (i % 1000 == 0)
				logger.info("Annotated " + i + " of " + listCVEData.size() + " descriptions.");
		}
		return listCVEData;

	}

	/**
	 * Annotate a given text (sDescription)
	 * 
	 * @param sDescription
	 * @return
	 */
	private String getAnnotations(String sDescription) {
		CoreDocument doc = new CoreDocument(sDescription); // create doc
		pipeline.annotate(doc); // annotate

		// get tokens and tags
		String tokensAndNERTags = doc.tokens().stream().map(token -> "(" + token.word() + "," + token.ner() + ")").collect(Collectors.joining(" "));
		return tokensAndNERTags;
	}

}
