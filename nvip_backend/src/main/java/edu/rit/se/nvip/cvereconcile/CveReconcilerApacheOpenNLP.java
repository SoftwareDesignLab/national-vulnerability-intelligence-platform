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
package edu.rit.se.nvip.cvereconcile;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import edu.rit.se.nvip.model.CompositeVulnerability;
import edu.rit.se.nvip.utils.MyProperties;
import edu.rit.se.nvip.utils.PropertyLoader;
import edu.rit.se.nvip.utils.UtilHelper;
import opennlp.tools.postag.POSModel;
import opennlp.tools.postag.POSTaggerME;
import opennlp.tools.sentdetect.SentenceDetector;
import opennlp.tools.sentdetect.SentenceDetectorME;
import opennlp.tools.sentdetect.SentenceModel;
import opennlp.tools.tokenize.WhitespaceTokenizer;

/**
 * Class for Cve reconciliation and validation based on Apache Open NLP library
 * 
 * @author Igor Khokhlov
 *
 */

public class CveReconcilerApacheOpenNLP extends AbstractCveReconciler {

	private Logger logger = LogManager.getLogger(getClass().getSimpleName());

	// Identifier of an unidentified language part
	final String unknwnPrt = "``";

	POSTaggerME tagger = null;
	POSModel model = null;
	SentenceModel sentenceModel = null;
	SentenceDetector sentenceDetector = null;
	String modelPath = "nlp/en-pos-perceptron.bin";
	String sentenceModelPath = "nlp/en-sent.bin";

	public CveReconcilerApacheOpenNLP() {
		super();
		MyProperties propertiesNvip = new MyProperties();
		propertiesNvip = new PropertyLoader().loadConfigFile(propertiesNvip);
		knownCveSources = propertiesNvip.getKnownCveSources();

		initialize();
	}

	public void initialize() {
		try {
			InputStream modelStream = this.getClass().getClassLoader().getResourceAsStream(modelPath);
			model = new POSModel(modelStream);
			tagger = new POSTaggerME(model);
			modelStream.close();

			InputStream modelIn = this.getClass().getClassLoader().getResourceAsStream(sentenceModelPath);
			sentenceModel = new SentenceModel(modelIn);
			sentenceDetector = new SentenceDetectorME(sentenceModel);
			modelIn.close();

		} catch (Exception e) {
			// System.out.println(e.getMessage());
			logger.error("A serious error has occurred while loading the models for CVE reconciliation! Exiting!" + e.toString());
			System.exit(1);
		}
	}

	@Override
	public boolean reconcileVulnerabilities(CompositeVulnerability existingVuln, CompositeVulnerability newVuln) {
		boolean reconciled = false;
		if (existingVuln.getPlatform() == null && newVuln.getPlatform() != null) {
			existingVuln.setPlatform(newVuln.getPlatform());
			reconciled = true;
		}

		if (existingVuln.getPublishDate() == null && newVuln.getPublishDate() != null) {
			existingVuln.setPublishDate(newVuln.getPublishDate());
			reconciled = true;
		}

		if (reconcileDescriptions(existingVuln.getDescription(), newVuln.getDescription(), existingVuln.getSourceDomainName(), newVuln.getSourceDomainName(), true)) {
			existingVuln.setDescription(newVuln.getDescription());
			reconciled = true;
		}

		if (reconciled) {
			/**
			 * Fix by AO: If the newVuln is a previously reconciled one, it may have
			 * multiple URLs!
			 */
			for (String newURL : newVuln.getSourceURL())
				existingVuln.addSourceURL(newURL);
		}
		return reconciled;
	}

	/**
	 * Reconcile description. If <existingDescription> should be updated, returns
	 * true.
	 * 
	 * @param existingDescription
	 * @param newDescription
	 * @return updateDescription
	 */
	@Override
	public boolean reconcileDescriptions(String existingDescription, String newDescription, String existingSourceDomain, String newSourceDomain, boolean considerSources) {

		boolean updateDescription = false;

		/**
		 * if existing CVE is from known source (and the new one is not) use existing
		 * description, no need for reconciliation. If existing source is unknown but
		 * the new one is known, update existing description. If both sources are known
		 * then move forward with reconciliation process
		 */
		if (considerSources && knownCveSources.containsKey(existingSourceDomain) && !knownCveSources.containsKey(newSourceDomain))
			return false;

		if (considerSources && !knownCveSources.containsKey(existingSourceDomain) && knownCveSources.containsKey(newSourceDomain))
			return true;

		if (existingDescription == null) {
			if (newDescription == null) {
				return updateDescription;
			} else {
				updateDescription = true;
				return updateDescription;
			}
		} else {
			if (newDescription == null) {
				return updateDescription;
			}
		}

		// Compare two descriptions ignoring white spaces and letter cases
		if (newDescription.replaceAll("\\s+", "").equalsIgnoreCase(existingDescription.replaceAll("\\s+", ""))) {
			return updateDescription;
		}

		/* Metrics which are used for the reconciliation decision */
		boolean newLonger = false, newHasMoreSent = false, newMoreDiverse = false, lessUnknwn = false;

		/* Counters of unidentified language parts in each description */
		int existingUnknw = 0;
		int newUnknw = 0;

		/* Check if new description has more characters */
		newLonger = newDescription.length() > existingDescription.length();

		String[] existingSentences = null;
		String[] newSentences = null;

		existingSentences = detectSentences(existingDescription);
		newSentences = detectSentences(newDescription);

		if (existingSentences == null) {
			existingSentences = new String[] { existingDescription };
		}
		if (newSentences == null) {
			newSentences = new String[] { newDescription };
		}

		/* Check if new description has more sentences */
		newHasMoreSent = newSentences.length >= existingSentences.length;

		/* Calculate diversity of language parts in each description */
		Map<String, Integer> existingDiversity = docLangParts(existingSentences);
		Map<String, Integer> newDiversity = docLangParts(newSentences);

		/* Check if new description has more diverse language parts */
		newMoreDiverse = newDiversity.size() > existingDiversity.size();

		/* Calculate how many unidentified language parts in existing description */
		if (existingDiversity.get(unknwnPrt) != null) {
			existingUnknw = existingDiversity.get(unknwnPrt);
		}

		/* Calculate how many unidentified language parts in new description */
		if (newDiversity.get(unknwnPrt) != null) {
			newUnknw = newDiversity.get(unknwnPrt);
		}

		/* Check if new description has less unidentified language parts */
		lessUnknwn = newUnknw < existingUnknw;
		/*
		 * Decision table
		 * 
		 * lessUnknwn | newLonger | newHasMoreSent | newMoreDiverse | UPDATE 0 | 0 | 0 |
		 * 0 | 0 0 | 0 | 0 | 1 | 0 0 | 0 | 1 | 0 | 0 0 | 0 | 1 | 1 | 1 0 | 1 | 0 | 0 | 0
		 * 0 | 1 | 0 | 1 | 0 0 | 1 | 1 | 0 | 0 0 | 1 | 1 | 1 | 0 1 | 0 | 0 | 0 | 0 1 | 0
		 * | 0 | 1 | 1 1 | 0 | 1 | 0 | 1 1 | 0 | 1 | 1 | 1 1 | 1 | 0 | 0 | 0 1 | 1 | 0 |
		 * 1 | 1 1 | 1 | 1 | 0 | 1 1 | 1 | 1 | 1 | 1
		 */

		/*
		 * Decision table - compressed version lessUnknwn | newLonger | newHasMoreSent |
		 * newMoreDiverse | UPDATE 0 | 0 | 1 | 1 | 1 1 | 0 | 0 | 1 | 1 1 | 0 | 1 | 0 | 1
		 * 1 | 0 | 1 | 1 | 1 1 | 1 | 0 | 1 | 1 1 | 1 | 1 | 0 | 1 1 | 1 | 1 | 1 | 1
		 */

		/* Decision rules implementation based on the decision table (above) */
		if (newHasMoreSent && newMoreDiverse) {
			updateDescription = true;
		} else if (newMoreDiverse && lessUnknwn) {
			updateDescription = true;
		} else if (lessUnknwn && newHasMoreSent) {
			updateDescription = true;
		} else if (lessUnknwn && newHasMoreSent && newMoreDiverse) {
			updateDescription = true;
		} else if (lessUnknwn && newLonger && newMoreDiverse) {
			updateDescription = true;
		} else if (lessUnknwn && newLonger && newHasMoreSent) {
			updateDescription = true;
		}

		return updateDescription;
	}

	/**
	 * Calculate diversity of the language parts in a description. Returns a Map
	 * with language parts as a KEY and the number of this laguage part as a VALUE
	 * (counts of how many time this language part occurs in the description).
	 * 
	 * @param document
	 * @return diversity object in a form of a Map object
	 */
	public Map<String, Integer> docLangParts(String[] sentences) {
		Map<String, Integer> counts = new HashMap<String, Integer>();

		for (String sent : sentences) {
			String whitespaceTokenizerLine[] = WhitespaceTokenizer.INSTANCE.tokenize(sent);
			String[] tags = tagger.tag(whitespaceTokenizerLine);
			for (String part : tags) {
				if (counts.containsKey(part)) {
					counts.put(part, counts.get(part) + 1);
				} else {
					counts.put(part, 1);
				}
			}
		}
		return counts;
	}

	public String[] detectSentences(String paragraph) {
		String sentences[] = sentenceDetector.sentDetect(paragraph);
		return sentences;
	}

}
