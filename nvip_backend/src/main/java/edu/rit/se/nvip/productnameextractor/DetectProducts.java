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

import java.io.InputStream;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import edu.rit.se.nvip.utils.UtilHelper;
import opennlp.tools.postag.POSModel;
import opennlp.tools.postag.POSTaggerME;
import opennlp.tools.sentdetect.SentenceDetector;
import opennlp.tools.sentdetect.SentenceDetectorME;
import opennlp.tools.sentdetect.SentenceModel;
import opennlp.tools.tokenize.WhitespaceTokenizer;

/**
 * DetectProducts class implements Expert System to extract Software Names and
 * Software Versions from CVE descriptions
 * 
 * @author Igor Khokhlov
 *
 */

public class DetectProducts {

	public static final String NNP = "NNP";
	public static final String IN = "IN";

	NERmodel nerModel = null;

	CpeLookUp cpeDict = null;

	POSTaggerME tagger = null;
	POSModel model = null;
	SentenceModel sentenceModel = null;
	SentenceDetector sentenceDetector = null;
	String modelPath = "nlp/en-pos-perceptron.bin";
	String sentenceModelPath = "nlp/en-sent.bin";

	static private final Logger logger = LogManager.getLogger(UtilHelper.class);

	/** singleton instance of class */
	private static DetectProducts detectProducts = null;

	/**
	 * Thread safe singleton implementation
	 *
	 */
	public static synchronized DetectProducts getInstance() {
		if (detectProducts == null)
			detectProducts = new DetectProducts();

		return detectProducts;
	}

	/**
	 * Class constructor
	 */
	private DetectProducts() {
		initialize();
	}

	/**
	 * Initializer
	 */
	private void initialize() {

		try {
			// Load NER model
			logger.info("Loading NER model...");
			nerModel = new NERmodel();

			// Load CPE dictionary
			logger.info("Loading CPE dictionary...");
			cpeDict = CpeLookUp.getInstance();

			// Load Apache OpenNLP sentence model
			logger.info("Loading NLP sentence model...");
			InputStream modelStream = this.getClass().getClassLoader().getResourceAsStream(modelPath);
			assert modelStream != null;
			model = new POSModel(modelStream);
			tagger = new POSTaggerME(model);
			modelStream.close();

			InputStream modelIn = this.getClass().getClassLoader().getResourceAsStream(sentenceModelPath);
			assert modelIn != null;
			sentenceModel = new SentenceModel(modelIn);
			sentenceDetector = new SentenceDetectorME(sentenceModel);
			modelIn.close();
			logger.info("Product name extractor initialization done!");
		} catch (Exception e) {
			logger.error("Error while initializing product extractor, model path {}, sentence model path {}, exception detail {}", modelPath, sentenceModelPath, e.toString());
		}
	}

	/**
	 * Extracts SN and SV
	 * 
	 * @param words                  array of words to be classified
	 * @param nerResult<ClassifiedWord> results from NER model
	 * @return ArrayList of classified words of labels (ArrayList<ClassifiedWord>)
	 */
	private ArrayList<ClassifiedWord> getProducts(String[] words, ArrayList<ClassifiedWord> nerResult) {
		ArrayList<ClassifiedWord> result = getProductsNamesOnly(words, nerResult);
		result = getProductsVersionsOnly(words, result);
		return result;
	}

	/**
	 * Extracts SN only using Expert System
	 * 
	 * @param words                  array of words to be classified
	 * @param nerResult<ClassifiedWord> results from NER model
	 * @return ArrayList of classified words of labels (ArrayList<ClassifiedWord>)
	 */
	private ArrayList<ClassifiedWord> getProductsNamesOnly(String[] words, ArrayList<ClassifiedWord> nerResult) {

		// Confidence level of NER model below which we re-check a word in CPE
		float confThreshold = (float) 0.9;

		// Words that do not belong to SN
		String[] exclusionWords = new String[] { "the", "a", "http" };

		// Ignore the whole word if it contain one of the following words
		String[] ignoreWords = new String[] { "http" };

		// After these words, next can be SN
		String[] triggerNextWords = new String[] { "in" };
		ArrayList<String> exclusionWordsList = new ArrayList<>();
		exclusionWordsList.addAll(Arrays.asList(exclusionWords));
		ArrayList<String> triggerNextWordsList = new ArrayList<>();
		triggerNextWordsList.addAll(Arrays.asList(triggerNextWords));

		ArrayList<ClassifiedWord> result = nerResult;

		// Maximum distance (in words) from the beginning we consider
		int maxSNDistance = 40;

		String[] tags = tagger.tag(words);

		for (int i = 0; i < tags.length; i++) {
			// Check if SN word has low confidence
			if (result.get(i).getAssignedClass() == 0 && result.get(i).getAssignedClassConfidence() < confThreshold) {
				// Check in the CPE
				boolean inTheCPE = hasMatch(nerResult, words, i);
				// if not in the CPE set it to the class with second highest confidence
				if (!inTheCPE) {
					if (result.get(i).getConfidences()[2] >= result.get(i).getConfidences()[1]) {
						result.get(i).setAssignedClass(2, result.get(i).getConfidences()[2]);
					} else {
						result.get(i).setAssignedClass(1, result.get(i).getConfidences()[1]);
					}
				}
			} else if (checkTriggerWords(words[i], ignoreWords)) {
				result.get(i).setAssignedClass(2, 1);
			}
			// Word is a proper noun
			else if (tags[i].equals(NNP)) {
				// Check if it is not a exclusion word
				boolean excluded = exclusionWordsList.contains(words[i].toLowerCase());
				if (!excluded && i < maxSNDistance + 1 && result.get(i).getAssignedClass() == 2) {

					// Check if word in the CPE and assign SN class if it there
					boolean inTheCPE = hasMatch(nerResult, words, i);

					if (inTheCPE) {
						result.get(i).setAssignedClass(0, 1);
					}
				}
			}
		}

		// Second pass to mark word as SN if it is between two SN words
		int snDistance = -1;
		for (int i = 0; i < result.size(); i++) {
			if (snDistance >= 0) {
				snDistance++;
			}

			if (result.get(i).getAssignedClass() == 0) {
				snDistance = 0;
			} else if (snDistance == 1 && i < result.size() - 1 && words[i].length() > 1) {
				if (result.get(i + 1).getAssignedClass() == 0) {
					result.get(i).setAssignedClass(0, 1);
					snDistance = 0;
				}
			}
		}

		return result;
	}

	/**
	 * Verifies if the word in the CPE
	 * 
	 * @param words<ClassifiedWord> results from NER model
	 * @param index                  array of words to be classified
	 * @param nerResult                       Index of the word to be checked
	 * @return If it has match in the CPE (boolean)
	 */
	private boolean hasMatch(ArrayList<ClassifiedWord> nerResult, String[] words, int index) {

		// Get list of potential matches from CPE
		List<String> cpeList = null;
		try {
			cpeList = cpeDict.getCPEtitles(words[index]);
		} catch (Exception e) {
			logger.error(e);
		}

		if (cpeList == null) {
			return false;
		}

		// Check each item from the CPE results
		for (String cpeWord : cpeList) {
			boolean match = hasMatch(cpeWord, nerResult, words, index);
			if (match) {
				return true;
			}
		}

		return false;
	}

	/**
	 * Verifies if the word corresponds to the CPE entry
	 * 
	 * @param words                    CPE entry
	 * @param index<ClassifiedWord> results from NER model
	 * @param cpeEntry                  array of words to be classified
	 * @param nerResult                       Index of the word to be checked
	 * @return If it has match in the CPE (boolean)
	 */
	private boolean hasMatch(String cpeEntry, ArrayList<ClassifiedWord> nerResult, String[] words, int index) {

		String word = words[index];

		String[] cpewords = WhitespaceTokenizer.INSTANCE.tokenize(cpeEntry);

		// Index of the word in the CPE entry
		int matchingIndex = -1;

		// Find index of the matching word
		for (int i = 0; i < cpewords.length; i++) {
			if (cpewords[i].equalsIgnoreCase(word)) {
				matchingIndex = i;
				break;
			}
		}

		if (matchingIndex == -1) {
			return false;
		}

		if (cpewords.length == 1) {
			return true;
		}

		boolean result = false;

		// Check next word if it matches CPE entry
		if (matchingIndex == 0) {
			if (words.length <= index + 1) {
				return false;
			}
			if (cpewords[1].equalsIgnoreCase(words[index + 1])) {
				nerResult.get(index + 1).setAssignedClass(0, 1);
				return true;
			}
		}
		// Check previous word if it matches CPE entry
		else if (matchingIndex == cpewords.length - 1) {
			if (index - 1 < 0) {
				return false;
			}
			if (cpewords[cpewords.length - 2].equalsIgnoreCase(words[index - 1])) {
				nerResult.get(index - 1).setAssignedClass(0, 1);
				return true;
			}
		}
		// Check next and previous word if they match CPE entry
		else {
			if (index + 1 <= words.length - 1) {
				if (cpewords[matchingIndex + 1].equalsIgnoreCase(words[index + 1])) {
					nerResult.get(index + 1).setAssignedClass(0, 1);
					result = true;
				}
			}
			if (index - 1 >= 0) {
				if (cpewords[matchingIndex - 1].equalsIgnoreCase(words[index - 1])) {
					nerResult.get(index - 1).setAssignedClass(0, 1);
					result = true;
				}
			}
		}

		return result;
	}

	/**
	 * Check if the word in the array
	 * 
	 * @param word   word to check
	 * @param words array of words to check within
	 * @return True if the word in the array (boolean)
	 */
	private boolean checkTriggerWords(String word, String[] words) {
		boolean result = false;

		String wToCheck = word.toLowerCase();

		for (String w : words) {
			if (wToCheck.contains(w)) {
				return true;
			}
		}

		return result;
	}

	/**
	 * Extracts SV only using Expert System
	 * 
	 * @param words                  array of words to be classified
	 * @param nerResult<ClassifiedWord> results from NER model and after SN ES
	 *                                  (optional)
	 * @return ArrayList of classified words of labels (ArrayList<ClassifiedWord>)
	 */
	private ArrayList<ClassifiedWord> getProductsVersionsOnly(String[] words, ArrayList<ClassifiedWord> nerResult) {

		// Below this confidence we re-check the word
		float confThreshold = (float) 0.8;

		// Words that belong to SV
		String[] trigerWords = new String[] { "before", "earlier", "prior", "between", "after", "newer", "older", "through", ">", "=", "<", "version", "v.", "build" };

		// May belong to SV
		String[] possibleWords = new String[] { "and", "or" };

		// Not SV
		String[] ignoreWords = new String[] { "CVE" };

		int snDistance = -1;
		int svDistance = -1;

		// Maximum distance of SV from SN (in words)
		int maxSNDistance = 30;

		boolean prevWordIsSV = false;

		// Classify all SV words with confidence level less than threshold to Other
		for (ClassifiedWord classifiedWord : nerResult) {
			if (classifiedWord.getAssignedClass() == 1 && classifiedWord.getAssignedClassConfidence() < confThreshold) {
				classifiedWord.setAssignedClass(2, classifiedWord.getConfidences()[2]);
			}
		}

		for (int i = 0; i < words.length; i++) {
			if (snDistance >= 0) {
				snDistance++;
			}
			if (svDistance >= 0) {
				svDistance++;
			}
			// assign SV class
			if (nerResult.get(i).getAssignedClass() == 2 && !checkTriggerWords(words[i], ignoreWords) && (words[i].matches(".*\\d.*") || checkTriggerWords(words[i], trigerWords))) {
				if ((snDistance >= 0 && snDistance <= maxSNDistance) || prevWordIsSV) {
					nerResult.get(i).setAssignedClass(1, 1);
					prevWordIsSV = true;
					svDistance = 0;
					snDistance = -1;
				}
			}
			// reset SN distance
			else if (nerResult.get(i).getAssignedClass() == 0) {
				snDistance = 0;
			}
			// set previous word is SV flag
			else if (nerResult.get(i).getAssignedClass() == 1) {
				svDistance = 0;
				prevWordIsSV = true;
				snDistance = -1;
			}
			// Reset previous word is SV flag
			else {
				prevWordIsSV = false;
			}
		}

		// Second pass to mark word as SV if it is between two SV words
		svDistance = -1;
		for (int i = 0; i < nerResult.size(); i++) {
			if (svDistance >= 0) {
				svDistance++;
			}

			if (nerResult.get(i).getAssignedClass() == 1) {
				svDistance = 0;
			} else if (svDistance == 1 && i < nerResult.size() - 1 && checkTriggerWords(words[i], possibleWords)) {

				if (nerResult.get(i + 1).getAssignedClass() == 1) {
					nerResult.get(i).setAssignedClass(1, 1);
					svDistance = 0;
				}
			}
		}

		return nerResult;
	}

	/**
	 * Extracts SN and SV from a CVE description using both NER and Expert System
	 * 
	 * @param descriptionWords array of words to be classified
	 * @return ArrayList of classified words of labels (ArrayList<ClassifiedWord>)
	 */
	public ArrayList<ClassifiedWord> classifyWordsInDescription(String[] descriptionWords) {

		// Use NER classification
		ArrayList<ClassifiedWord> nerResult = nerModel.classifyComplex(descriptionWords);

		// Use ES classification
		nerResult = getProducts(descriptionWords, nerResult);

		return new ArrayList<>(nerResult);
	}

	/**
	 * Extracts SN and SV from a CVE description using both NER and Expert System
	 * 
	 * @param description Description to be classified
	 * @return ArrayList of classified words of labels (ArrayList<ClassifiedWord>)
	 */
	public ArrayList<ClassifiedWord> classifyWordsInDescription(String description) {

		if (description == null || description.length() == 0) {
			return null;
		}

		String[] descriptionWords = WhitespaceTokenizer.INSTANCE.tokenize(description);

		return classifyWordsInDescription(descriptionWords);
	}

	/**
	 * Matches SN and SV into complete product using Expert System
	 * 
	 * @param words<ClassifiedWord> List of classified words of labels
	 * @return List of products (ArrayList<ProductItem>)
	 */
	public ArrayList<ProductItem> getProductItems(ArrayList<ClassifiedWord> words) {

		ArrayList<ProductItem> products = new ArrayList<>();

		boolean prevWordSN = false;
		for (ClassifiedWord word : words) {
			if (word.getAssignedClass() == 0) {
				// Adds word to existing product name
				if (prevWordSN) {
					ProductItem product = products.get(products.size() - 1);
					product.setName(product.getName() + " " + word.getWord());
					products.set(products.size() - 1, product);
				}
				// creates new product
				else {
					products.add(new ProductItem(word.getWord()));
				}
				prevWordSN = true;
			} else if (word.getAssignedClass() == 1) {
				prevWordSN = false;
				// adds version to the product item
				if (products.size() > 0) {
					ProductItem product = products.get(products.size() - 1);
					product.addVersion(word.getWord());
					products.set(products.size() - 1, product);
				}
			} else {
				prevWordSN = false;
			}
		}

		return products;
	}

	/**
	 * Matches SN and SV into complete product using Expert System
	 * 
	 * @param descriptionWords Description words to be classified
	 * @return List of products (ArrayList<ProductItem>)
	 */
	public ArrayList<ProductItem> getProductItems(String[] descriptionWords) {

		ArrayList<ClassifiedWord> words = classifyWordsInDescription(descriptionWords);

		return getProductItems(words);
	}

}
