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

import java.io.File;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Random;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.deeplearning4j.nn.multilayer.MultiLayerNetwork;
import org.nd4j.linalg.api.ndarray.INDArray;
import org.nd4j.linalg.dataset.api.preprocessor.DataNormalization;
import org.nd4j.linalg.dataset.api.preprocessor.serializer.NormalizerSerializer;
import org.nd4j.linalg.factory.Nd4j;

import edu.rit.se.nvip.utils.MyProperties;
import edu.rit.se.nvip.utils.PropertyLoader;
import edu.rit.se.nvip.utils.UtilHelper;
import opennlp.tools.sentdetect.SentenceDetector;
import opennlp.tools.sentdetect.SentenceDetectorME;
import opennlp.tools.sentdetect.SentenceModel;
import opennlp.tools.tokenize.WhitespaceTokenizer;

/**
 * NER class for classification words in the CVE description into "Software Name", "Software Version", and "Others"
 * 
 * Implementation of the Dong, Ying, Wenbo Guo, Yueqi Chen, Xinyu Xing, Yuqing Zhang, and Gang Wang. &quot;Towards the 
 * detection of inconsistencies in public security vulnerability reports.&quot; In 28th {USENIX} Security
 * Symposium ({USENIX} Security 19), pp. 869-885. 2019.
 * 
 * @author Igor Khokhlov
 *
 */

public class NERmodel {

	private boolean timingOn = false;

	private MultiLayerNetwork model = null; // NER model
	private Char2vec c2vModel = null; // Char2Vector model
	private Word2Vector w2vModel = null; // Word2Vector model
	static public final int numLabelClasses = 3; // Number of classes (SN, SV, O)
	private int featureLength = 300; // length of the input features vector.

	private int wordVecLength = 250; // Expected length of the word2vector model output. Later will be updated from the actual model
	private int charVecLength = 50; // Expected length of the char2vector model output. Later will be updated from the actual model

	private static Random rand = new Random(); // Needed in the case when word2vector model doesn't know the word

	public static final String SN = "SN", SV = "SV", OTHER = "O"; // class names

	private String sentenceModelPath = "nlp/en-sent.bin"; // path to Apache Open NLP sentence model

	private SentenceModel sentenceModel = null;
	private SentenceDetector sentenceDetector = null;

	private DataNormalization restoredNormalizer = null; // Feature normalizer

	private Logger logger = LogManager.getLogger(getClass().getSimpleName());

	/**
	 * Class constructor
	 */
	public NERmodel() {
		super();

		try {
			MyProperties propertiesNvip = new MyProperties();
			propertiesNvip = new PropertyLoader().loadConfigFile(propertiesNvip);

			// Get models paths
			String modelsDir = propertiesNvip.getDataDir() + "/" + propertiesNvip.getNameExtractorDir() + "/";
			String c2vModelConfigPath = modelsDir + propertiesNvip.getChar2VecModelConfigPath();
			String c2vModelWeightsPath = modelsDir + propertiesNvip.getChar2VecModelWeightsPath();
			String w2vModelPath = modelsDir + propertiesNvip.getWord2VecModelPath();
			String nerModelPath = modelsDir + propertiesNvip.getNerModelPath();
			String nerNormalizerPath = modelsDir + propertiesNvip.getNerModelNormalizerPath();

			long startTime = System.currentTimeMillis();
			// Load NER model
			try {
				model = MultiLayerNetwork.load(new File(nerModelPath), false);
			} catch (Exception e) {
				logger.error("Error loading MultiLayerNetwork for product name extraction from path {}: {}", nerModelPath, e.toString());
			}
			long endTime = System.currentTimeMillis();

			if (timingOn) {
				logger.info("Timing for NER model loading: " + Long.toString(endTime - startTime) + "ms.");
			}

			// Load Char2vec model
			startTime = System.currentTimeMillis();
			c2vModel = new Char2vec(c2vModelConfigPath, c2vModelWeightsPath);
			endTime = System.currentTimeMillis();
			charVecLength = c2vModel.getOutVectorLength();

			if (timingOn) {
				logger.info("Timing for Char2Vector model initializing: " + Long.toString(endTime - startTime) + "ms.");
			}

			// Load Word2Vector model
			startTime = System.currentTimeMillis();
			w2vModel = new Word2Vector(w2vModelPath);
			endTime = System.currentTimeMillis();
			wordVecLength = w2vModel.getOutVectorLength();

			if (timingOn) {
				logger.info("Timing for Word2Vector model initializing: " + Long.toString(endTime - startTime) + "ms.");
			}

			rand = new Random();
			featureLength = wordVecLength + charVecLength;

			// Load Apache Open NLP sentence detector model
			try {
				startTime = System.currentTimeMillis();
				InputStream modelIn = this.getClass().getClassLoader().getResourceAsStream(sentenceModelPath);
				sentenceModel = new SentenceModel(modelIn);
				sentenceDetector = new SentenceDetectorME(sentenceModel);
				modelIn.close();
				endTime = System.currentTimeMillis();
				if (timingOn) {
					logger.info("Timing for Sentence detector model loading: " + Long.toString(endTime - startTime) + "ms.");
				}
			} catch (Exception e) {
				logger.error("Error loading sentence model for product name extraction from {}: {}", sentenceModelPath, e.toString());
			}

			// Load features Normalizer
			startTime = System.currentTimeMillis();
			NormalizerSerializer loader = NormalizerSerializer.getDefault();
			try {
				restoredNormalizer = loader.restore(new File(nerNormalizerPath));
			} catch (Exception e) {
				logger.error("Error while restoring normalizer from {}: {}", nerNormalizerPath, e.toString());
			}
			endTime = System.currentTimeMillis();
			if (timingOn) {
				logger.info("Timing for Sentence detector model loading: " + Long.toString(endTime - startTime) + "ms.");
			}
		} catch (Exception e) {
			logger.error("Error initializing NERmodel {}", e.toString());
		}

	}

	/**
	 * Classifies each word in the array of words (strings) as one of three classes (SN, SV, O)
	 * 
	 * @param String[] array of words to be classified
	 * @return Array of labels (strings) of classes
	 */
	public String[] classify(String[] words) {

		String[] result = new String[words.length];
		float[][] features = new float[words.length][featureLength];

		long startTime = System.currentTimeMillis();
		// Convert each word into a feature vector
		for (int i = 0; i < words.length; i++) {
			features[i] = word2vector(words[i], w2vModel, wordVecLength, c2vModel, charVecLength, logger);
		}

		long endTime = System.currentTimeMillis();
		if (timingOn) {
			logger.info("Timing for converting " + Integer.toString(words.length) + " words into 300 long feature vectors: " + Long.toString(endTime - startTime) + "ms.");
		}

		INDArray featuresDL4J = Nd4j.zeros(1, featureLength, words.length);

		// Convert features into 3D-array acceptable by DL4J model
		int[] indecies = new int[3];
		for (int i = 0; i < words.length; i++) {
			indecies[2] = i;
			for (int j = 0; j < featureLength; j++) {
				indecies[1] = j;
				featuresDL4J.putScalar(indecies, features[i][j]);
			}
		}

		// Normalize features
		restoredNormalizer.transform(featuresDL4J);

		// Perform classification
		startTime = System.currentTimeMillis();
		INDArray out = model.output(featuresDL4J);
		endTime = System.currentTimeMillis();
		if (timingOn) {
			logger.info("Timing for description classification (model.output(featuresDL4J)): " + Long.toString(endTime - startTime) + "ms.");
		}

		// Determine class based on the confidence levels of the model output
		float maxValue = 0;
		float curValue = 0;
		int classNum = 0;

		for (int i = 0; i < words.length; i++) {
			indecies[2] = i;
			maxValue = 0;
			curValue = 0;
			classNum = 0;
			for (int j = 0; j < numLabelClasses; j++) {
				indecies[1] = j;
				curValue = out.getFloat(indecies);
				if (curValue > maxValue) {
					maxValue = curValue;
					classNum = j;
				}
			}
			// assign class labels
			result[i] = assignClassLabel(classNum);
		}

		return result;
	}

	/**
	 * Classifies each word in the array of words (strings) as one of three classes (SN, SV, O)
	 * 
	 * @param String[] array of words to be classified
	 * @return ArrayList of Classified Words (ClassifiedWord objects)
	 */
	public ArrayList<ClassifiedWord> classifyComplex(String[] words) {

		ArrayList<ClassifiedWord> result = new ArrayList<ClassifiedWord>();
		float[][] features = new float[words.length][featureLength];

		// Convert each word into a feature vector
		for (int i = 0; i < words.length; i++) {
			features[i] = word2vector(words[i], w2vModel, wordVecLength, c2vModel, charVecLength, logger);
		}

		INDArray featuresDL4J = Nd4j.zeros(1, featureLength, words.length);

		// Convert features into 3D-array acceptable by DL4J model
		int[] indecies = new int[3];
		for (int i = 0; i < words.length; i++) {
			indecies[2] = i;
			for (int j = 0; j < featureLength; j++) {
				indecies[1] = j;
				featuresDL4J.putScalar(indecies, features[i][j]);
			}
		}

		// Normalize features
		restoredNormalizer.transform(featuresDL4J);

		// Perform classification
		INDArray out = model.output(featuresDL4J);

		// Get confidence levels of the model output and create ClassifiedWord objects
		for (int i = 0; i < words.length; i++) {
			indecies[2] = i;
			float[] confidences = new float[numLabelClasses];
			for (int j = 0; j < numLabelClasses; j++) {
				indecies[1] = j;
				confidences[j] = out.getFloat(indecies);
			}
			result.add(new ClassifiedWord(words[i], confidences));
		}

		return result;
	}

	/**
	 * Classifies the whole description
	 * 
	 * @param String description
	 * @return ArrayList of Classified Words (ClassifiedWord objects) or NULL if description is null or
	 *         empty
	 */
	public ArrayList<ClassifiedWord> classifyComplex(String description) {

		if (description == null || description.length() == 0) {
			return null;
		}

		String[] descriptionWords = WhitespaceTokenizer.INSTANCE.tokenize(description);

		ArrayList<ClassifiedWord> result = classifyComplex(descriptionWords);

		return result;
	}

	/**
	 * Convert classes numbers into labels (SN, SV, O)
	 * 
	 * @param int class number
	 * @return String class label
	 */
	private String assignClassLabel(int classNum) {
		String classLabel = null;

		if (classNum == 0) {
			classLabel = SN;
		} else if (classNum == 1) {
			classLabel = SV;
		} else {
			classLabel = OTHER;
		}

		return classLabel;
	}

	/**
	 * Convert word into the 1D features vector
	 * 
	 * @param String      word to be converted
	 * @param Word2Vector model instance
	 * @param int         length of the word2vector vector
	 * @param Char2vec    model instance
	 * @param int         length of the Char2vec vector
	 * 
	 * @return features vector (length = length of the word2vector + length of the Char2vec vector)
	 */
	public static float[] word2vector(String word, Word2Vector wordModel, int wordVecSize, Char2vec charModel, int charVecSize, Logger log) {

		float[] wordVector = new float[wordVecSize + charVecSize];

		// get word embedding from word2vector model
		double[] wordVector1 = wordModel.word2vector(word);
		float[] wordVector2 = null;

		// get word embedding from char2vector model (on the character level)
		try {
			wordVector2 = charModel.word2vec(word);
		} catch (Exception e) {
			log.error(e);
		}

		// convert double[] to float[]
		if (wordVector2 == null) {
			wordVector2 = new float[charVecSize];
		}

		for (int i = 0; i < wordVecSize; i++) {
			if (wordVector1 != null) {
				wordVector[i] = (float) wordVector1[i];
			}
			// if word2vector model does not know the word, generate vector random values
			else {
				wordVector[i] = rand.nextFloat() * 2 - 1; // has to be between -1 and 1
			}
		}

		// Concatenate vectors
		for (int i = wordVecSize; i < wordVecSize + charVecSize; i++) {
			wordVector[i] = wordVector2[i - wordVecSize];
		}

		return wordVector;
	}

	/**
	 * classify words in the description into one of three classes (SN, SV, O)
	 * 
	 * @param String description text
	 * 
	 * @return ArrayList of strings arrays. Each array contains word (index=0) and the assigned class
	 *         (index=1)
	 */
	public ArrayList<String[]> classify(String description) {
		ArrayList<String[]> result = new ArrayList<String[]>();

		// Split description into sentences
		String sentences[] = sentenceDetector.sentDetect(description);

		// Split description into words
		ArrayList<String> wordsList = new ArrayList<String>();
		for (String sent : sentences) {
			String whitespaceTokenizerLine[] = WhitespaceTokenizer.INSTANCE.tokenize(sent);
			wordsList.addAll(Arrays.asList(whitespaceTokenizerLine));
		}

		// convert ArrayList into array of strings
		String[] words = wordsList.toArray(new String[wordsList.size()]);

		// Perform classification
		String[] resultClasses = classify(words);

		// assemble the output
		for (int i = 0; i < words.length; i++) {
			result.add(new String[] { words[i], resultClasses[i] });
		}

		return result;
	}

	/**
	 * Returns expected length of the vector after word2vec and char2vec vectors concatenation
	 * 
	 * @return expected length of the vector after concatenation
	 */
	public int getFeatureLength() {
		return featureLength;
	}

	/**
	 * Returns expected length of the vector after word embedding on the word level
	 * 
	 * @return expected length of the vector after word embedding on the word level
	 */
	public int getWordVecLength() {
		return wordVecLength;
	}

	/**
	 * Returns expected length of the vector after word embedding on the character level
	 * 
	 * @return expected length of the vector after word embedding on the character level
	 */
	public int getCharVecLength() {
		return charVecLength;
	}

}
