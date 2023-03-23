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
package edu.rit.se.nvip.characterizer.classifier;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import weka.classifiers.Classifier;
import weka.classifiers.bayes.NaiveBayes;
import weka.classifiers.functions.SMO;
import weka.classifiers.meta.Vote;
import weka.classifiers.trees.J48;
import weka.classifiers.trees.RandomForest;

/**
 * 
 * @author axoeec
 *
 */
public class CveClassifierFactory {
	private Logger logger = LogManager.getLogger(getClass().getSimpleName());

	public AbstractCveClassifier getCveClassifier(String approach, String method, String preProcessedTrainingDataFile) {
		AbstractCveClassifier cveClassifier = null;
		// cve characterization approach
		Classifier classifier = null;
		if (approach.equalsIgnoreCase("ML")) {
			try {
				switch (method) {
				case "SVM":
					classifier = new SMO();
					break;
				case "DT":
					classifier = new J48();
					break;
				case "RF":
					classifier = new RandomForest();
					break;
				case "NB":
					classifier = new NaiveBayes();
					break;
				case "Vote":
					Vote vote = new Vote();
					Classifier[] voteClassifiers = new Classifier[] { new RandomForest(), new SMO(), new NaiveBayes(), new J48() };
					vote.setClassifiers(voteClassifiers);
					classifier = vote;
					break;
				}
			} catch (Exception e) {
				classifier = new RandomForest();
			}

			cveClassifier = new OrdinaryCveClassifier(classifier, preProcessedTrainingDataFile);

		} else if (approach.equalsIgnoreCase("IT")) {
			cveClassifier = new EntropyBasedCveClassifier(preProcessedTrainingDataFile);
			cveClassifier.resetClassifier(method); // CE,KLD or JSD
		} else if (approach.equalsIgnoreCase("IT-ML")) {
			cveClassifier = new EntropyThenOrdinaryClassifier(preProcessedTrainingDataFile);
			cveClassifier.resetClassifier(method); // CE,KLD or JSD
		} else if (approach.equalsIgnoreCase("ML-IT")) {
			cveClassifier = new OrdinaryThenEntropyClassifier(new Vote(), preProcessedTrainingDataFile);
		} else {
			logger.error("Error in config file. Define the Characterization approach!");
			System.exit(1);
		}

		return cveClassifier;
	}
}
