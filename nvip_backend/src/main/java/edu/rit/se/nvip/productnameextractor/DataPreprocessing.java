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

import java.io.BufferedReader;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.IOException;
import java.nio.charset.Charset;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.Random;

import org.apache.commons.io.FileUtils;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import edu.rit.se.nvip.utils.MyProperties;
import edu.rit.se.nvip.utils.PropertyLoader;
import edu.rit.se.nvip.utils.UtilHelper;

/**
 * DataPreprocessing class to convert training and test data acceptable by our NER model
 * 
 * Converts data published in the paper:
 * Implementation of the Dong, Ying, Wenbo Guo, Yueqi Chen, Xinyu Xing, Yuqing Zhang, and Gang Wang. &quot;Towards the 
 * detection of inconsistencies in public security vulnerability reports.&quot; In 28th {USENIX} Security
 * Symposium ({USENIX} Security 19), pp. 869-885. 2019.
 * 
 * @author Igor Khokhlov
 *
 */

public class DataPreprocessing {
	
	private static Logger logger = LogManager.getLogger(DataPreprocessing.class);
		
	private static Random rand = new Random(); //Needed in the case when word2vector model doesn't know the word

	/**
	 * Coverts data for NER model training
	 * @param String file with training data or directory with training data files
	 * @param String file with test data or directory with test data files
	 * @param String path to converted data (parent directory, sub-directories will be created)
	 * 
	 * Calling examples:
	 * d:\RIT\NVIP\Data_to_convert\train.txt d:\RIT\NVIP\Data_to_convert\test.txt d:\RIT\NVIP\NER_data
	 * d:\RIT\NVIP\Data_to_convert\train_data_folder\ d:\RIT\NVIP\Data_to_convert\test_data_folder\ d:\RIT\NVIP\NER_data
	 * 
	 * Structure of the data folder will be:
	 * DataPath:
	 * 			test:
	 * 				features:
	 * 				labels:
	 * 			train:
	 *  			features:
	 * 				labels:
	 */		
	public static void main(String[] args) {
		
		if (args.length != 3) {
			logger.error("Incorrect number of arguments!");
			return;
		}
		
		String trainDataPath = args[0];
		String testDataPath = args[1];
		String destinationFolder = args[2];
		
		String trainFeaturePath = destinationFolder + "\\train\\features\\";
		String trainLabelPath = destinationFolder + "\\train\\labels\\";
		
		String testFeaturePath = destinationFolder + "\\test\\features\\";
		String testLabelPath = destinationFolder + "\\test\\labels\\";
		
		//check if a folder exists and create if it does not
		File directory = new File(trainFeaturePath);
		if (! directory.exists()){
			logger.info("Creating train feature folders...");
	        directory.mkdirs();
	    }
		
		directory = new File(trainLabelPath);
		if (! directory.exists()){
			logger.info("Creating train labels folders...");
	        directory.mkdirs();
	    }
		
		directory = new File(testFeaturePath);
		if (! directory.exists()){
			logger.info("Creating test features folders...");
	        directory.mkdirs();
	    }
		
		directory = new File(testLabelPath);
		if (! directory.exists()){
			logger.info("Creating test labels folders...");
	        directory.mkdirs();
	    }
		
		MyProperties propertiesNvip = new MyProperties();
		propertiesNvip = new PropertyLoader().loadConfigFile(propertiesNvip);
		
		// Get models paths
		String modelsDir = propertiesNvip.getDataDir() + "/" + propertiesNvip.getNameExtractorDir() + "/";
		String c2vModelConfigPath = modelsDir + propertiesNvip.getChar2VecModelConfigPath();
		String c2vModelWeightsPath = modelsDir + propertiesNvip.getChar2VecModelWeightsPath();
		String w2vModelPath = modelsDir + propertiesNvip.getWord2VecModelPath();
		
		//Load Char2vec model
		Char2vec c2vModel = new Char2vec(c2vModelConfigPath,c2vModelWeightsPath);
		int charVecLength = c2vModel.getOutVectorLength();
		
		//Load Word2Vector model
		Word2Vector w2vModel = new Word2Vector(w2vModelPath);
		int wordVecLength = w2vModel.getOutVectorLength();
		
		rand = new Random();
		
		File trainFile = new File(trainDataPath);
		boolean trainPathIsDir = trainFile.isDirectory();
		
		File testfile = new File(testDataPath);
		boolean testPathIsDir = testfile.isDirectory();
		
		ArrayList<String[]> trainDataList = null;
		ArrayList<String[]> testDataList = null;
		
		if (trainPathIsDir) {
			logger.info("Train dataset is in the folder" + trainDataPath);
			String[] filePaths = trainFile.list();
			if (filePaths.length==0) {
				logger.error("The training directory is empty!");
				return;
			}
			trainDataList = new ArrayList<String[]>();
			for (String path:filePaths) {
				ArrayList<String[]> dataSubSet = readDataset(trainDataPath+path);
				trainDataList.addAll(dataSubSet);				
				logger.info(path + " file added " + Integer.toString(dataSubSet.size()) + " words were added to the training dataset");
			}
		}
		else {
			logger.info("Train dataset is in the file" + testDataPath);
			trainDataList = readDataset(trainDataPath);
		}
		
		logger.info("Train dataset size is " + Integer.toString(trainDataList.size()) + " words.");
		
		if (testPathIsDir) {
			String[] filePaths = testfile.list();
			logger.info("Test dataset is in the folder" + testDataPath);
			if (filePaths.length==0) {
				logger.error("The testing directory is empty!");
				return;
			}
			testDataList = new ArrayList<String[]>();
			for (String path:filePaths) {
				ArrayList<String[]> dataSubSet = readDataset(testDataPath+path);
				testDataList.addAll(dataSubSet);
				logger.info(path + " file added " + Integer.toString(dataSubSet.size()) + " words were added to the test dataset");
			}
		}
		else {
			logger.info("Test dataset is in the file" + testDataPath);
			testDataList = readDataset(testDataPath);
		}
		
		logger.info("Test dataset size is " + Integer.toString(testDataList.size()) + " words.");
		
    	int listSize = trainDataList.size();
    	String[] labelsNER = new String[listSize];
    	
    	for (int i=0; i<listSize; i++) {
    		labelsNER[i]=trainDataList.get(i)[1];
    	}
    	
    	String[] labelsNERTest = new String[testDataList.size()];
    	
    	for (int i=0; i<labelsNERTest.length; i++) {
    		labelsNERTest[i]=testDataList.get(i)[1];
    	}
    	
    	ArrayList<float[]> resultvectors = new ArrayList<float[]>();
    	ArrayList<float[]> resultvectorsTest = new ArrayList<float[]>();
    	
    	logger.info("Starting train data...");
    	
    	for (int i=0; i<trainDataList.size(); i++) {
    		if (trainDataList.get(i)[0].length()>0) {
    			resultvectors.add(NERmodel.word2vector(trainDataList.get(i)[0], w2vModel, wordVecLength, c2vModel, charVecLength, logger));
    		}
    		else {
    			resultvectors.add(new float[] {});
    		}
        }
    	reformatDataBySentences(resultvectors, labelsNER, trainFeaturePath, trainLabelPath);
    	
    	logger.info("Train data is DONE! Starting Test data...");
    	
    	for (int i=0; i<testDataList.size(); i++) {
    		if (testDataList.get(i)[0].length()>0) {
    			resultvectorsTest.add(NERmodel.word2vector(testDataList.get(i)[0], w2vModel, wordVecLength, c2vModel, charVecLength, logger));
    		}
    		else {
    			resultvectorsTest.add(new float[] {});
    		}
        }  	
    	reformatDataBySentences(resultvectorsTest, labelsNERTest, testFeaturePath, testLabelPath);
    	
    	logger.info("Conversion is finished!");

	}
	
	private static ArrayList<String[]> readDataset(String filePath) {
		
		BufferedReader bReader = null;
		ArrayList<String[]> wordsList = null;
		try {
			
			wordsList = new ArrayList<String[]>();
			
			File file = new File(filePath);

			bReader = new BufferedReader(new FileReader(file));
			
			String sLine;
			while((sLine = bReader.readLine()) != null) {
				if (sLine.length()>0) {
					int spaceIndex = sLine.indexOf(" ");
					if (spaceIndex>0) {
						String word = sLine.substring(0, spaceIndex);
						String label = sLine.substring(spaceIndex+1, sLine.length());
						wordsList.add(new String[]{word,label});
					}
				}
				else {
					wordsList.add(new String[] {"",""});
				}
			}
		} catch (FileNotFoundException e) {
			logger.error(e);
		} catch (IOException e) {
			logger.error(e);
		} finally {
			if (bReader != null) {
				try {
					bReader.close();
				} catch (IOException e) {
					logger.error(e);
				}
			}
		}
		
		return wordsList;
		
	}
	
	static private void reformatData(ArrayList<float[]> features, String[] labels, String featuresPath, String labelPath) {
		
		String sn = "SN"; //software name label = 0
		String sv = "SV"; //software version label = 1
		String other = "O"; //Other label = 2
		
		String label = null;
		
		for (int i=0; i<features.size(); i++) {
			//Write output in a format we can read, in the appropriate locations
            File outPathFeatures;
            File outPathLabels;
            
            outPathFeatures = new File(featuresPath, i + ".csv");
            outPathLabels = new File(labelPath, i + ".csv");
            
            String featureVector = "";
            float[] floatVector = features.get(i);
            
            for (int j=0; j<floatVector.length; j++) {
            	if (j!=floatVector.length-1) {
            		featureVector = featureVector + Float.toString(floatVector[j]) + ",";
            	}
            	else {
            		featureVector = featureVector + Float.toString(floatVector[j]);
            	}
            }
                        
            if (labels[i].equals(sn)) {
            	label = "0";
            }
//            else {
//            	label="1";
//            }
            else if (labels[i].equals(sv)) {
            	label="1";
            }
            else {
            	label="2";
            }
			
            try {
				FileUtils.writeStringToFile(outPathFeatures, featureVector, (Charset) null);
				FileUtils.writeStringToFile(outPathLabels, label, (Charset) null);
			} catch (IOException e) {
				logger.error(e);
			}
			
		}
		
	}
	
	static private void reformatDataBySentences(ArrayList<float[]> features, String[] labels, String featuresPath, String labelPath) {
		
		String sn = "SN"; //software name label = 0
		String sv = "SV"; //software version label = 1
		String other = "O"; //Other label = 2
		
		int fileNameCounter = 0; //need this to name files consequently 
		String featuresToWrite=""; //contains feature vectors of the whole sentence
		String labelsToWrite=""; //contains labels of the whole sentence
		
		for (int i=0; i<features.size(); i++) {
			
            float[] floatVector = features.get(i);
            
            if (floatVector.length>0) {
            	
            	if(featuresToWrite.length()>0) {
            		featuresToWrite = featuresToWrite + "\n";
            	}
            	
            	for (int j=0; j<floatVector.length; j++) {
                	if (j!=floatVector.length-1) {
                		featuresToWrite = featuresToWrite + Float.toString(floatVector[j]) + ",";
                	}
                	else {
                		featuresToWrite = featuresToWrite + Float.toString(floatVector[j]);
                	}
                }
            	
            	if(labelsToWrite.length()>0) {
            		labelsToWrite = labelsToWrite + "\n";
            	}
                            
                if (labels[i].equals(sn)) {
                	labelsToWrite = labelsToWrite+"0";
                }
//                else {
//                	label="1";
//                }
                else if (labels[i].equals(sv)) {
                	labelsToWrite=labelsToWrite+"1";
                }
                else {
                	labelsToWrite=labelsToWrite+"2";
                }
            }
            else {
            	try {
    				FileUtils.writeStringToFile(new File(featuresPath, fileNameCounter + ".csv"), featuresToWrite, (Charset) null);
    				FileUtils.writeStringToFile(new File(labelPath, fileNameCounter + ".csv"), labelsToWrite, (Charset) null);
    				fileNameCounter++;
    				featuresToWrite="";
    				labelsToWrite="";
    			} catch (IOException e) {
    				logger.error(e);
    			}
            }		
		}	
	}
}
