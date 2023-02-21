package edu.rit.se.nvip.characterizer.classifier;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import edu.rit.se.nvip.characterizer.CveCharacterizer;
import edu.rit.se.nvip.utils.MyProperties;
import edu.rit.se.nvip.utils.PropertyLoader;
import org.junit.Test;
import weka.core.*;

import java.util.ArrayList;
import java.util.Map;

public class EntropyBasedCveClassifierTest {
    @Test
    public void testTrainMLModel() {
        MyProperties propertiesNvip = new MyProperties();
        propertiesNvip = new PropertyLoader().loadConfigFile(propertiesNvip);
        String[] trainingDataInfo = propertiesNvip.getCveCharacterizationTrainingDataInfo();
        String trainingDataPath = trainingDataInfo[0];
        String trainingDataFiles = trainingDataInfo[1];
        String[] trainingDataFileArr = trainingDataFiles.split(",");
        String trainingDataFileName = trainingDataFileArr[0];
        trainingDataFileName = trainingDataPath + trainingDataFileName;

        // pre-process training data and store it
        String preProcessedTrainingDataFile = trainingDataFileName.concat("-processed.csv");

        EntropyBasedCveClassifier entropyBasedCveClassifier = new EntropyBasedCveClassifier(preProcessedTrainingDataFile);
        entropyBasedCveClassifier.trainMLModel();

        assertEquals(entropyBasedCveClassifier.histograms.size(), 4);
    }

    @Test
    public void testPredictIncorrectNumAttributes() {
        MyProperties propertiesNvip = new MyProperties();
        propertiesNvip = new PropertyLoader().loadConfigFile(propertiesNvip);
        String[] trainingDataInfo = propertiesNvip.getCveCharacterizationTrainingDataInfo();
        String trainingDataPath = trainingDataInfo[0];
        String trainingDataFiles = trainingDataInfo[1];
        String[] trainingDataFileArr = trainingDataFiles.split(",");
        String trainingDataFileName = trainingDataFileArr[0];
        trainingDataFileName = trainingDataPath + trainingDataFileName;

        // pre-process training data and store it
        String preProcessedTrainingDataFile = trainingDataFileName.concat("-processed.csv");

        EntropyBasedCveClassifier entropyBasedCveClassifier = new EntropyBasedCveClassifier(preProcessedTrainingDataFile);

        Instance newInstance = new SparseInstance(293);
        ArrayList newList = entropyBasedCveClassifier.predict(newInstance, false);
        assertEquals(0, newList.size());
    }

    @Test
    public void testPredictCorrectNumAttributes() {
        MyProperties propertiesNvip = new MyProperties();
        propertiesNvip = new PropertyLoader().loadConfigFile(propertiesNvip);
        String[] trainingDataInfo = propertiesNvip.getCveCharacterizationTrainingDataInfo();
        String trainingDataPath = trainingDataInfo[0];
        String trainingDataFiles = trainingDataInfo[1];
        String[] trainingDataFileArr = trainingDataFiles.split(",");
        String trainingDataFileName = trainingDataFileArr[0];
        trainingDataFileName = trainingDataPath + trainingDataFileName;

        // pre-process training data and store it
        String preProcessedTrainingDataFile = trainingDataFileName.concat("-processed.csv");

        EntropyBasedCveClassifier entropyBasedCveClassifier = new EntropyBasedCveClassifier(preProcessedTrainingDataFile);
        String cveDesc = "7.2 HIGH9.0 HIGHCVE-2020-11544 Ã¢â‚¬â€� An issue was discovered in Project Worlds Official Car Rental System 1. It allows the admin user to run commands on the server with their account because the upload section on the file-manager page contains an arbitrary file upload vulnerability via... read CVE-2020-11544 Published: April 06, 2020; 12:15:13 PM -04:00 CVE-2020-11544read CVE-2020-11544V3.1:7.2 HIGH6.5 MEDIUM";

        CveCharacterizer cveCharacterizer = new CveCharacterizer(trainingDataPath, trainingDataFiles, "IT", "NB", true);
        Map<String,ArrayList<String[]>> prediction = cveCharacterizer.characterizeCveForVDO(cveDesc, true);
        //ArrayList newList = entropyBasedCveClassifier.predict(newInstance, false);
        //assertEquals(0, newList.size());
        assertTrue(prediction.size() > 0);
        cveCharacterizer = null;
    }
}
