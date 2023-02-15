package edu.rit.se.nvip.characterizer.classifier;

import static org.junit.Assert.assertEquals;

import edu.rit.se.nvip.utils.MyProperties;
import edu.rit.se.nvip.utils.PropertyLoader;

import org.junit.Test;

public class CveClassifierFactorTest {
    @Test
    public void testGetCveClassifier() {
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

        // get CVE classification model
        CveClassifierFactory cveCharacterizerFactory = new CveClassifierFactory();

        AbstractCveClassifier aClassifier = cveCharacterizerFactory.getCveClassifier("ML", "NB", preProcessedTrainingDataFile);
        assertEquals(aClassifier.getClass(), OrdinaryCveClassifier.class);

        aClassifier = cveCharacterizerFactory.getCveClassifier("IT", "NB", preProcessedTrainingDataFile);
        assertEquals(aClassifier.getClass(), EntropyBasedCveClassifier.class);

        aClassifier = cveCharacterizerFactory.getCveClassifier("IT-ML", "NB", preProcessedTrainingDataFile);
        assertEquals(aClassifier.getClass(), EntropyThenOrdinaryClassifier.class);

        aClassifier = cveCharacterizerFactory.getCveClassifier("ML-IT", "NB", preProcessedTrainingDataFile);
        assertEquals(aClassifier.getClass(), OrdinaryThenEntropyClassifier.class);
    }
}
