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
