package edu.rit.se.nvip.cvss;

import static org.junit.Assert.assertEquals;

import org.junit.Test;

import edu.rit.se.nvip.automatedcvss.CvssScoreCalculator;

public class CvssScoreCalculatorTest {

	@Test
	public void cvssCalculatorTest() {
		CvssScoreCalculator cvssScorer = new CvssScoreCalculator();
		String[] cvssVec = new String[] { "P", "X", "X", "X", "X", "H", "H", "H" };
		double[] scores = cvssScorer.getCvssScoreJython(cvssVec);
		assertEquals(true, (scores[0] != -1));
	}

}
