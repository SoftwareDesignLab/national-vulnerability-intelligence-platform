package edu.rit.se.nvip.characterizer.preprocessor;

import static org.junit.Assert.assertEquals;

import java.io.File;

import org.junit.Test;

import edu.rit.se.nvip.characterizer.CvePreProcessor;

public class PreProcessorTest {
	@Test
	public void testDataDirs() {
		/**
		 * Test the existence of NVD and MITRE CVEs
		 */
		String input = "Heap-based buffer overflow in the strip_escapes function in signal.c in GNU ed before 1.0 allows context-dependent or user-assisted attackers to execute arbitrary code via a long filename. NOTE: since ed itself does not typically run with special privileges this issue only crosses privilege boundaries when ed is invoked as a third-party component.";
		String output = "heap base buffer overflow strip escap function signal gnu ed allow context depend user assist attack execut arbitrari code filenam note ed doe typic run special privileg issu cross privileg boundari ed invok parti compon ";
		CvePreProcessor nvipPreProcessor = new CvePreProcessor(true);
		String sTemp = nvipPreProcessor.preProcessLine(input);
		assertEquals(true, sTemp.contains(output));
	}

}
