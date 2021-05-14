/**
 * Copyright 2021 Rochester Institute of Technology (RIT). Developed with
 * government support under contract 70RSAT19CB0000020 awarded by the United
 * States Department of Homeland Security.
 * 
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the �Software�), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 * 
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 * 
 * THE SOFTWARE IS PROVIDED �AS IS�, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */
package edu.rit.se.nvip.productnameextractor;

import static org.junit.Assert.assertEquals;
import java.util.List;

import org.junit.Test;

/**
 * Unit tests for the CPElookUp class
 * 
 * @author Igor Khokhlov
 *
 */

public class CPElookUpTest {

	@Test
	public void legitemateProduct() {

		CpeLookUp cpeLookUp = CpeLookUp.getInstance();

		ProductItem product = new ProductItem("phpMyAdmin");
		product.addVersion("4.8.4");

		String expectedResult = "cpe:2.3:a:phpmyadmin:phpmyadmin:4.8.4:*:*:*:*:*:*:*";

		List<String> idList = cpeLookUp.getCPEids(product);

		boolean correctResult = false;
		boolean notEmpty = false;

		if (idList != null && idList.size() > 0) {
			notEmpty = true;
			correctResult = expectedResult.equals(idList.get(0));
		}

		assertEquals("Result is not empty", true, notEmpty);
		assertEquals("Result is correct", true, correctResult);
	}

	@Test
	public void legitemateComplexProduct() {

		CpeLookUp cpeLookUp = CpeLookUp.getInstance();

		ProductItem product = new ProductItem("phpMyAdmin.");
		product.addVersion("before  4.8.4");

		String expectedResult = "cpe:2.3:a:phpmyadmin:phpmyadmin:4.8.4:*:*:*:*:*:*:*";

		List<String> idList = cpeLookUp.getCPEids(product);

		boolean correctResult = false;
		boolean notEmpty = false;

		if (idList != null && idList.size() > 0) {
			notEmpty = true;
			correctResult = expectedResult.equals(idList.get(0));
		}

		assertEquals("Result is not empty", true, notEmpty);
		assertEquals("Result is correct", true, correctResult);
	}

	@Test
	public void legitemateComplexProduct2() {

		CpeLookUp cpeLookUp = CpeLookUp.getInstance();

		ProductItem product = new ProductItem("phpMyAdmin:.");
		product.addVersion("https://www.openwall.com/lists/oss-security/2012/05/10/6");
		product.addVersion("before");
		product.addVersion("4.8.4");

		String expectedResult = "cpe:2.3:a:phpmyadmin:phpmyadmin:4.8.4:*:*:*:*:*:*:*";

		List<String> idList = cpeLookUp.getCPEids(product);

		boolean correctResult = false;
		boolean notEmpty = false;

		if (idList != null && idList.size() > 0) {
			notEmpty = true;
			correctResult = expectedResult.equals(idList.get(0));
		}

		assertEquals("Result is not empty", true, notEmpty);
		assertEquals("Result is correct", true, correctResult);
	}

	@Test
	public void legitemateComplexProduct3() {

		CpeLookUp cpeLookUp = CpeLookUp.getInstance();

		ProductItem product = new ProductItem("the Linux.");
		product.addVersion("https://www.openwall.com/lists/oss-security/2012/05/10/6");

		String expectedResult = "cpe:2.3:a:sun:linux:*:*:*:*:*:*:*:*";

		List<String> idList = cpeLookUp.getCPEids(product);

		boolean correctResult = false;
		boolean notEmpty = false;

		if (idList != null && idList.size() > 0) {
			notEmpty = true;
			correctResult = expectedResult.equals(idList.get(0));
		}

		assertEquals("Result is not empty", true, notEmpty);
		assertEquals("Result is correct", true, correctResult);
	}

	@Test
	public void legitemateComplexProductMultipleVersions() {

		CpeLookUp cpeLookUp = CpeLookUp.getInstance();

		ProductItem product = new ProductItem("phpMyAdmin.");
		product.addVersion("4.8.0.1");
		product.addVersion("4.8.4");
		product.addVersion("4.7.9");

		String expectedResult1 = "cpe:2.3:a:phpmyadmin:phpmyadmin:4.8.0.1:*:*:*:*:*:*:*";
		String expectedResult2 = "cpe:2.3:a:phpmyadmin:phpmyadmin:4.8.4:*:*:*:*:*:*:*";
		String expectedResult3 = "cpe:2.3:a:phpmyadmin:phpmyadmin:4.7.9:*:*:*:*:*:*:*";

		List<String> idList = cpeLookUp.getCPEids(product);

		boolean correctResult1 = false;
		boolean correctResult2 = false;
		boolean correctResult3 = false;
		boolean notEmpty = false;

		if (idList != null && idList.size() > 0) {
			notEmpty = true;
			correctResult1 = expectedResult1.equals(idList.get(0));
			correctResult2 = expectedResult2.equals(idList.get(1));
			correctResult3 = expectedResult3.equals(idList.get(2));
		}

		assertEquals("Result is not empty", true, notEmpty);
		assertEquals("Result is correct for 4.8.0.1", true, correctResult1);
		assertEquals("Result is correct for 4.8.4", true, correctResult2);
		assertEquals("Result is correct for 4.7.9", true, correctResult3);
	}

	@Test
	public void legitemateComplexProductNoVersion() {

		CpeLookUp cpeLookUp = CpeLookUp.getInstance();

		ProductItem product = new ProductItem("Microsoft Internet Explorer. ");

		String expectedResult = "cpe:2.3:a:microsoft:internet_explorer:*:*:*:*:*:*:*:*";

		List<String> idList = cpeLookUp.getCPEids(product);

		boolean correctResult = false;
		boolean notEmpty = false;

		if (idList != null && idList.size() > 0) {
			notEmpty = true;
			correctResult = expectedResult.equals(idList.get(0));
		}

		assertEquals("Result is not empty", true, notEmpty);
		assertEquals("Result is correct", true, correctResult);
	}

	@Test
	public void checkSNverification() {

		CpeLookUp cpeLookUp = CpeLookUp.getInstance();

		String sn1 = "Explorer.";
		String sn2 = "Linux";

		List<String> sn1List = cpeLookUp.getCPEtitles(sn1);
		List<String> sn2List = cpeLookUp.getCPEtitles(sn2);

		boolean sn1NotEmpty = (sn1List != null && sn1List.size() > 0);
		boolean sn2NotEmpty = (sn2List != null && sn2List.size() > 0);

		assertEquals("Result for \"Explorer.\" is not empty", true, sn1NotEmpty);
		assertEquals("Result for \"Linux\" is not empty", true, sn2NotEmpty);
	}

}
