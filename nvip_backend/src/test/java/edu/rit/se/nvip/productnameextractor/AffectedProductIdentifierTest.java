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

import edu.rit.se.nvip.model.CompositeVulnerability;
import org.junit.Test;

import java.util.ArrayList;
import java.util.List;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

/**
 * Test AffectedProductIdentifier
 * @author axoeec
 */

public class AffectedProductIdentifierTest {

	/**
	 * Test product name extraction for a simple CVE
	 */
	@Test
	public void affectedProductIdentifierTest() {
		String description = "A relative path traversal vulnerability has been reported to affect QNAP NAS running QTS and QuTS hero. If exploited, this vulnerability allows attackers to modify files that impact system integrity. QNAP have already fixed this vulnerability in the following versions: QTS 4.5.2.1630 Build 20210406 and later QTS 4.3.6.1663 Build 20210504 and later QTS 4.3.3.1624 Build 20210416 and later QuTS hero h4.5.2.1638 Build 20210414 and later QNAP NAS running QTS 4.5.3 are not affected";
		List<CompositeVulnerability> vulnList = new ArrayList<CompositeVulnerability>();
		CompositeVulnerability v = new CompositeVulnerability(0, null, "CVE-2021-28798", "", null, null, description, null);
		v.setCveReconcileStatus(CompositeVulnerability.CveReconcileStatus.UPDATE);
		vulnList.add(v);

		AffectedProductIdentifier affectedProductIdentifier = new AffectedProductIdentifier(vulnList);
		int count = affectedProductIdentifier.identifyAffectedReleases();

		System.out.println(v.getAffectedReleases());

		assertTrue((v.getAffectedReleases().size() > 0));
		assertEquals(v.getAffectedReleases().size(), count);
	}

}
