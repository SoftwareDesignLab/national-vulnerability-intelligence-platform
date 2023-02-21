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
package edu.rit.se.nvip.cvereconcile;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import edu.rit.se.nvip.model.CompositeVulnerability;
import edu.rit.se.nvip.utils.MyProperties;
import edu.rit.se.nvip.utils.PropertyLoader;

/**
 * Class for simple Cve reconciliation and validation
 * 
 * @author Igor Khokhlov
 *
 */

public class CveReconcilerSimple extends AbstractCveReconciler {
	private final Logger logger = LogManager.getLogger(getClass().getSimpleName());

	public CveReconcilerSimple() {
		MyProperties propertiesNvip = new MyProperties();
		propertiesNvip = new PropertyLoader().loadConfigFile(propertiesNvip);
		knownCveSources = propertiesNvip.getKnownCveSources();
	}

	/**
	 * Reconcile two CVEs
	 */
	@Override
	public boolean reconcileVulnerabilities(CompositeVulnerability existingVuln, CompositeVulnerability newVuln) {
		boolean reconciled = false;
		if (existingVuln.getPlatform() == null && newVuln.getPlatform() != null) {
			existingVuln.setPlatform(newVuln.getPlatform());
			reconciled = true;
		}

		if (existingVuln.getPublishDate() == null && newVuln.getPublishDate() != null) {
			existingVuln.setPublishDate(newVuln.getPublishDate());
			reconciled = true;
		}

		if (reconcileDescriptions(existingVuln.getDescription(), newVuln.getDescription(), existingVuln.getSourceDomainName(), newVuln.getSourceDomainName(), true)) {
			existingVuln.setDescription(newVuln.getDescription());
			reconciled = true;
		}

		if (reconciled) {
			/**
			 * Fix by AO: If the newVuln is a previously reconciled one, it may have
			 * multiple URLs!
			 */
			for (String newURL : newVuln.getSourceURL())
				existingVuln.addSourceURL(newURL);
		}
		return reconciled;
	}

	/**
	 * Reconcile description. If <existingDescription> should be updated, returns
	 * true.
	 * 
	 * @param existingDescription
	 * @param newDescription
	 * @return updateDescription
	 */
	public boolean reconcileDescriptions(String existingDescription, String newDescription, String existingSourceDomain, String newSourceDomain, boolean considerSources) {
		boolean updateDescription = false;

		/**
		 * if existing CVE is from known source (and the new one is not) use existing
		 * description, no need for reconciliation. If existing source is unknown but
		 * the new one is known, update existing description. If both sources are known
		 * then move forward with reconciliation process
		 */
		if (considerSources && knownCveSources.containsKey(existingSourceDomain) && !knownCveSources.containsKey(newSourceDomain))
			return false;

		if (considerSources && !knownCveSources.containsKey(existingSourceDomain) && knownCveSources.containsKey(newSourceDomain))
			return true;

		// both CVEs from unknown sources
		if (existingDescription == null || existingDescription.length() < newDescription.length()) {
			updateDescription = true;
			return updateDescription;
		} else {
			return updateDescription;
		}
	}
}
