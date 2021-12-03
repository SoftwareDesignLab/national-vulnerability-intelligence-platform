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
package edu.rit.se.nvip.mitre;

import edu.rit.se.nvip.utils.MyProperties;
import edu.rit.se.nvip.utils.PropertyLoader;
import edu.rit.se.nvip.utils.UtilHelper;

/**
 * 
 * Pull Mitre CVEs from a local Git repository and create a .csv file. It pulls
 * the repository first if it is not updated.
 * 
 * @author axoeec
 *
 */
public class PullMitreCveMain {
	public static void main(String[] args) {
		/**
		 * To download all mitre cve items at once:
		 * https://cve.mitre.org/data/downloads/allitems.csv
		 */

		// load property file
		MyProperties propertiesNvip = new MyProperties();
		propertiesNvip = new PropertyLoader().loadConfigFile(propertiesNvip);

		String remotePath = "https://github.com/CVEProject/cvelist.git";
		String localPath = propertiesNvip.getDataDir() + "/mitre-cve";
		String outputCSVpath = propertiesNvip.getDataDir() + "/mitre-cve.csv";
 
		new MitreCveController().getMitreCVEsFromGitRepo(localPath, remotePath, outputCSVpath);

		// UtilHelper.checkCveIdAtNvd("CVE-2108-6150");
	}
}
