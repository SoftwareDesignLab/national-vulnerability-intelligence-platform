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
package edu.rit.se.nvip.automatedcvss;

import java.text.DecimalFormat;
import java.text.NumberFormat;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Map;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import edu.rit.se.nvip.automatedcvss.enums.AttackTheater;
import edu.rit.se.nvip.automatedcvss.enums.ImpactMethod;
import edu.rit.se.nvip.automatedcvss.enums.LogicalImpact;
import edu.rit.se.nvip.automatedcvss.enums.Mitigation;
import edu.rit.se.nvip.automatedcvss.enums.VdoNounGroup;

/**
 *
 * @author axoeec
 *
 */
public class PartialCvssVectorGenerator {
	private static Logger logger = LogManager.getLogger(PartialCvssVectorGenerator.class);
	static NumberFormat formatter = new DecimalFormat("#0.00");

	public static void main(String[] args) {
		PartialCvssVectorGenerator partialCvssVectorGenerator = new PartialCvssVectorGenerator();
	}

	/**
	 * A partial CVSS vector is a list like ["P", "X", "X", "X", "X", "H", "H",
	 * "H"], where each item in the list represents the values of AV, AC, PR, UI, S,
	 * C, I, A, respectively
	 * 
	 * AV: Attack Vector, AC: Attack Complexity, PR: Privilege Required, S: Scope,
	 * UI: User Interaction, C: Confidentiality, I: Integrity, A: Availability.
	 * 
	 * Note: Right now we do not have any mapping for: PR, UI, S fields of the CVSS
	 * vector
	 * 
	 * @param predictionsForVuln: Predictions for each VDO noun group. The value of
	 *                            the map is ArrayList<String[]> to store the label
	 *                            and confidence for each noun group value.
	 * @return
	 */
	public String[] getCVssVector(Map<String, ArrayList<String[]>> predictionsForVuln) {

		// values for: AV, AC, PR, UI, S, C, I, A
		// initially set to unknown
		String[] vectorCvss = new String[] { "X", "L", "X", "X", "U", "N", "N", "N" };

		Map<String, Integer> predictedLabelMap = new HashMap<>();

		for (String vdoNounGroup : predictionsForVuln.keySet()) {
			ArrayList<String[]> predictionsForNounGroup = predictionsForVuln.get(vdoNounGroup);

			predictedLabelMap = new HashMap<>(); // create map
			// put labels into the map to avoid repeated list iterations
			for (String[] prediction : predictionsForNounGroup) {
				predictedLabelMap.put(prediction[0].trim(), 0);
			}

			if (vdoNounGroup.equalsIgnoreCase(VdoNounGroup.ATTACK_THEATER.getNounGroup())) {
				/**
				 * Attack Vector (AV)* Network (AV:N), Adjacent (AV:A), Local (AV:L), Physical
				 * (AV:P)
				 * 
				 */
				if (predictedLabelMap.containsKey(AttackTheater.Remote.getNounGroupValue()))
					vectorCvss[0] = "N";
				else if (predictedLabelMap.containsKey(AttackTheater.LimitedRemote.getNounGroupValue()))
					vectorCvss[0] = "N";
				else if (predictedLabelMap.containsKey(AttackTheater.Local.getNounGroupValue()))
					vectorCvss[0] = "L";
				else if (predictedLabelMap.containsKey(AttackTheater.Physical.getNounGroupValue()))
					vectorCvss[0] = "P";

			} else if (vdoNounGroup.equalsIgnoreCase(VdoNounGroup.CONTEXT.getNounGroup())) {
				// no mapping yet
			} else if (vdoNounGroup.equalsIgnoreCase(VdoNounGroup.IMPACT_METHOD.getNounGroup())) {
				/**
				 * Attack Complexity (AC)* Low (AC:L)High (AC:H)
				 * 
				 */
				if (predictedLabelMap.containsKey(ImpactMethod.ManintheMiddle.getNounGroupValue()))
					vectorCvss[1] = "H"; // if there is MitM impact then, we assume attack complexity is High
				else if (predictedLabelMap.containsKey(ImpactMethod.ContextEscape.getNounGroupValue()))
					vectorCvss[4] = "C"; // scope changes if context escape

			} else if (vdoNounGroup.equalsIgnoreCase(VdoNounGroup.LOGICAL_IMPACT.getNounGroup())) {

				/**
				 * ******************* CONFIDENTIALITY **************************
				 * 
				 * (Privilege Escalation && (len(Logical Impact)==1 || Read || Indirect
				 * Disclosure)) -> C: H
				 * 
				 * Read || Indirect Disclosure-> C: LH
				 * 
				 * ******************* INTEGRITY **************************
				 * 
				 * (Privilege Escalation && (len(Logical Impact)==1) || Write || Resource
				 * Removal)) -> I: H
				 * 
				 * Write || Resource Removal -> I: LH
				 * 
				 * 
				 * ******************* AVAILABILITY **************************
				 * 
				 * (Privilege Escalation && (len(Logical Impact)==1 || Service Interrupt)) -> A:
				 * H
				 * 
				 * Service Interrupt -> A:LH
				 * 
				 */
				if (predictedLabelMap.containsKey(LogicalImpact.PrivilegeEscalation.getNounGroupValue())
						&& (predictedLabelMap.size() == 1 || predictedLabelMap.containsKey(LogicalImpact.Read.getNounGroupValue()) || predictedLabelMap.containsKey(LogicalImpact.IndirectDisclosure.getNounGroupValue()))

				)
					vectorCvss[5] = "H"; // confidentiality H
				else if (predictedLabelMap.containsKey(LogicalImpact.PrivilegeEscalation.getNounGroupValue())
						&& (predictedLabelMap.size() == 1 || predictedLabelMap.containsKey(LogicalImpact.Write.getNounGroupValue()) || predictedLabelMap.containsKey(LogicalImpact.ResourceRemoval.getNounGroupValue()))

				)
					vectorCvss[6] = "H"; // integrity H
				else if (predictedLabelMap.containsKey(LogicalImpact.PrivilegeEscalation.getNounGroupValue()) && (predictedLabelMap.size() == 1 || predictedLabelMap.containsKey(LogicalImpact.ServiceInterrupt.getNounGroupValue()))

				)
					vectorCvss[7] = "H"; // availability H
				else if (predictedLabelMap.containsKey(LogicalImpact.Read.getNounGroupValue()) || predictedLabelMap.containsKey(LogicalImpact.IndirectDisclosure.getNounGroupValue()))
					vectorCvss[5] = "LH"; // confidentiality LH
				else if (predictedLabelMap.containsKey(LogicalImpact.Write.getNounGroupValue()) || predictedLabelMap.containsKey(LogicalImpact.ResourceRemoval.getNounGroupValue()))
					vectorCvss[6] = "LH"; // integrity LH
				else if (predictedLabelMap.containsKey(LogicalImpact.ServiceInterrupt.getNounGroupValue()))
					vectorCvss[7] = "LH"; // availability LH

			} else if (vdoNounGroup.equalsIgnoreCase(VdoNounGroup.MITIGATION.getNounGroup())) {
				if (predictedLabelMap.containsKey(Mitigation.Sandboxed.getNounGroupValue()))
					vectorCvss[4] = "C"; // we assume a scope change if "sandboxed" is feasible for mitigation

			}

		}
		return vectorCvss;
	}

}
